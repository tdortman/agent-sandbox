//! Policy store: the lifecycle of a pending approval.
//!
//! A request no rule decides becomes a pending approval. This module owns
//! what happens to it from there: the verdict cache that answers repeats,
//! joining an identical prompt or queueing a new one under both caps, the
//! wait for a verdict and what each way out of it does, settling pendings
//! the rules decide in the meantime, answering the waiters, and applying a
//! decision, including putting a taken pending back when the decision could
//! not be applied.
//!
//! [`PromptKind`] is what a capability kind with a regular prompt supplies
//! (filesystem, resource, D-Bus, secret). [`ApprovalKind`] is the part that
//! settling and deciding need, which network supplies too; network keeps its
//! own waiters because one proxy check can leave a prompt on its own.
//! Elevation and HTTP use the board and the wait directly.

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    hash::Hash,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, ResolvedRequestContext, RpcReply, ScopeActionReply, Verdict,
    VerdictSource,
};
use tokio::{sync::oneshot, time};
use uuid::Uuid;

use super::{
    dbus::DbusApproval,
    decisions::DecisionAction,
    filesystem::FilesystemApproval,
    network::NetworkApproval,
    resource::ResourceApproval,
    secrets::SecretApproval,
    state::{PendingBoard, PolicyDecisionState},
    types::{
        MAX_PENDING_APPROVALS, MAX_WAITERS_PER_PENDING, Pending, PolicyStore, VerdictEntry,
        enforce_verdict_cache_limit,
    },
};
use crate::{
    error::PolicydError,
    wire::{PendingDecision, ScopeWire},
};

/// Blocked reply text of a request that would exceed the pending cap.
pub(super) const TOO_MANY_PENDING: &str = "agent-sandbox: too many pending approvals";

/// How often a queued wait checks whether it has reached the head of its
/// owner's queue.
const QUEUE_POLL: Duration = Duration::from_millis(100);

/// Why a verdict wait ended without a verdict. `C` is what the wait's cancel
/// signal yields, so a wait with no cancel signal has no cancelled exit.
pub(super) enum VerdictExit<C = Infallible> {
    /// No policy UI registered within the short wait window.
    NoUi,

    /// The verdict channel closed before a reply arrived.
    ChannelClosed,

    /// The full approval timeout elapsed.
    Timeout,

    /// The cancel signal fired.
    Cancelled(C),
}

/// Where a waiter landed on the board.
pub(super) struct Joined {
    pub(super) id: String,

    /// The pending this request queued; `None` when it joined an existing
    /// one.
    pub(super) queued: Option<Pending>,
}

/// The cap a request hit instead of landing on the board.
pub(super) enum CapHit {
    Waiters,
    Pendings,
}

/// A decision on one pending approval, as submitted.
pub(super) struct Decision {
    pub(super) wire: ScopeWire,
    pub(super) scope: ApprovalScope,
    pub(super) target: Option<ApprovalTarget>,
    pub(super) action: DecisionAction,
}

/// How a decision on a taken pending ended.
pub(super) struct Decided {
    pub(super) reply: RpcReply,

    /// The taken pending, when the decision was not applied: it goes back on
    /// the board.
    pub(super) unapplied: Option<Pending>,
}

impl Decided {
    pub(super) const fn done(reply: RpcReply) -> Self {
        Self {
            reply,
            unapplied: None,
        }
    }

    pub(super) const fn put_back(pending: Pending, reply: RpcReply) -> Self {
        Self {
            reply,
            unapplied: Some(pending),
        }
    }
}

/// The points of a prompt's life a kind may log.
pub(super) enum PromptStage {
    Queued,
    AwaitingUi,
    AwaitingDecision,
}

/// What a capability kind supplies to settle and decide its pendings.
pub(super) trait ApprovalKind: Sized {
    /// The kind's record on the board.
    type Pending: Send + Sync;

    /// What a finished verdict is recorded and replied under.
    type Key: Send;

    /// A validated approval target.
    type Target: Send;

    /// Whether an approval whose scope application failed answers the
    /// waiters as blocked. Otherwise the pending stays queued.
    const FAILED_APPROVAL_BLOCKS: bool;

    fn into_pending(pending: Self::Pending) -> Pending;

    fn id(pending: &Self::Pending) -> &str;

    fn key(pending: &Self::Pending) -> Self::Key;

    /// The verdict the current rules give the pending request, when they
    /// decide it.
    fn decided_verdict(
        store: &PolicyStore,
        pending: &Self::Pending,
    ) -> impl Future<Output = Option<Verdict>> + Send;

    /// Answer every waiter of the pending.
    fn finish(
        store: &PolicyStore,
        pending_id: &str,
        key: Self::Key,
        verdict: Verdict,
    ) -> impl Future<Output = ()> + Send;

    /// Validate the decision's approval target against the pending request.
    ///
    /// # Errors
    ///
    /// Returns the error that rejects a target the request does not allow.
    fn approval_target(
        pending: &Self::Pending,
        decision: &Decision,
    ) -> Result<Self::Target, PolicydError>;

    /// Whether a once decision finishes the pending without scope
    /// application.
    fn once_skips_scope(_action: DecisionAction) -> bool {
        true
    }

    /// Audit a once decision that skips scope application.
    fn audit_once(_pending: &Self::Pending, _target: &Self::Target, _action: DecisionAction) {}

    /// The key a decision on `target` finishes the pending under.
    fn decided_key(pending: &Self::Pending, target: &Self::Target) -> Self::Key;

    /// The reply to a once decision that skipped scope application.
    fn once_reply(pending: &Self::Pending, target: Self::Target) -> ScopeActionReply;

    fn apply_scope(
        store: &PolicyStore,
        pending: &Self::Pending,
        target: Self::Target,
        decision: Decision,
    ) -> impl Future<Output = RpcReply> + Send;
}

/// What a capability kind supplies to prompt for its requests. The key
/// identifies a request: it is the verdict-cache key and what a reply is
/// built from.
pub(super) trait PromptKind: ApprovalKind<Key: Clone + Eq + Hash + Sync> {
    type Reply: Clone + Send;

    const ID_PREFIX: &'static str;
    /// Names the kind in the reply of an approval whose sandbox cannot be
    /// frozen.
    const APPROVAL_NAME: &'static str;
    const TOO_MANY_WAITERS: &'static str;
    const NO_UI: &'static str;
    const TIMED_OUT: &'static str;
    const VERDICT_TTL: Duration;

    fn waiters(board: &mut PendingBoard)
    -> &mut HashMap<String, Vec<oneshot::Sender<Self::Reply>>>;

    fn verdict_cache(state: &mut PolicyDecisionState) -> &mut HashMap<Self::Key, VerdictEntry>;

    /// Whether a queued pending is the prompt a request for `key` from `ctx`
    /// joins.
    fn same_prompt(pending: &Pending, key: &Self::Key, ctx: &ResolvedRequestContext) -> bool;

    fn new_pending(
        id: String,
        created_at: f64,
        key: &Self::Key,
        ctx: &ResolvedRequestContext,
    ) -> Pending;

    fn reply(key: &Self::Key, verdict: Verdict) -> Self::Reply;

    fn blocked(key: &Self::Key, message: &str) -> Self::Reply;

    /// Whether a finished verdict is recorded in the verdict cache.
    fn caches(_verdict: &Verdict) -> bool {
        true
    }

    /// A cached verdict recorded under another key that also covers `key`.
    fn aliased_verdict(
        _cache: &HashMap<Self::Key, VerdictEntry>,
        _key: &Self::Key,
    ) -> Option<Verdict> {
        None
    }

    fn trace(_stage: PromptStage, _id: &str, _key: &Self::Key, _ctx: &ResolvedRequestContext) {}
}

/// Verdict source of a finished decision. Denied verdicts report
/// [`VerdictSource::User`]: the wire codec has no `Scope` encoding for
/// `allowed = false`.
fn decision_source(scope: ApprovalScope, action: DecisionAction) -> VerdictSource {
    if action == DecisionAction::Approve {
        VerdictSource::from(scope)
    } else {
        VerdictSource::User
    }
}

/// The verdict recorded for `key` within the last `ttl`.
pub(super) fn cached_verdict<K: Eq + Hash>(
    cache: &HashMap<K, VerdictEntry>,
    key: &K,
    ttl: Duration,
) -> Option<Verdict> {
    cache
        .get(key)
        .filter(|entry| entry.time.elapsed() < ttl)
        .map(|entry| Verdict {
            allowed: entry.allowed,
            source: entry.source.clone(),
        })
}

pub(super) fn record_verdict<K: Clone + Eq + Hash>(
    cache: &mut HashMap<K, VerdictEntry>,
    key: K,
    verdict: Verdict,
) {
    cache.insert(key, VerdictEntry {
        allowed: verdict.allowed,
        source: verdict.source,
        time: Instant::now(),
    });

    enforce_verdict_cache_limit(cache);
}

impl PendingBoard {
    /// Queue the pending `make` builds from a fresh id and the creation
    /// time. `None` at the pending cap.
    pub(super) fn create(
        &mut self,
        id_prefix: &str,
        make: impl FnOnce(String, f64) -> Pending,
    ) -> Option<Pending> {
        if self.pending.len() >= MAX_PENDING_APPROVALS {
            return None;
        }

        let id = format!("{id_prefix}:{}", Uuid::now_v7().simple());

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |elapsed| elapsed.as_secs_f64());

        let pending = make(id.clone(), created_at);
        self.pending.insert(id, pending.clone());
        Some(pending)
    }

    /// Add `waiter` to the pending `same` selects, or to a new one built by
    /// `make`.
    ///
    /// # Errors
    ///
    /// Returns the cap the request hit; nothing is queued then.
    pub(super) fn join_or_create<W>(
        &mut self,
        waiters: fn(&mut Self) -> &mut HashMap<String, Vec<W>>,
        waiter: W,
        id_prefix: &str,
        same: impl Fn(&Pending) -> bool,
        make: impl FnOnce(String, f64) -> Pending,
    ) -> Result<Joined, CapHit> {
        let existing = self
            .pending
            .values()
            .find(|pending| same(pending))
            .map(|pending| pending.id().to_owned());

        let joined = if let Some(id) = existing {
            if waiters(self).get(&id).map_or(0, Vec::len) >= MAX_WAITERS_PER_PENDING {
                return Err(CapHit::Waiters);
            }

            Joined { id, queued: None }
        } else {
            let pending = self.create(id_prefix, make).ok_or(CapHit::Pendings)?;

            Joined {
                id: pending.id().to_owned(),
                queued: Some(pending),
            }
        };

        waiters(self)
            .entry(joined.id.clone())
            .or_default()
            .push(waiter);

        Ok(joined)
    }

    /// Drop a pending together with its waiters.
    pub(super) fn abandon<W>(
        &mut self,
        waiters: fn(&mut Self) -> &mut HashMap<String, W>,
        pending_id: &str,
    ) {
        self.pending.remove(pending_id);
        waiters(self).remove(pending_id);
    }

    /// Remove the waiters of `pending_id` whose wait has ended (their
    /// receiver is gone) and drop the pending with the last of them. One
    /// waiter giving up must not deny the others that joined the same prompt.
    pub(super) fn leave<R>(
        &mut self,
        waiters: fn(&mut Self) -> &mut HashMap<String, Vec<oneshot::Sender<R>>>,
        pending_id: &str,
    ) {
        let waiting = waiters(self);

        let Some(senders) = waiting.get_mut(pending_id) else {
            return;
        };

        senders.retain(|tx| !tx.is_closed());

        if senders.is_empty() {
            waiting.remove(pending_id);
            self.pending.remove(pending_id);
        }
    }
}

impl PolicyStore {
    /// Wait for the verdict of the queued request `pending_id`. A CLI
    /// approval can arrive before any policy UI does, so the verdict channel
    /// is raced against UI registration: a short wait for a UI to register,
    /// then the full `approval_timeout` for the verdict.
    ///
    /// The UI shows one prompt at a time per user, so a pending that is not
    /// the oldest unresolved one of its owner is not on screen yet. Its
    /// `approval_timeout` starts once every older pending is resolved, and the
    /// verdict can still arrive while it waits its turn.
    ///
    /// `on_ui_poll` hears each fresh answer to whether a UI is registered.
    ///
    /// # Errors
    ///
    /// Returns why the wait ended without a verdict.
    pub(super) async fn wait_for_verdict_or<R: Send, C: Send>(
        &self,
        ctx: &ResolvedRequestContext,
        pending_id: &str,
        rx: oneshot::Receiver<R>,
        cancel: impl Future<Output = C> + Send,
        mut on_ui_poll: impl FnMut(bool) + Send,
    ) -> Result<R, VerdictExit<C>> {
        let ui_deadline = Instant::now() + self.args.approval_timeout.min(Duration::from_mins(1));
        tokio::pin!(rx);
        tokio::pin!(cancel);

        loop {
            let registered = self.has_ui_for_context(ctx).await;
            on_ui_poll(registered);

            if registered {
                break;
            }

            let now = Instant::now();

            if now >= ui_deadline {
                return Err(VerdictExit::NoUi);
            }

            tokio::select! {
                biased;
                () = time::sleep((ui_deadline - now).min(Duration::from_millis(50))) => {}
                verdict = &mut rx => return verdict.map_err(|_| VerdictExit::ChannelClosed),
                cancelled = &mut cancel => return Err(VerdictExit::Cancelled(cancelled)),
            }
        }

        let queued_wait = async {
            let reached_head = async {
                while !self.is_queue_head(pending_id).await {
                    time::sleep(QUEUE_POLL).await;
                }
            };

            tokio::select! {
                verdict = &mut rx => return Ok(verdict),
                () = reached_head => {}
            }

            time::timeout(self.args.approval_timeout, &mut rx).await
        };

        tokio::select! {
            verdict = queued_wait => match verdict {
                Ok(verdict) => verdict.map_err(|_| VerdictExit::ChannelClosed),
                Err(_) => Err(VerdictExit::Timeout),
            },
            cancelled = &mut cancel => Err(VerdictExit::Cancelled(cancelled)),
        }
    }

    /// Whether no older pending of the same owner is unresolved. Pendings
    /// without a registered sandbox session share the owner `None`.
    async fn is_queue_head(&self, pending_id: &str) -> bool {
        let sessions = self.sandbox_sessions.snapshot();

        let owner = |pending: &Pending| {
            pending
                .sandbox_session_id()
                .and_then(|id| sessions.get(id))
                .map(|registration| registration.owner_uid)
        };

        let inner = self.inner.lock().await;
        let board = &inner.pending.pending;

        let Some(this) = board.get(pending_id) else {
            return true;
        };

        let this_owner = owner(this);

        let head = !board.values().any(|other| {
            other
                .created_at()
                .total_cmp(&this.created_at())
                .then_with(|| other.id().cmp(this.id()))
                .is_lt()
                && owner(other) == this_owner
        });

        drop(inner);
        head
    }

    /// [`Self::wait_for_verdict_or`] for a wait nothing cancels.
    ///
    /// # Errors
    ///
    /// Returns why the wait ended without a verdict.
    pub(super) async fn wait_for_verdict<R: Send>(
        &self,
        ctx: &ResolvedRequestContext,
        pending_id: &str,
        rx: oneshot::Receiver<R>,
    ) -> Result<R, VerdictExit> {
        self.wait_for_verdict_or(ctx, pending_id, rx, std::future::pending(), |_| {})
            .await
    }

    /// Drop a pending whose wait ended without a verdict, with its waiters.
    pub(super) async fn abandon_pending<W>(
        &self,
        waiters: fn(&mut PendingBoard) -> &mut HashMap<String, W>,
        pending_id: &str,
    ) {
        self.inner.lock().await.pending.abandon(waiters, pending_id);
    }

    /// Push a newly queued pending to the policy UI of its request context,
    /// spawning a UI when none is registered.
    pub(super) async fn announce(&self, pending: &Pending, ctx: &ResolvedRequestContext) {
        self.notify_general_ui(ctx, &Self::ui_push(pending)).await;

        self.maybe_spawn_ui(
            || self.has_ui_for_context(ctx),
            ctx.ids.uid(),
            pending.home(),
            pending.cwd(),
            pending.project_root(),
            pending.sandbox_session_id(),
        )
        .await;
    }

    /// The reply a recent verdict for `key` already gives.
    pub(super) async fn cached_reply<K: PromptKind>(&self, key: &K::Key) -> Option<K::Reply> {
        let mut inner = self.inner.lock().await;
        let cache = K::verdict_cache(&mut inner);

        let verdict = cached_verdict(cache, key, K::VERDICT_TTL)
            .or_else(|| K::aliased_verdict(cache, key))?;

        drop(inner);
        Some(K::reply(key, verdict))
    }

    /// Prompt for the request `key` identifies and wait for its verdict. The
    /// request joins the prompt already queued for it, or queues and
    /// announces a new one. A wait that ends with no UI or no decision
    /// removes the pending and answers blocked.
    pub(super) async fn prompt<K: PromptKind>(
        &self,
        key: K::Key,
        ctx: &ResolvedRequestContext,
    ) -> K::Reply {
        // Freeze the requester's sandbox while the approval pends so the
        // agent cannot keep working before the user decides. A failed freeze
        // fails closed without creating an approval. Every request holds the
        // scope itself, also one that joins a prompt another request queued.
        let freeze_hold = match self
            .cgroup_freeze
            .acquire(ctx.ids.pid(), ctx.ids.uid())
            .await
        {
            Ok(hold) => hold,
            Err(error) => {
                return K::blocked(
                    &key,
                    &format!(
                        "agent-sandbox: cannot freeze sandbox for {} approval: {error}",
                        K::APPROVAL_NAME
                    ),
                );
            }
        };

        let (tx, rx) = oneshot::channel();

        let joined = self.inner.lock().await.pending.join_or_create(
            K::waiters,
            tx,
            K::ID_PREFIX,
            |pending| K::same_prompt(pending, &key, ctx),
            |id, created_at| K::new_pending(id, created_at, &key, ctx),
        );

        let joined = match joined {
            Ok(joined) => joined,
            Err(CapHit::Waiters) => return K::blocked(&key, K::TOO_MANY_WAITERS),
            Err(CapHit::Pendings) => return K::blocked(&key, TOO_MANY_PENDING),
        };

        if let Some(pending) = &joined.queued {
            K::trace(PromptStage::Queued, &joined.id, &key, ctx);
            self.announce(pending, ctx).await;
        }

        let mut awaiting_ui_traced = false;

        let waited = self
            .wait_for_verdict_or(
                ctx,
                &joined.id,
                rx,
                std::future::pending::<Infallible>(),
                |registered| {
                    if registered {
                        K::trace(PromptStage::AwaitingDecision, &joined.id, &key, ctx);
                    } else if !awaiting_ui_traced {
                        awaiting_ui_traced = true;
                        K::trace(PromptStage::AwaitingUi, &joined.id, &key, ctx);
                    }
                },
            )
            .await;

        let reply = match waited {
            Ok(reply) => reply,
            Err(VerdictExit::ChannelClosed) => {
                K::reply(&key, Verdict::denied(VerdictSource::Blocked))
            }
            Err(VerdictExit::NoUi) => {
                self.inner
                    .lock()
                    .await
                    .pending
                    .leave(K::waiters, &joined.id);
                K::blocked(&key, K::NO_UI)
            }
            Err(VerdictExit::Timeout) => {
                self.inner
                    .lock()
                    .await
                    .pending
                    .leave(K::waiters, &joined.id);
                K::blocked(&key, K::TIMED_OUT)
            }
        };

        // The sandbox thaws before the reply leaves.
        if let Some(hold) = freeze_hold {
            hold.release().await;
        }

        reply
    }

    /// Answer every waiter of a pending with `verdict` and record it in the
    /// kind's verdict cache.
    pub(super) async fn finish_prompt<K: PromptKind>(
        &self,
        pending_id: &str,
        key: K::Key,
        verdict: Verdict,
    ) {
        let mut inner = self.inner.lock().await;

        let waiters = K::waiters(&mut inner.pending)
            .remove(pending_id)
            .unwrap_or_default();
        let reply = (!waiters.is_empty()).then(|| K::reply(&key, verdict.clone()));

        if K::caches(&verdict) {
            record_verdict(K::verdict_cache(&mut inner), key, verdict);
        }

        drop(inner);

        if let Some(reply) = reply {
            for tx in waiters {
                let _ = tx.send(reply.clone());
            }
        }
    }

    /// Finish every pending filesystem, resource, network, D-Bus, and secret
    /// approval that the current declarative and session rules decide.
    ///
    /// A scoped decision on one prompt often covers others queued behind it:
    /// a directory rule covers sibling files, a host rule covers the same host
    /// from another context. Each pending is re-evaluated exactly as a fresh
    /// request would be, so denies still win over allows.
    ///
    /// HTTP scope application settles matching HTTP pendings itself.
    /// Elevation pendings stay queued: approving one runs the command.
    pub(crate) async fn settle_covered_pendings(&self) {
        let pending: Vec<Pending> = self
            .inner
            .lock()
            .await
            .pending
            .pending
            .values()
            .filter(|pending| !matches!(pending, Pending::Elevation(_) | Pending::Http(_)))
            .cloned()
            .collect();

        for pending in pending {
            match pending {
                Pending::Filesystem(fs) => self.settle::<FilesystemApproval>(fs).await,
                Pending::Resource(res) => self.settle::<ResourceApproval>(res).await,
                Pending::Network(net) => self.settle::<NetworkApproval>(net).await,
                Pending::Dbus(dbus) => self.settle::<DbusApproval>(dbus).await,
                Pending::Secret(secret) => self.settle::<SecretApproval>(secret).await,
                Pending::Elevation(_) | Pending::Http(_) => {}
            }
        }
    }

    async fn settle<K: ApprovalKind>(&self, pending: K::Pending) {
        let Some(verdict) = K::decided_verdict(self, &pending).await else {
            return;
        };

        let id = K::id(&pending);

        // A concurrent decision may have taken the pending first.
        let taken = self.inner.lock().await.pending.pending.remove(id).is_some();

        if !taken {
            return;
        }

        tracing::info!(pending_id = id, "pending settled by current policy");
        K::finish(self, id, K::key(&pending), verdict).await;
    }

    /// Queue a taken pending again: the decision on it was not applied.
    pub(super) async fn put_back(&self, pending: Pending) {
        let id = pending.id().to_owned();
        self.inner.lock().await.pending.pending.insert(id, pending);
    }

    /// Apply an approve or deny decision to the pending it names, then
    /// settle the pendings a scoped decision now covers.
    pub(crate) async fn apply_pending_decision(
        &self,
        decision: PendingDecision,
        action: DecisionAction,
    ) -> RpcReply {
        let scoped = decision.scope != ApprovalScope::Once;
        let reply = self.decide_pending(decision, action).await;

        if scoped {
            self.settle_covered_pendings().await;
        }

        reply
    }

    async fn decide_pending(&self, decision: PendingDecision, action: DecisionAction) -> RpcReply {
        let taken = match self.take_pending_decision(decision).await {
            Ok(taken) => taken,
            Err(err) => return *err,
        };

        let decision = Decision {
            wire: taken.wire,
            scope: taken.scope,
            target: taken.target,
            action,
        };

        let decided = match taken.pending {
            Pending::Network(net) => self.decide::<NetworkApproval>(net, decision).await,
            Pending::Filesystem(fs) => self.decide::<FilesystemApproval>(fs, decision).await,
            Pending::Resource(res) => self.decide::<ResourceApproval>(res, decision).await,
            Pending::Dbus(dbus) => self.decide::<DbusApproval>(dbus, decision).await,
            Pending::Secret(secret) => self.decide::<SecretApproval>(secret, decision).await,
            Pending::Elevation(elev) => self.decide_elevation(elev, decision).await,
            Pending::Http(http) => Decided::done(self.decide_http(http, decision).await),
        };

        if let Some(pending) = decided.unapplied {
            self.put_back(pending).await;
        }

        decided.reply
    }

    /// The decide skeleton: validate the approval target, finish a once
    /// decision that needs no scope application, otherwise apply the scope
    /// and finish on success.
    async fn decide<K: ApprovalKind>(&self, pending: K::Pending, decision: Decision) -> Decided {
        let target = match K::approval_target(&pending, &decision) {
            Ok(target) => target,
            Err(err) => return Decided::put_back(K::into_pending(pending), err.into()),
        };

        let scope = decision.scope;
        let action = decision.action;
        let key = K::decided_key(&pending, &target);

        let verdict = Verdict {
            allowed: action == DecisionAction::Approve,
            source: decision_source(scope, action),
        };

        if scope == ApprovalScope::Once && K::once_skips_scope(action) {
            K::audit_once(&pending, &target, action);
            K::finish(self, K::id(&pending), key, verdict).await;

            return Decided::done(RpcReply::ScopeAction(K::once_reply(&pending, target)));
        }

        let reply = K::apply_scope(self, &pending, target, decision).await;

        if reply.scope_succeeded() {
            K::finish(self, K::id(&pending), key, verdict).await;
        } else if action == DecisionAction::Approve && K::FAILED_APPROVAL_BLOCKS {
            let blocked = Verdict::denied(VerdictSource::Blocked);
            K::finish(self, K::id(&pending), key, blocked).await;
        } else {
            return Decided::put_back(K::into_pending(pending), reply);
        }

        Decided::done(reply)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use agent_sandbox_core::{
        ApprovalScope, ApprovalTarget, DbusCheckReply, DbusMessageKind, DbusTarget, ProcessIds,
        ResolvedRequestContext, RpcReply, SandboxPaths, Verdict, VerdictSource,
    };
    use tokio::{net::UnixStream, sync::Mutex, task::JoinHandle};

    use crate::{
        store::{
            DecisionAction, PolicyStore, test_args,
            types::{
                MAX_PENDING_APPROVALS, MAX_WAITERS_PER_PENDING, Pending, PendingDbus, UiClient,
                UiSessionContext,
            },
        },
        wire::{PendingDecision, ScopeWire},
    };

    const UI_SESSION: &str = "ui1";
    const SANDBOX_SESSION: &str = "sandbox-cap";

    fn store(approval_timeout: Duration) -> Arc<PolicyStore> {
        Arc::new(PolicyStore::new(test_args(
            "/tmp/test.sock".into(),
            "/tmp/test-sandbox.sock".into(),
            "/tmp/declarative.json".into(),
            "/tmp/export.json".into(),
            approval_timeout,
            true,
        )))
    }

    fn ctx() -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(
                Some("/repo".into()),
                Some("/home/user".into()),
                Some("/repo".into()),
            ),
            ids: ProcessIds::from_options(None, Some(1000)),
            sandbox_session_id: Some(SANDBOX_SESSION.into()),
            package: None,
        }
    }

    fn target(member: &str) -> DbusTarget {
        DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            member,
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        )
    }

    /// Register a policy UI for [`ctx`]. The returned stream is the UI's end
    /// of the connection; dropping it disconnects the UI.
    async fn register_ui(store: &PolicyStore) -> UnixStream {
        let (ui, policyd) = UnixStream::pair().expect("unix stream pair");
        let (_, writer) = policyd.into_split();
        let mut inner = store.inner.lock().await;

        inner.ui_clients.insert(1, UiClient {
            session_id: UI_SESSION.into(),
            writer: Arc::new(Mutex::new(writer)),
        });

        inner
            .ui_context_by_session
            .insert(UI_SESSION.into(), UiSessionContext {
                cwd: Some("/repo".into()),
                home: Some("/home/user".into()),
                project_root: Some("/repo".into()),
                sandbox_session_id: Some(SANDBOX_SESSION.into()),
                owner_uid: Some(1000),
                client_id: 1,
            });

        drop(inner);
        ui
    }

    fn request(store: &Arc<PolicyStore>, member: &str) -> JoinHandle<DbusCheckReply> {
        let store = store.clone();
        let target = target(member);

        tokio::spawn(async move { store.request_dbus_approval(target, ctx()).await })
    }

    /// The ids of the queued pendings, once `waiters` requests wait on them.
    async fn queued(store: &PolicyStore, waiters: usize) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(5);

        loop {
            let inner = store.inner.lock().await;
            let waiting: usize = inner.pending.dbus_futures.values().map(Vec::len).sum();

            if waiting == waiters {
                return inner.pending.pending.keys().cloned().collect();
            }

            assert!(Instant::now() < deadline, "requests never queued");
            drop(inner);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn approve(
        store: &PolicyStore,
        pending_id: &str,
        scope: ApprovalScope,
        target: DbusTarget,
    ) -> RpcReply {
        store
            .apply_pending_decision(
                PendingDecision {
                    pending_id: pending_id.into(),
                    scope,
                    target: Some(ApprovalTarget::Dbus { target }),
                    wire: ScopeWire::from_resolved(&ctx(), Some(UI_SESSION.into())),
                    client_id: 1,
                    approver_uid: Some(1000),
                },
                DecisionAction::Approve,
            )
            .await
    }

    #[tokio::test]
    async fn identical_requests_share_one_prompt_and_its_verdict() {
        let store = store(Duration::from_secs(30));
        let _ui = register_ui(&store).await;
        let requests = [request(&store, "Read"), request(&store, "Read")];
        let pending_ids = queued(&store, requests.len()).await;

        assert_eq!(pending_ids.len(), 1, "identical requests share one prompt");

        let reply = approve(&store, &pending_ids[0], ApprovalScope::Once, target("Read")).await;
        assert!(reply.scope_succeeded(), "got: {reply:?}");

        for request in requests {
            let reply = request.await.expect("request task");

            assert_eq!(
                reply.verdict,
                Verdict::allowed(VerdictSource::Scope(ApprovalScope::Once))
            );
        }
    }

    #[tokio::test]
    async fn waiter_cap_blocks_a_further_identical_request() {
        let store = store(Duration::from_secs(30));
        let _ui = register_ui(&store).await;

        let waiting: Vec<_> = (0..MAX_WAITERS_PER_PENDING)
            .map(|_| request(&store, "Read"))
            .collect();

        queued(&store, MAX_WAITERS_PER_PENDING).await;

        let reply = store.request_dbus_approval(target("Read"), ctx()).await;

        assert_eq!(reply.verdict.source, VerdictSource::Blocked);

        assert_eq!(
            reply.error.as_deref(),
            Some("agent-sandbox: too many waiters for one D-Bus approval")
        );

        for request in waiting {
            request.abort();
        }
    }

    #[tokio::test]
    async fn pending_cap_blocks_a_new_prompt() {
        let store = store(Duration::from_secs(30));

        let mut inner = store.inner.lock().await;

        for index in 0..MAX_PENDING_APPROVALS {
            let id = format!("dbus:seed{index}");

            inner.pending.pending.insert(
                id.clone(),
                Pending::Dbus(PendingDbus {
                    id,
                    created_at: 0.0,
                    target: target(&format!("Seed{index}")),
                    ctx: ctx(),
                }),
            );
        }

        drop(inner);

        let reply = store.request_dbus_approval(target("Read"), ctx()).await;

        assert_eq!(
            reply.error.as_deref(),
            Some("agent-sandbox: too many pending approvals")
        );

        assert_eq!(
            store.inner.lock().await.pending.pending.len(),
            MAX_PENDING_APPROVALS,
            "a blocked request must not queue a pending"
        );
    }

    #[tokio::test]
    async fn request_without_a_ui_is_blocked_and_leaves_no_pending() {
        let store = store(Duration::from_millis(100));
        let reply = store.request_dbus_approval(target("Read"), ctx()).await;

        assert_eq!(
            reply.error.as_deref(),
            Some(
                "agent-sandbox: no standalone policy UI registered (agent-sandbox-ui or \
                 auto-spawn)"
            )
        );

        assert!(store.inner.lock().await.pending.pending.is_empty());
    }

    #[tokio::test]
    async fn undecided_request_times_out_blocked_and_leaves_no_pending() {
        let store = store(Duration::from_millis(100));
        let _ui = register_ui(&store).await;
        let reply = store.request_dbus_approval(target("Read"), ctx()).await;

        assert_eq!(
            reply.error.as_deref(),
            Some("agent-sandbox: D-Bus approval timed out (no response from policy UI)")
        );

        assert!(store.inner.lock().await.pending.pending.is_empty());
    }

    #[tokio::test]
    async fn session_decision_settles_the_other_pendings_it_covers() {
        let store = store(Duration::from_secs(30));
        let _ui = register_ui(&store).await;
        let requests = [request(&store, "Read"), request(&store, "Write")];
        let pending_ids = queued(&store, requests.len()).await;

        assert_eq!(
            pending_ids.len(),
            2,
            "different requests get their own prompts"
        );

        let reply = approve(&store, &pending_ids[0], ApprovalScope::Session, target("*")).await;
        assert!(reply.scope_succeeded(), "got: {reply:?}");

        for request in requests {
            let reply = tokio::time::timeout(Duration::from_secs(5), request)
                .await
                .expect("the decision must answer every request it covers")
                .expect("request task");

            assert_eq!(
                reply.verdict,
                Verdict::allowed(VerdictSource::Scope(ApprovalScope::Session))
            );
        }

        assert!(store.inner.lock().await.pending.pending.is_empty());
    }

    #[tokio::test]
    async fn rejected_decision_leaves_the_pending_queued_and_answerable() {
        let store = store(Duration::from_secs(30));
        let _ui = register_ui(&store).await;
        let request = request(&store, "Read");
        let pending_ids = queued(&store, 1).await;

        let other = target("Write");
        let rejected = approve(&store, &pending_ids[0], ApprovalScope::Session, other).await;

        assert!(
            !rejected.scope_succeeded(),
            "a target that does not cover the request must be rejected"
        );

        assert_eq!(queued(&store, 1).await, pending_ids);

        let reply = approve(&store, &pending_ids[0], ApprovalScope::Once, target("Read")).await;
        assert!(reply.scope_succeeded(), "got: {reply:?}");

        let reply = request.await.expect("request task");
        assert!(reply.verdict.allowed, "got: {reply:?}");
    }

    const D_BUS_TIMED_OUT: &str =
        "agent-sandbox: D-Bus approval timed out (no response from policy UI)";

    #[tokio::test]
    async fn queued_prompt_gets_its_full_window_after_the_one_ahead_expires() {
        let timeout = Duration::from_millis(400);
        let store = store(timeout);
        let _ui = register_ui(&store).await;

        let first = request(&store, "Read");
        queued(&store, 1).await;
        let second = request(&store, "Write");
        queued(&store, 2).await;

        let first_reply = first.await.expect("request task");
        assert_eq!(first_reply.error.as_deref(), Some(D_BUS_TIMED_OUT));

        // The window the second prompt would have had from its creation is
        // over, but it was not on screen before the first one ended.
        tokio::time::sleep(timeout / 2).await;

        assert!(
            !second.is_finished(),
            "a queued prompt timed out while it waited behind another"
        );

        let pending_ids = queued(&store, 1).await;
        let reply = approve(
            &store,
            &pending_ids[0],
            ApprovalScope::Once,
            target("Write"),
        )
        .await;
        assert!(reply.scope_succeeded(), "got: {reply:?}");

        let reply = second.await.expect("request task");
        assert!(reply.verdict.allowed, "got: {reply:?}");
    }

    #[tokio::test]
    async fn one_waiter_timing_out_leaves_the_others_on_the_shared_prompt() {
        let timeout = Duration::from_millis(400);
        let store = store(timeout);
        let _ui = register_ui(&store).await;

        let first = request(&store, "Read");
        queued(&store, 1).await;
        tokio::time::sleep(timeout / 2).await;
        let second = request(&store, "Read");
        let pending_ids = queued(&store, 2).await;
        assert_eq!(pending_ids.len(), 1, "identical requests share one prompt");

        let first_reply = first.await.expect("request task");
        assert_eq!(first_reply.error.as_deref(), Some(D_BUS_TIMED_OUT));

        assert!(
            !second.is_finished(),
            "the other waiter was denied with the one that timed out"
        );

        assert_eq!(queued(&store, 1).await, pending_ids);

        let reply = approve(&store, &pending_ids[0], ApprovalScope::Once, target("Read")).await;
        assert!(reply.scope_succeeded(), "got: {reply:?}");

        let reply = second.await.expect("request task");
        assert!(reply.verdict.allowed, "got: {reply:?}");
    }
}

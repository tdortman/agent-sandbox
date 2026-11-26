//! Fairness of the approval queue across sandbox scopes.
//!
//! All sandboxes of one user share one prompt line, so what one sandbox
//! queues must not decide what another can ask. Two things are accounted per
//! sandbox scope (the agent cgroup of the requesting process, which a sandbox
//! cannot choose): how many approval requests it may have in flight, and where
//! its prompts stand in line.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use agent_sandbox_core::ResolvedRequestContext;

use super::types::Pending;

/// Who a request is counted against, by the best identity policyd has.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScopeKey {
    /// The agent scope cgroup of the requesting process. The kernel reports
    /// it, so a sandbox cannot count its requests against another one.
    Scope(PathBuf),

    /// The session policyd attributed the request to, for a request whose
    /// process is gone or is in no agent scope. Only an attribution backed by
    /// evidence counts (the package is set), never a session id a request
    /// merely names.
    Session(String),

    /// The user, when nothing finer identifies the request.
    User(u32),

    /// Nothing identifies the request.
    Shared,
}

/// Approval requests one sandbox scope may have in flight at once. Beyond
/// it the scope's requests are blocked without queueing, so one sandbox
/// cannot occupy the shared pending table, the policy UI, the NFQUEUE
/// handlers or the connections other sandboxes need.
pub const MAX_PROMPTS_PER_SCOPE: usize = 16;

/// The same cap for the buckets of requests that only a user, or nothing,
/// identifies. It is smaller than [`MAX_PROMPTS_PER_SCOPE`]: whoever fills one
/// blocks the other requests in it, so it stays well under the NFQUEUE
/// handler pool.
pub const MAX_UNATTRIBUTED_PROMPTS: usize = 8;

const fn limit(scope: &ScopeKey) -> usize {
    match scope {
        ScopeKey::Scope(_) | ScopeKey::Session(_) => MAX_PROMPTS_PER_SCOPE,
        ScopeKey::User(_) | ScopeKey::Shared => MAX_UNATTRIBUTED_PROMPTS,
    }
}

#[derive(Default)]
struct InFlight(Mutex<HashMap<ScopeKey, usize>>);

/// One approval request in flight for a scope. Dropping it frees the slot
/// wherever the request ends.
pub struct PromptSlot {
    in_flight: Arc<InFlight>,
    scope: ScopeKey,
    quantum: Duration,
}

impl Drop for PromptSlot {
    fn drop(&mut self) {
        let mut in_flight = self
            .in_flight
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        if let Some(count) = in_flight.get_mut(&self.scope) {
            *count -= 1;

            if *count == 0 {
                in_flight.remove(&self.scope);
            }
        }
    }
}

/// In-flight counts and queue positions of the pending approvals.
#[derive(Default)]
pub struct PromptQueue {
    in_flight: Arc<InFlight>,

    /// Where each pending stands in line, in seconds on the clock of
    /// `created_at`.
    start: HashMap<String, f64>,

    /// When each scope's last queued prompt ends its turn.
    tails: HashMap<ScopeKey, f64>,
}

impl PromptQueue {
    /// Take a slot for one request of `scope`; `quantum` is the length of a
    /// turn in line. `None` at the scope's cap.
    pub(crate) fn acquire(&self, scope: ScopeKey, quantum: Duration) -> Option<PromptSlot> {
        let mut in_flight = self
            .in_flight
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        let count = in_flight.entry(scope.clone()).or_insert(0);

        if *count >= limit(&scope) {
            return None;
        }

        *count += 1;
        drop(in_flight);

        Some(PromptSlot {
            in_flight: Arc::clone(&self.in_flight),
            scope,
            quantum,
        })
    }

    /// Place the new pending `id` in line.
    ///
    /// A scope's prompts are spaced one `quantum` apart, so however many a
    /// scope queues ahead, at most one of them stands before a prompt another
    /// scope queues later: that prompt waits for one turn per scope, not one
    /// per queued prompt.
    pub(super) fn enqueue(
        &mut self,
        id: &str,
        slot: &PromptSlot,
        created_at: f64,
        board: &HashMap<String, Pending>,
    ) {
        self.start.retain(|id, _| board.contains_key(id));
        self.tails.retain(|_, tail| *tail > created_at);

        let start = self
            .tails
            .get(&slot.scope)
            .map_or(created_at, |tail| tail.max(created_at));

        self.tails
            .insert(slot.scope.clone(), start + slot.quantum.as_secs_f64());
        self.start.insert(id.to_owned(), start);
    }

    /// Where the pending `id` stands in line; `fallback` when it was never
    /// placed.
    pub(super) fn start_of(&self, id: &str, fallback: f64) -> f64 {
        self.start.get(id).copied().unwrap_or(fallback)
    }
}

/// The outermost agent scope `cgroup` lies in. A process in a cgroup nested
/// under its scope still counts against the scope, whatever the nested
/// directories are called.
fn scope_root_of(cgroup: &Path) -> Option<PathBuf> {
    cgroup
        .ancestors()
        .filter(|ancestor| {
            ancestor
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("agent-sandbox-")
                        && Path::new(name)
                            .extension()
                            .is_some_and(|ext| ext == "scope")
                })
        })
        .last()
        .map(Path::to_path_buf)
}

/// The agent scope of the process `pid`, when it is in one.
pub(super) fn scope_root(pid: u32) -> Option<PathBuf> {
    super::lifecycle::agent_scope_cgroup(pid).and_then(|cgroup| scope_root_of(&cgroup))
}

/// Who `ctx`'s request is counted against: its process's agent scope, else
/// the session policyd verified it belongs to, else its user, else nobody in
/// particular.
pub(super) fn scope_of(ctx: &ResolvedRequestContext) -> ScopeKey {
    if let Some(scope) = ctx.ids.pid().and_then(scope_root) {
        return ScopeKey::Scope(scope);
    }

    if let (Some(session), Some(_package)) = (&ctx.sandbox_session_id, &ctx.package) {
        return ScopeKey::Session(session.clone());
    }

    ctx.ids.uid().map_or(ScopeKey::Shared, ScopeKey::User)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf, time::Duration};

    use agent_sandbox_core::{ProcessIds, ResolvedRequestContext, SandboxPaths};

    use super::{
        MAX_PROMPTS_PER_SCOPE, MAX_UNATTRIBUTED_PROMPTS, PromptQueue, ScopeKey, scope_of,
        scope_root_of,
    };

    const TURN: Duration = Duration::from_secs(20);

    fn scope(name: &str) -> ScopeKey {
        ScopeKey::Scope(PathBuf::from(name))
    }

    fn ctx(
        pid: Option<u32>,
        uid: Option<u32>,
        session: Option<&str>,
        package: Option<&str>,
    ) -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::default(),
            ids: ProcessIds::from_options(pid, uid),
            sandbox_session_id: session.map(Into::into),
            package: package.map(Into::into),
        }
    }

    #[test]
    fn a_scope_at_its_cap_leaves_other_scopes_their_slots() {
        let queue = PromptQueue::default();

        let held: Vec<_> = (0..MAX_PROMPTS_PER_SCOPE)
            .map(|_| queue.acquire(scope("a"), TURN).expect("below the cap"))
            .collect();

        assert!(queue.acquire(scope("a"), TURN).is_none());
        assert!(queue.acquire(scope("b"), TURN).is_some());

        drop(held);
        assert!(queue.acquire(scope("a"), TURN).is_some());
    }

    #[test]
    fn requests_nothing_identifies_share_a_smaller_bucket() {
        let queue = PromptQueue::default();

        let held: Vec<_> = (0..MAX_UNATTRIBUTED_PROMPTS)
            .map(|_| {
                queue
                    .acquire(ScopeKey::Shared, TURN)
                    .expect("below the cap")
            })
            .collect();

        assert!(queue.acquire(ScopeKey::Shared, TURN).is_none());
        assert!(queue.acquire(scope("a"), TURN).is_some());
        assert!(queue.acquire(ScopeKey::User(1000), TURN).is_some());
        drop(held);
    }

    #[test]
    fn unattributed_requests_get_a_bucket_each_by_the_best_identity() {
        let queue = PromptQueue::default();

        let held: Vec<_> = (0..MAX_PROMPTS_PER_SCOPE)
            .map(|_| {
                queue
                    .acquire(ScopeKey::Session("a".into()), TURN)
                    .expect("below the cap")
            })
            .collect();

        assert!(queue.acquire(ScopeKey::Session("a".into()), TURN).is_none());
        assert!(queue.acquire(ScopeKey::Session("b".into()), TURN).is_some());
        assert!(queue.acquire(ScopeKey::Shared, TURN).is_some());
        drop(held);
    }

    #[test]
    fn the_identity_of_a_request_without_a_live_scope_follows_the_evidence() {
        // A session id alone is a claim; with the package it is attributed.
        assert_eq!(
            scope_of(&ctx(None, Some(1000), Some("a"), Some("pkg"))),
            ScopeKey::Session("a".into())
        );
        assert_eq!(
            scope_of(&ctx(None, Some(1000), Some("a"), None)),
            ScopeKey::User(1000)
        );
        assert_eq!(scope_of(&ctx(None, None, None, None)), ScopeKey::Shared);

        // A pid that is in no agent scope falls through the same way.
        assert_eq!(
            scope_of(&ctx(Some(std::process::id()), Some(1000), None, None)),
            ScopeKey::User(1000)
        );
    }

    #[test]
    fn a_nested_cgroup_counts_against_its_agent_scope() {
        let scope = "/sys/fs/cgroup/user.slice/agent-sandbox-12_34.scope";

        assert_eq!(
            scope_root_of(std::path::Path::new(&format!(
                "{scope}/sub/agent-sandbox-1_2.scope"
            ))),
            Some(PathBuf::from(scope))
        );
        assert_eq!(
            scope_root_of(std::path::Path::new(
                "/sys/fs/cgroup/user.slice/app.service"
            )),
            None
        );
    }

    #[test]
    fn a_later_scope_stands_before_all_but_the_first_prompt_of_a_busy_scope() {
        let mut queue = PromptQueue::default();
        let board = HashMap::new();
        let rogue = queue.acquire(scope("rogue"), TURN).expect("slot");
        let victim = queue.acquire(scope("victim"), TURN).expect("slot");

        // Each start is read as it is placed: `enqueue` forgets pendings no
        // longer on the board, and this board is empty.
        let mut place = |id, slot, created_at| {
            queue.enqueue(id, slot, created_at, &board);
            queue.start_of(id, f64::NAN)
        };

        let r0 = place("r0", &rogue, 100.0);
        let r1 = place("r1", &rogue, 100.1);
        let r2 = place("r2", &rogue, 100.2);
        let v0 = place("v0", &victim, 105.0);

        assert!(r0 < v0, "r0 {r0} v0 {v0}");
        assert!(v0 < r1, "v0 {v0} r1 {r1}");
        assert!(r1 < r2, "r1 {r1} r2 {r2}");
    }

    #[test]
    fn a_prompt_after_the_scope_went_quiet_starts_at_its_creation() {
        let mut queue = PromptQueue::default();
        let board = HashMap::new();
        let slot = queue.acquire(scope("a"), TURN).expect("slot");

        queue.enqueue("p0", &slot, 100.0, &board);
        queue.enqueue("p1", &slot, 500.0, &board);

        assert!((queue.start_of("p1", f64::NAN) - 500.0).abs() < f64::EPSILON);
    }
}

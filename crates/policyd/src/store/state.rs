//! The policy decision state: one mutex-guarded struct plus the nested
//! state groups behind it.
//!
//! `SessionState` concentrates the deny-wins invariant for the runtime
//! decision buckets: an approve always clears the matching deny key and
//! vice versa, through [`BucketPair::apply`].
//!
//! `PendingBoard` concentrates the pending map and the per capability
//! oneshot waiter maps, so a pending id, its futures, and its http
//! waiters live and die together.

use super::{
    decisions::DecisionAction,
    types::{
        DenyInodeCache, HttpPendingKey, HttpScopeKey, Pending, ProxyCancellation, ProxyFlowState,
        ProxySessionState, UiClient, UiSessionContext, VerdictEntry,
    },
};
use agent_sandbox_core::{
    AttributionToken, CheckReply, DbusCheckReply, DbusTarget, ElevateReply, FilesystemCheckReply,
    FilesystemRule, FilesystemRuleKey, HttpCheckReply, NetworkFlowKey, NetworkRuleKey,
    PendingHttpId, ProxyRequestId, ProxySessionToken, ResourceCheckReply, ResourceRuleKey,
};
use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};
use tokio::sync::oneshot;

/// One check on a trusted proxy session: which session, which request
/// on that session. Named type instead of a tuple key so the pairing is
/// explicit at construction and match sites.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyCheckId {
    pub(crate) session: ProxySessionToken,
    pub(crate) request: ProxyRequestId,
}

/// One decoded HTTP check waiting for the policy UI.
#[derive(Debug)]
pub struct HttpWaiter {
    pub(crate) request_id: ProxyRequestId,
    pub(crate) proxy_session: ProxySessionToken,
    pub(crate) attribution_token: AttributionToken,
    pub(crate) tx: oneshot::Sender<HttpCheckReply>,
}

/// One transport fallback check waiting for a policy verdict.
#[derive(Debug)]
pub struct NetworkWaiter {
    pub(crate) proxy: Option<ProxyCheckId>,
    pub(crate) tx: oneshot::Sender<CheckReply>,
}

/// A session allow/deny bucket pair with deny-wins insertion.
pub struct BucketPair<'a, T> {
    allow: &'a mut HashMap<String, HashSet<T>>,
    deny: &'a mut HashMap<String, HashSet<T>>,
}

impl<T: Clone + Eq + std::hash::Hash> BucketPair<'_, T> {
    /// Insert `key` for `session_id` under `action`, clearing the matching
    /// key from the opposite bucket. Approve wins by removing deny; deny
    /// wins by removing allow.
    pub(crate) fn apply(&mut self, action: DecisionAction, session_id: &str, key: &T) {
        match action {
            DecisionAction::Approve => {
                self.allow
                    .entry(session_id.to_owned())
                    .or_default()
                    .insert(key.clone());
                if let Some(bucket) = self.deny.get_mut(session_id) {
                    bucket.remove(key);
                }
            }

            DecisionAction::Deny => {
                self.deny
                    .entry(session_id.to_owned())
                    .or_default()
                    .insert(key.clone());
                if let Some(bucket) = self.allow.get_mut(session_id) {
                    bucket.remove(key);
                }
            }
        }
    }
}

/// The runtime decision buckets: per-session allow/deny sets and the
/// once-consumed keys, for every capability.
#[derive(Default)]
pub struct SessionState {
    pub(crate) session_allow: HashMap<String, HashSet<NetworkRuleKey>>,
    pub(crate) session_deny: HashMap<String, HashSet<NetworkRuleKey>>,
    pub(crate) once_allow: HashSet<NetworkRuleKey>,
    pub(crate) session_sudo_allow: HashMap<String, HashSet<Vec<String>>>,
    pub(crate) session_sudo_deny: HashMap<String, HashSet<Vec<String>>>,
    pub(crate) session_filesystem_allow: HashMap<String, HashSet<FilesystemRuleKey>>,
    pub(crate) session_filesystem_deny: HashMap<String, HashSet<FilesystemRuleKey>>,
    pub(crate) session_resource_allow: HashMap<String, HashSet<ResourceRuleKey>>,
    pub(crate) session_resource_deny: HashMap<String, HashSet<ResourceRuleKey>>,
    pub(crate) session_dbus_allow: HashMap<String, HashSet<DbusTarget>>,
    pub(crate) session_dbus_deny: HashMap<String, HashSet<DbusTarget>>,
    pub(crate) http_once_allow: HashSet<HttpPendingKey>,
    pub(crate) http_once_deny: HashSet<HttpPendingKey>,
    pub(crate) http_session_allow: HashMap<String, HashSet<HttpScopeKey>>,
    pub(crate) http_session_deny: HashMap<String, HashSet<HttpScopeKey>>,
}

impl SessionState {
    pub(crate) const fn network(&mut self) -> BucketPair<'_, NetworkRuleKey> {
        BucketPair {
            allow: &mut self.session_allow,
            deny: &mut self.session_deny,
        }
    }

    pub(crate) const fn sudo(&mut self) -> BucketPair<'_, Vec<String>> {
        BucketPair {
            allow: &mut self.session_sudo_allow,
            deny: &mut self.session_sudo_deny,
        }
    }

    pub(crate) const fn filesystem(&mut self) -> BucketPair<'_, FilesystemRuleKey> {
        BucketPair {
            allow: &mut self.session_filesystem_allow,
            deny: &mut self.session_filesystem_deny,
        }
    }

    pub(crate) const fn resource(&mut self) -> BucketPair<'_, ResourceRuleKey> {
        BucketPair {
            allow: &mut self.session_resource_allow,
            deny: &mut self.session_resource_deny,
        }
    }

    pub(crate) const fn dbus(&mut self) -> BucketPair<'_, DbusTarget> {
        BucketPair {
            allow: &mut self.session_dbus_allow,
            deny: &mut self.session_dbus_deny,
        }
    }

    pub(crate) const fn http(&mut self) -> BucketPair<'_, HttpScopeKey> {
        BucketPair {
            allow: &mut self.http_session_allow,
            deny: &mut self.http_session_deny,
        }
    }
}

/// The pending approval map plus the per capability oneshot waiter maps.
#[derive(Default)]
pub struct PendingBoard {
    pub(crate) pending: HashMap<String, Pending>,
    pub(crate) elevation_futures: HashMap<String, oneshot::Sender<ElevateReply>>,
    pub(crate) network_futures: HashMap<String, Vec<NetworkWaiter>>,
    pub(crate) filesystem_futures: HashMap<String, Vec<oneshot::Sender<FilesystemCheckReply>>>,
    pub(crate) resource_futures: HashMap<String, Vec<oneshot::Sender<ResourceCheckReply>>>,
    pub(crate) dbus_futures: HashMap<String, Vec<oneshot::Sender<DbusCheckReply>>>,
    pub(crate) http_futures: HashMap<PendingHttpId, Vec<HttpWaiter>>,
    pub(crate) http_waiters: HashMap<ProxyCheckId, PendingHttpId>,
}

impl PendingBoard {
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn pending_values(&self) -> impl Iterator<Item = &Pending> {
        self.pending.values()
    }

    #[cfg(test)]
    pub(crate) fn pending_keys(&self) -> impl Iterator<Item = &String> {
        self.pending.keys()
    }

    #[cfg(test)]
    pub(crate) fn pending_entries(&self) -> impl Iterator<Item = (&String, &Pending)> {
        self.pending.iter()
    }

    pub(crate) fn pending_get(&self, pending_id: &str) -> Option<&Pending> {
        self.pending.get(pending_id)
    }

    pub(crate) fn insert_pending(&mut self, pending: Pending) -> Option<Pending> {
        let pending_id = pending.id().to_owned();
        self.pending.insert(pending_id, pending)
    }

    pub(crate) fn take_pending(&mut self, pending_id: &str) -> Option<Pending> {
        self.pending.remove(pending_id)
    }

    pub(crate) fn restore_pending(&mut self, pending: Pending) {
        let _ = self.insert_pending(pending);
    }
}

/// The full decision state behind `PolicyStore::inner`.
#[derive(Default)]
pub struct PolicyDecisionState {
    pub(crate) session: SessionState,
    pub(crate) pending: PendingBoard,
    pub(crate) proxy_cancellations: HashMap<ProxyCheckId, ProxyCancellation>,
    pub(crate) ui_clients: HashMap<u64, UiClient>,
    pub(crate) ui_context_by_session: HashMap<String, UiSessionContext>,
    pub(crate) network_verdict_cache: HashMap<NetworkRuleKey, VerdictEntry>,
    pub(crate) filesystem_verdict_cache: HashMap<FilesystemRuleKey, VerdictEntry>,
    pub(crate) resource_verdict_cache: HashMap<ResourceRuleKey, VerdictEntry>,
    pub(crate) dbus_verdict_cache: HashMap<DbusTarget, VerdictEntry>,
    pub(crate) http_verdict_cache: HashMap<HttpPendingKey, VerdictEntry>,
    pub(crate) ui_spawn_last: HashMap<String, Instant>,
    pub(crate) sandbox_filesystem_static_allow: HashMap<String, Vec<FilesystemRule>>,
    pub(crate) deny_inode_cache: DenyInodeCache,
    pub(crate) connections_by_uid: HashMap<u32, usize>,
    pub(crate) proxy_flows: HashMap<NetworkFlowKey, ProxyFlowState>,
    pub(crate) proxy_session: Option<ProxySessionState>,
}

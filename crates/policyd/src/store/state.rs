//! The policy decision state: one mutex-guarded struct plus the nested
//! state groups behind it.
//!
//! `SessionState` concentrates the deny-wins invariant for the runtime
//! decision buckets: an approve always clears the matching deny key and
//! vice versa, through [`apply_bucket`].
//!
//! `PendingBoard` concentrates the pending map and the per capability
//! oneshot waiter maps, so a pending id, its futures, and its http
//! waiters live and die together.

use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

use agent_sandbox_core::{
    AttributionToken, CheckReply, DbusCheckReply, DbusTarget, ElevateReply, FilesystemCheckReply,
    FilesystemRule, FilesystemRuleKey, HttpCheckReply, NetworkFlowKey, NetworkRuleKey,
    PendingHttpId, ProxyRequestId, ProxySessionToken, ResourceCheckReply, ResourceRuleKey,
};
use tokio::sync::oneshot;

use super::{
    decisions::DecisionAction,
    types::{
        DenyInodeCache, HttpPendingKey, HttpScopeKey, Pending, ProxyCancellation, ProxyFlowState,
        ProxySessionState, UiClient, UiSessionContext, VerdictEntry,
    },
};

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

/// Insert `key` for `session_id` under `action`, clearing the matching
/// key from the opposite bucket. Approve wins by removing deny; deny
/// wins by removing allow.
pub fn apply_bucket<T: Clone + Eq + std::hash::Hash>(
    allow: &mut HashMap<String, HashSet<T>>,
    deny: &mut HashMap<String, HashSet<T>>,
    action: DecisionAction,
    session_id: &str,
    key: &T,
) {
    match action {
        DecisionAction::Approve => {
            allow
                .entry(session_id.to_owned())
                .or_default()
                .insert(key.clone());
            if let Some(bucket) = deny.get_mut(session_id) {
                bucket.remove(key);
            }
        }

        DecisionAction::Deny => {
            deny.entry(session_id.to_owned())
                .or_default()
                .insert(key.clone());

            if let Some(bucket) = allow.get_mut(session_id) {
                bucket.remove(key);
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

//! The policy decision state: one mutex-guarded struct plus the nested
//! state groups behind it.
//!
//! `SessionState` concentrates the deny-wins invariant for the runtime
//! decision buckets: an approve always clears the matching deny key and
//! vice versa, through [`SessionBuckets`].
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

/// One capability's per-session allow and deny sets, borrowed from
/// [`SessionState`]. The only way to write them keeps the deny-wins
/// invariant: an approve clears the matching deny key and vice versa.
pub struct SessionBuckets<'a, K> {
    allow: &'a mut HashMap<String, HashSet<K>>,
    deny: &'a mut HashMap<String, HashSet<K>>,
}

impl<K: Clone + Eq + std::hash::Hash> SessionBuckets<'_, K> {
    /// Insert `key` for `session_id` under `action`, clearing the matching
    /// key from the opposite bucket. Approve wins by removing deny; deny
    /// wins by removing allow.
    pub fn apply(self, action: DecisionAction, session_id: &str, key: &K) {
        match action {
            DecisionAction::Approve => insert_clearing(self.allow, self.deny, session_id, key),
            DecisionAction::Deny => insert_clearing(self.deny, self.allow, session_id, key),
        }
    }
}

fn insert_clearing<K: Clone + Eq + std::hash::Hash>(
    add: &mut HashMap<String, HashSet<K>>,
    clear: &mut HashMap<String, HashSet<K>>,
    session_id: &str,
    key: &K,
) {
    add.entry(session_id.to_owned())
        .or_default()
        .insert(key.clone());

    if let Some(bucket) = clear.get_mut(session_id) {
        bucket.remove(key);
    }
}

/// The single declaration of the per-session decision buckets. Each entry
/// names the accessor on [`SessionState`], the rule key, and the allow and
/// deny fields (the field names are the handoff file's JSON keys). It calls
/// `$callback` with the whole list, so the state struct, its teardown, and
/// the handoff serialisation all derive from it; adding a capability's
/// session buckets is one entry here.
macro_rules! with_session_buckets {
    ($callback:ident) => {
        $callback! {
            network_buckets: NetworkRuleKey {
                allow: session_allow,
                deny: session_deny,
            },
            sudo_buckets: Vec<String> {
                allow: session_sudo_allow,
                deny: session_sudo_deny,
            },
            filesystem_buckets: FilesystemRuleKey {
                allow: session_filesystem_allow,
                deny: session_filesystem_deny,
            },
            resource_buckets: ResourceRuleKey {
                allow: session_resource_allow,
                deny: session_resource_deny,
            },
            dbus_buckets: DbusTarget {
                allow: session_dbus_allow,
                deny: session_dbus_deny,
            },
            http_buckets: HttpScopeKey {
                allow: http_session_allow,
                deny: http_session_deny,
            },
        }
    };
}

pub(super) use with_session_buckets;

/// Declares [`SessionState`] from the bucket list of
/// [`with_session_buckets`], plus the once-consumed key sets.
macro_rules! session_state {
    ($($accessor:ident: $key:ty { allow: $allow:ident, deny: $deny:ident $(,)? }),* $(,)?) => {
        /// The runtime decision buckets: per-session allow/deny sets and the
        /// once-consumed keys, for every capability.
        #[derive(Default)]
        pub struct SessionState {
            $(
                pub(crate) $allow: HashMap<String, HashSet<$key>>,
                pub(crate) $deny: HashMap<String, HashSet<$key>>,
            )*
            pub(crate) once_allow: HashSet<NetworkRuleKey>,
            pub(crate) http_once_allow: HashSet<HttpPendingKey>,
            pub(crate) http_once_deny: HashSet<HttpPendingKey>,
        }

        impl SessionState {
            $(
                pub(crate) const fn $accessor(&mut self) -> SessionBuckets<'_, $key> {
                    SessionBuckets {
                        allow: &mut self.$allow,
                        deny: &mut self.$deny,
                    }
                }
            )*

            /// Drop every per-session decision of `session_id`.
            pub(crate) fn forget_session(&mut self, session_id: &str) {
                $(
                    self.$allow.remove(session_id);
                    self.$deny.remove(session_id);
                )*
            }
        }
    };
}

with_session_buckets!(session_state);

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
    /// UI sessions handed over from the previous daemon that no UI has
    /// resumed yet; their context and decisions wait under the same id.
    pub(crate) resumable_ui_sessions: HashSet<String>,
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

#[cfg(test)]
mod tests {
    use agent_sandbox_core::{
        DbusMessageKind, FileAccess, HttpContextKey, HttpMethod, HttpMethodMatcher, HttpRuleTarget,
        HttpUrl, ResourceAccess, ResourceKind,
    };

    use super::*;
    use crate::store::{test_store, types::UiSessionContext};

    const SESSION: &str = "ui-session";

    /// Both the allow and the deny set of every capability hold one key.
    fn populate(state: &mut SessionState) {
        let http = |url: &str| HttpScopeKey {
            target: HttpRuleTarget::new(
                HttpMethodMatcher::Exact(HttpMethod::parse("GET").expect("valid method")),
                HttpUrl::parse(url).expect("valid URL"),
            )
            .expect("valid target"),
            context: HttpContextKey::default(),
        };

        let dbus = |member: &str| {
            DbusTarget::session(
                "org.example.Service",
                "/org/example/Object",
                "org.example.Interface",
                member,
                DbusMessageKind::MethodCall,
                "s",
                Vec::new(),
            )
        };

        let approve = DecisionAction::Approve;
        let deny = DecisionAction::Deny;

        state.network_buckets().apply(
            approve,
            SESSION,
            &NetworkRuleKey::new("allowed.example", 443),
        );
        state
            .network_buckets()
            .apply(deny, SESSION, &NetworkRuleKey::new("denied.example", 80));
        state
            .sudo_buckets()
            .apply(approve, SESSION, &vec!["ls".to_owned()]);
        state
            .sudo_buckets()
            .apply(deny, SESSION, &vec!["rm".to_owned()]);
        state.filesystem_buckets().apply(
            approve,
            SESSION,
            &FilesystemRuleKey::new("/allowed", FileAccess::Read),
        );
        state.filesystem_buckets().apply(
            deny,
            SESSION,
            &FilesystemRuleKey::new("/denied", FileAccess::ReadWrite),
        );
        state.resource_buckets().apply(
            approve,
            SESSION,
            &ResourceRuleKey::new(
                ResourceKind::Device,
                "/dev/allowed",
                ResourceAccess::Device(agent_sandbox_core::DeviceAccess::Read),
            ),
        );
        state.resource_buckets().apply(
            deny,
            SESSION,
            &ResourceRuleKey::new(
                ResourceKind::Device,
                "/dev/denied",
                ResourceAccess::Device(agent_sandbox_core::DeviceAccess::Read),
            ),
        );
        state
            .dbus_buckets()
            .apply(approve, SESSION, &dbus("Allowed"));
        state.dbus_buckets().apply(deny, SESSION, &dbus("Denied"));
        state
            .http_buckets()
            .apply(approve, SESSION, &http("https://allowed.example/"));
        state
            .http_buckets()
            .apply(deny, SESSION, &http("https://denied.example/"));
    }

    #[test]
    fn approve_and_deny_displace_each_other() {
        let mut state = SessionState::default();
        let key = NetworkRuleKey::new("example.com", 443);

        state
            .network_buckets()
            .apply(DecisionAction::Approve, SESSION, &key);
        state
            .network_buckets()
            .apply(DecisionAction::Deny, SESSION, &key);
        assert!(state.session_allow[SESSION].is_empty());
        assert!(state.session_deny[SESSION].contains(&key));

        state
            .network_buckets()
            .apply(DecisionAction::Approve, SESSION, &key);
        assert!(state.session_allow[SESSION].contains(&key));
        assert!(state.session_deny[SESSION].is_empty());
    }

    #[test]
    fn forgetting_a_session_clears_every_bucket() {
        let mut state = SessionState::default();
        populate(&mut state);
        state.forget_session(SESSION);

        let SessionState {
            session_allow,
            session_deny,
            session_sudo_allow,
            session_sudo_deny,
            session_filesystem_allow,
            session_filesystem_deny,
            session_resource_allow,
            session_resource_deny,
            session_dbus_allow,
            session_dbus_deny,
            http_session_allow,
            http_session_deny,
            once_allow: _,
            http_once_allow: _,
            http_once_deny: _,
        } = state;

        assert!(session_allow.is_empty() && session_deny.is_empty());
        assert!(session_sudo_allow.is_empty() && session_sudo_deny.is_empty());
        assert!(session_filesystem_allow.is_empty() && session_filesystem_deny.is_empty());
        assert!(session_resource_allow.is_empty() && session_resource_deny.is_empty());
        assert!(session_dbus_allow.is_empty() && session_dbus_deny.is_empty());
        assert!(http_session_allow.is_empty() && http_session_deny.is_empty());
    }

    /// Every session bucket survives a handoff, and the file keeps the key
    /// names an older daemon wrote and a newer one must still read.
    #[tokio::test]
    async fn handoff_carries_every_session_bucket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("handoff.json");
        let first = test_store();

        {
            let mut inner = first.inner.lock().await;
            populate(&mut inner.session);
            let (writer, _) = tokio::net::UnixStream::pair().expect("unix stream pair");
            inner.ui_clients.insert(1, crate::store::types::UiClient {
                session_id: SESSION.to_owned(),
                writer: std::sync::Arc::new(tokio::sync::Mutex::new(writer.into_split().1)),
            });
            inner
                .ui_context_by_session
                .insert(SESSION.to_owned(), UiSessionContext::default());
        }

        drop(first.write_handoff_to(&path).await.expect("write handoff"));

        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read handoff"))
                .expect("handoff is JSON");
        let mut keys: Vec<&str> = file["ui_sessions"][0]["decisions"]
            .as_object()
            .expect("decisions object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, [
            "http_session_allow",
            "http_session_deny",
            "session_allow",
            "session_dbus_allow",
            "session_dbus_deny",
            "session_deny",
            "session_filesystem_allow",
            "session_filesystem_deny",
            "session_resource_allow",
            "session_resource_deny",
            "session_sudo_allow",
            "session_sudo_deny",
        ]);

        let mut second = test_store();
        second.restore_handoff_from(&path);

        let original = first.inner.lock().await;
        let restored = second.inner.lock().await;
        let a = &original.session;
        let b = &restored.session;
        assert_eq!(a.session_allow, b.session_allow);
        assert_eq!(a.session_deny, b.session_deny);
        assert_eq!(a.session_sudo_allow, b.session_sudo_allow);
        assert_eq!(a.session_sudo_deny, b.session_sudo_deny);
        assert_eq!(a.session_filesystem_allow, b.session_filesystem_allow);
        assert_eq!(a.session_filesystem_deny, b.session_filesystem_deny);
        assert_eq!(a.session_resource_allow, b.session_resource_allow);
        assert_eq!(a.session_resource_deny, b.session_resource_deny);
        assert_eq!(a.session_dbus_allow, b.session_dbus_allow);
        assert_eq!(a.session_dbus_deny, b.session_dbus_deny);
        assert_eq!(a.http_session_allow, b.http_session_allow);
        assert_eq!(a.http_session_deny, b.http_session_deny);
        assert!(!b.session_allow.is_empty() && !b.http_session_deny.is_empty());
        drop(original);
        drop(restored);
    }
}

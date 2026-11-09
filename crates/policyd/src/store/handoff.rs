//! State a stopping policyd hands to the daemon that replaces it.
//!
//! On `SIGTERM` the daemon writes the trusted proxy's session and flows and
//! every connected policy UI's session with its session-scope decisions to a
//! root-only file. The next daemon reads and deletes the file at startup. The
//! proxy resumes its session with `ResumeProxySession` and keeps its claimed
//! connections; a reconnecting UI that presents its previous session id keeps
//! its session decisions. A daemon that dies without `SIGTERM` writes nothing
//! and its successor starts empty. Pending prompts are not handed over: their
//! clients retry against the new daemon.

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};

use agent_sandbox_core::{
    AttributionToken, DbusTarget, FilesystemRuleKey, FlowRegistration, NetworkRuleKey,
    ProxyConnectionId, ProxySessionToken, ResourceRuleKey,
};
use serde::{Deserialize, Serialize};
use tokio::sync::MutexGuard;
use tracing::{info, warn};

use super::{
    sandbox_state::write_atomic,
    state::{PolicyDecisionState, SessionState},
    types::{HttpScopeKey, PolicyStore, ProxyFlowState, ProxySessionState, UiSessionContext},
};

const DEFAULT_HANDOFF_PATH: &str = "/run/agent-sandbox/policyd-handoff.json";
const HANDOFF_PATH_ENV: &str = "AGENT_SANDBOX_POLICYD_HANDOFF";

/// Handoff file contents.
#[derive(Default, Serialize, Deserialize)]
struct Handoff {
    #[serde(default)]
    proxy: Option<ProxyHandoff>,

    #[serde(default)]
    ui_sessions: Vec<UiSessionHandoff>,
}

/// The proxy's session token and the flows registered or claimed under it.
#[derive(Serialize, Deserialize)]
struct ProxyHandoff {
    token: ProxySessionToken,
    flows: Vec<FlowHandoff>,
}

/// One registered flow. Its request context is derived again from the
/// registration, as on registration.
#[derive(Serialize, Deserialize)]
struct FlowHandoff {
    registration: FlowRegistration,
    owner_fd_hint: Option<u32>,
    attribution_token: Option<AttributionToken>,
    connection_id: Option<ProxyConnectionId>,
}

/// One UI session: the context it registered with and its decisions.
#[derive(Serialize, Deserialize)]
struct UiSessionHandoff {
    id: String,
    cwd: Option<PathBuf>,
    home: Option<PathBuf>,
    project_root: Option<PathBuf>,
    sandbox_session_id: Option<String>,
    owner_uid: Option<u32>,
    decisions: SessionDecisions,
}

/// Declares [`SessionDecisions`] with one list per per-session bucket of
/// [`SessionState`], named after the bucket.
macro_rules! session_decisions {
    ($($bucket:ident: $key:ty),* $(,)?) => {
        /// One session's entries in every per-session decision bucket.
        #[derive(Default, Serialize, Deserialize)]
        struct SessionDecisions {
            $(
                #[serde(default)]
                $bucket: Vec<$key>,
            )*
        }

        impl SessionDecisions {
            fn of(state: &SessionState, session_id: &str) -> Self {
                Self {
                    $(
                        $bucket: state
                            .$bucket
                            .get(session_id)
                            .map(|bucket| bucket.iter().cloned().collect())
                            .unwrap_or_default(),
                    )*
                }
            }

            fn restore(self, state: &mut SessionState, session_id: &str) {
                $(
                    if !self.$bucket.is_empty() {
                        state
                            .$bucket
                            .insert(session_id.to_owned(), self.$bucket.into_iter().collect());
                    }
                )*
            }
        }
    };
}

session_decisions! {
    session_allow: NetworkRuleKey,
    session_deny: NetworkRuleKey,
    session_sudo_allow: Vec<String>,
    session_sudo_deny: Vec<String>,
    session_filesystem_allow: FilesystemRuleKey,
    session_filesystem_deny: FilesystemRuleKey,
    session_resource_allow: ResourceRuleKey,
    session_resource_deny: ResourceRuleKey,
    session_dbus_allow: DbusTarget,
    session_dbus_deny: DbusTarget,
    http_session_allow: HttpScopeKey,
    http_session_deny: HttpScopeKey,
}

fn handoff_path() -> PathBuf {
    std::env::var_os(HANDOFF_PATH_ENV)
        .map_or_else(|| PathBuf::from(DEFAULT_HANDOFF_PATH), PathBuf::from)
}

impl PolicyStore {
    /// Write the handoff for the next daemon to the path named by
    /// `AGENT_SANDBOX_POLICYD_HANDOFF`.
    ///
    /// Returns the decision state lock still held: no request may change the
    /// state after the snapshot, so the caller exits without releasing it.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the file cannot be written.
    pub async fn write_handoff(&self) -> io::Result<MutexGuard<'_, PolicyDecisionState>> {
        self.write_handoff_to(&handoff_path()).await
    }

    /// Take over the handoff the previous daemon wrote to the path named by
    /// `AGENT_SANDBOX_POLICYD_HANDOFF`.
    pub fn restore_handoff(&mut self) {
        self.restore_handoff_from(&handoff_path());
    }

    pub(crate) async fn write_handoff_to(
        &self,
        path: &Path,
    ) -> io::Result<MutexGuard<'_, PolicyDecisionState>> {
        let inner = self.inner.lock().await;

        let proxy = inner.proxy_session.as_ref().map(|session| ProxyHandoff {
            token: session.token.clone(),
            flows: inner
                .proxy_flows
                .values()
                .map(|flow| FlowHandoff {
                    registration: flow.registration.clone(),
                    owner_fd_hint: flow.owner_fd_hint,
                    attribution_token: flow.attribution_token.clone(),
                    connection_id: flow.connection_id,
                })
                .collect(),
        });

        let ui_sessions = inner
            .ui_clients
            .values()
            .filter_map(|client| {
                let ctx = inner.ui_context_by_session.get(&client.session_id)?;
                Some(UiSessionHandoff {
                    id: client.session_id.clone(),
                    cwd: ctx.cwd.clone(),
                    home: ctx.home.clone(),
                    project_root: ctx.project_root.clone(),
                    sandbox_session_id: ctx.sandbox_session_id.clone(),
                    owner_uid: ctx.owner_uid,
                    decisions: SessionDecisions::of(&inner.session, &client.session_id),
                })
            })
            .collect();

        write_atomic(path, &Handoff { proxy, ui_sessions })?;
        Ok(inner)
    }

    // The file is trusted because it lives in a root-owned directory and is
    // written only by root; sandboxes cannot modify it.
    pub(crate) fn restore_handoff_from(&mut self, path: &Path) {
        let Some(handoff) = take_handoff(path) else {
            return;
        };

        let restored_flows: Vec<ProxyFlowState> = handoff.proxy.as_ref().map_or_default(|proxy| {
            let now = Instant::now();
            proxy
                .flows
                .iter()
                .map(|flow| ProxyFlowState {
                    owner: flow.registration.owner(),
                    owner_fd_hint: flow.owner_fd_hint,
                    context: self.flow_context(&flow.registration),
                    registration: flow.registration.clone(),
                    attribution_token: flow.attribution_token.clone(),
                    connection_id: flow.connection_id,
                    claimed_at: flow.attribution_token.as_ref().map(|_| now),
                    last_check: now,
                })
                .collect()
        });

        let inner = self.inner.get_mut();
        let ui_sessions = handoff.ui_sessions.len();
        let flows = restored_flows.len();

        if let Some(proxy) = handoff.proxy {
            inner.proxy_session = Some(ProxySessionState {
                token: proxy.token,
                connection_id: None,
                opened_at: Instant::now(),
            });
            inner.proxy_flows.extend(
                restored_flows
                    .into_iter()
                    .map(|flow| (flow.registration.flow().clone(), flow)),
            );
        }

        for session in handoff.ui_sessions {
            session.decisions.restore(&mut inner.session, &session.id);
            inner
                .ui_context_by_session
                .insert(session.id.clone(), UiSessionContext {
                    cwd: session.cwd,
                    home: session.home,
                    project_root: session.project_root,
                    sandbox_session_id: session.sandbox_session_id,
                    owner_uid: session.owner_uid,
                    client_id: 0,
                });
            inner.resumable_ui_sessions.insert(session.id);
        }

        info!(
            ui_sessions,
            flows,
            proxy = inner.proxy_session.is_some(),
            "took over state from the previous policyd"
        );
    }
}

/// Read and delete the handoff, so a later start cannot apply it twice.
fn take_handoff(path: &Path) -> Option<Handoff> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => {
            warn!(%error, path = %path.display(), "ignoring unreadable policyd handoff");
            return None;
        }
    };

    if let Err(error) = fs::remove_file(path) {
        warn!(%error, path = %path.display(), "cannot remove policyd handoff; ignoring it");
        return None;
    }

    serde_json::from_str(&content)
        .inspect_err(|error| {
            warn!(%error, path = %path.display(), "ignoring corrupt policyd handoff");
        })
        .ok()
}

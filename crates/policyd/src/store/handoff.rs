//! State a stopping policyd hands to the daemon that replaces it.
//!
//! On `SIGTERM` the daemon writes the trusted proxy's session and flows and
//! every connected policy UI's session with its session-scope decisions to a
//! root-only file. The next daemon reads and deletes the file at startup. The
//! proxy resumes its session with `ResumeProxySession` and keeps its claimed
//! connections; a reconnecting UI that presents its previous session id keeps
//! its session decisions. A daemon that dies without `SIGTERM` writes nothing
//! and its successor starts empty. Pending prompts are not handed over: their
//! clients retry against the new daemon. `restart.rs` restores this file
//! together with the state a crash preserves.

use std::{
    collections::{HashMap, HashSet},
    fs,
    hash::Hash,
    io,
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
    restart::write_atomic,
    state::{PolicyDecisionState, SessionState, with_session_buckets},
    types::{
        HandedOverUiSession, HttpScopeKey, PolicyStore, ProxyFlowState, ProxySessionState,
        UiSessionContext,
    },
};

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

/// Declares [`SessionDecisions`] from the bucket list of
/// [`with_session_buckets`]: one list per allow and deny bucket, named after
/// the [`SessionState`] field, which is the file's JSON key.
macro_rules! session_decisions {
    ($($accessor:ident: $key:ty { allow: $allow:ident, deny: $deny:ident $(,)? }),* $(,)?) => {
        /// One session's entries in every per-session decision bucket.
        #[derive(Default, Serialize, Deserialize)]
        struct SessionDecisions {
            $(
                #[serde(default)]
                $allow: Vec<$key>,
                #[serde(default)]
                $deny: Vec<$key>,
            )*
        }

        impl SessionDecisions {
            fn of(state: &SessionState, session_id: &str) -> Self {
                Self {
                    $(
                        $allow: bucket_entries(&state.$allow, session_id),
                        $deny: bucket_entries(&state.$deny, session_id),
                    )*
                }
            }

            fn restore(self, state: &mut SessionState, session_id: &str) {
                $(
                    restore_bucket(&mut state.$allow, session_id, self.$allow);
                    restore_bucket(&mut state.$deny, session_id, self.$deny);
                )*
            }
        }
    };
}

with_session_buckets!(session_decisions);

fn bucket_entries<K: Clone>(bucket: &HashMap<String, HashSet<K>>, session_id: &str) -> Vec<K> {
    bucket
        .get(session_id)
        .map_or_default(|keys| keys.iter().cloned().collect())
}

fn restore_bucket<K: Eq + Hash>(
    bucket: &mut HashMap<String, HashSet<K>>,
    session_id: &str,
    keys: Vec<K>,
) {
    if !keys.is_empty() {
        bucket.insert(session_id.to_owned(), keys.into_iter().collect());
    }
}

impl PolicyStore {
    /// Write the handoff for the next daemon to the path [`Self::restore`]
    /// was configured with.
    ///
    /// Returns the decision state lock still held: no request may change the
    /// state after the snapshot, so the caller exits without releasing it.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when restart state is not configured or the file
    /// cannot be written.
    pub async fn write_handoff(&self) -> io::Result<MutexGuard<'_, PolicyDecisionState>> {
        let path = self.handoff_path()?;
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

        let handoff =
            serde_json::to_vec(&Handoff { proxy, ui_sessions }).map_err(io::Error::other)?;

        write_atomic(&path, &handoff)?;
        Ok(inner)
    }

    // The file is trusted because it lives in a root-owned directory and is
    // written only by root; sandboxes cannot modify it.
    pub(super) fn restore_handoff_from(&mut self, path: &Path) {
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
                .handed_over_ui_sessions
                .insert(session.id, HandedOverUiSession {
                    handed_over_at: Instant::now(),
                    context: UiSessionContext {
                        cwd: session.cwd,
                        home: session.home,
                        project_root: session.project_root,
                        sandbox_session_id: session.sandbox_session_id,
                        owner_uid: session.owner_uid,
                        client_id: 0,
                    },
                });
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

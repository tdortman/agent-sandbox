//! Policy store: ui.

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use agent_sandbox_core::{SessionContext, UiPush};
use tokio::io::AsyncWriteExt;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::time;
use uuid::Uuid;

use crate::spawn::maybe_spawn_ui;
use crate::wire::{UiSpawnContext, UiSpawnGate};

use super::types::{
    CLIENT_ID, Pending, PolicyStore, UiClient, UiClientHandle, UiSessionContext, UiSessionOwner,
};
use super::ui_route::{
    UiRoute, omp_ui_client_owns_by_pid, request_owned_by_omp, standalone_ui_client_matches,
    ui_client_matches_with_contexts,
};

impl PolicyStore {
    pub async fn has_omp_ui(&self) -> bool {
        self.inner
            .lock()
            .await
            .ui_clients
            .values()
            .any(|c| c.ui_client == "omp")
    }

    /// Whether an OMP UI is already registered for a given sandbox session.
    }

    fn omp_clients(inner: &super::types::StoreInner) -> Vec<&UiClient> {
        inner
            .ui_clients
            .values()
            .filter(|c| c.ui_client == "omp")
            .collect()
    }

    pub(crate) async fn route_owned_by_omp_ui(&self, route: &UiRoute) -> bool {
        let inner = self.inner.lock().await;
        request_owned_by_omp(
            route,
            &Self::omp_clients(&inner),
            &inner.ui_context_by_session,
        )
    }

    fn matching_ui_session_ids(
        inner: &super::types::StoreInner,
        route: &UiRoute,
    ) -> HashSet<String> {
        let omp_clients = Self::omp_clients(inner);
        inner
            .ui_clients
            .values()
            .filter(|client| {
                inner
                    .ui_context_by_session
                    .get(&client.session_id)
                    .is_some_and(|ctx| {
                        ui_client_matches_with_contexts(
                            client,
                            ctx,
                            route,
                            &omp_clients,
                            &inner.ui_context_by_session,
                        )
                    })
            })
            .map(|c| c.session_id.clone())
            .collect()
    }

    fn matching_standalone_ui_session_ids(
        inner: &super::types::StoreInner,
        route: &UiRoute,
    ) -> HashSet<String> {
        inner
            .ui_clients
            .values()
            .filter(|client| {
                client.ui_client != "omp"
                    && inner
                        .ui_context_by_session
                        .get(&client.session_id)
                        .is_some_and(|ctx| standalone_ui_client_matches(client, ctx, route))
            })
            .map(|c| c.session_id.clone())
            .collect()
    }

    fn matching_filesystem_session_ids(
        inner: &super::types::StoreInner,
        route: &UiRoute,
    ) -> HashSet<String> {
        let omp_pid_sessions: HashSet<String> = inner
            .ui_clients
            .values()
            .filter(|client| omp_ui_client_owns_by_pid(client, route))
            .map(|client| client.session_id.clone())
            .collect();
        if !omp_pid_sessions.is_empty() {
            return omp_pid_sessions;
        }
        Self::matching_standalone_ui_session_ids(inner, route)
    }

    pub(crate) async fn session_ids_for_route(&self, route: &UiRoute) -> HashSet<String> {
        let inner = self.inner.lock().await;
        Self::matching_ui_session_ids(&inner, route)
    }

    pub(crate) async fn filesystem_session_ids_for_route(
        &self,
        route: &UiRoute,
    ) -> HashSet<String> {
        let inner = self.inner.lock().await;
        Self::matching_filesystem_session_ids(&inner, route)
    }
    pub(crate) async fn has_ui_for_route(&self, route: &UiRoute) -> bool {
        !self.session_ids_for_route(route).await.is_empty()
    }

    pub(crate) async fn has_standalone_ui_for_route(&self, route: &UiRoute) -> bool {
        let inner = self.inner.lock().await;
        !Self::matching_standalone_ui_session_ids(&inner, route).is_empty()
    }

    async fn ui_notification_targets_for(
        &self,
        route: &UiRoute,
    ) -> Vec<std::sync::Arc<Mutex<OwnedWriteHalf>>> {
        let inner = self.inner.lock().await;
        let session_ids = Self::matching_ui_session_ids(&inner, route);
        inner
            .ui_clients
            .values()
            .filter(|c| session_ids.contains(&c.session_id))
            .map(|c| c.writer.clone())
            .collect()
    }

    async fn standalone_ui_notification_targets_for(
        &self,
        route: &UiRoute,
    ) -> Vec<std::sync::Arc<Mutex<OwnedWriteHalf>>> {
        let inner = self.inner.lock().await;
        let session_ids = Self::matching_standalone_ui_session_ids(&inner, route);
        inner
            .ui_clients
            .values()
            .filter(|c| session_ids.contains(&c.session_id))
            .map(|c| c.writer.clone())
            .collect()
    }

    pub(crate) async fn start_ui_session(
        &self,
        handle: &UiClientHandle,
        ui_client: &str,
        owner: Option<UiSessionOwner>,
        context: UiSessionContext,
    ) -> String {
        let session_id = Uuid::new_v4().simple().to_string();
        let mut inner = self.inner.lock().await;
        inner.ui_clients.insert(
            handle.id,
            UiClient {
                session_id: session_id.clone(),
                ui_client: ui_client.to_string(),
                writer: handle.writer.clone(),
                owner_uid: owner.map_or(0, |o| o.uid),
                owner_pid: owner.map_or(0, |o| o.pid),
            },
        );
        inner
            .ui_context_by_session
            .insert(session_id.clone(), context);
        session_id
    }

    pub async fn end_ui_session(&self, client_id: u64) {
        self.end_ui_session_by_id(client_id).await;
    }

    async fn end_ui_session_by_id(&self, client_id: u64) {
        self.remove_ui_client(client_id, true).await;
    }

    async fn remove_ui_client(&self, client_id: u64, reroute_pending: bool) {
        let removed = {
            let mut inner = self.inner.lock().await;
            inner.ui_clients.remove(&client_id).map(|client| {
                inner.session_allow.remove(&client.session_id);
                inner.session_deny.remove(&client.session_id);
                inner.session_sudo_allow.remove(&client.session_id);
                inner.session_sudo_deny.remove(&client.session_id);
                inner.session_filesystem_allow.remove(&client.session_id);
                inner.session_filesystem_deny.remove(&client.session_id);
                inner.ui_context_by_session.remove(&client.session_id);
            })
        };
        if removed.is_some() && reroute_pending {
            self.reroute_orphaned_pending().await;
        }
    }

    /// Re-notify pending requests that lost their UI, and spawn standalone UI when needed.
    pub(crate) async fn reroute_orphaned_pending(&self) {
        let pending: Vec<Pending> = self.inner.lock().await.pending.values().cloned().collect();
        for p in pending {
            let route = UiRoute::new(
                p.request_pid(),
                p.cwd().map(str::to_owned),
                p.home().map(str::to_owned),
                p.project_root().map(str::to_owned),
            )
            .with_sandbox_session(p.sandbox_session_id().map(str::to_owned));
            let has_ui = match p {
                Pending::Filesystem(_) => self.has_standalone_ui_for_route(&route).await,
                _ => self.has_ui_for_route(&route).await,
            };
            let route_owned_by_omp =
                !matches!(p, Pending::Filesystem(_)) && self.route_owned_by_omp_ui(&route).await;
            if !has_ui && !route_owned_by_omp {
                let spawn_uid = nix::unistd::User::from_name(&Self::user_for_home(p.home()))
                    .ok()
                    .flatten()
                    .map(|u| u.uid.as_raw());
                let spawn = UiSpawnContext {
                    gate: UiSpawnGate {
                        has_matching_ui: false,
                    },
                    uid: spawn_uid,
                    home: p.home(),
                    cwd: p.cwd(),
                    project_root: p.project_root(),
                    sandbox_session_id: p.sandbox_session_id(),
                };
                maybe_spawn_ui(
                    &self.args,
                    &mut self.inner.lock().await.ui_spawn_last,
                    &spawn,
                );
            }
            self.notify_pending(&p).await;
        }
    }

    async fn notify_pending(&self, p: &Pending) {
        let route = UiRoute::new(
            p.request_pid(),
            p.cwd().map(str::to_owned),
            p.home().map(str::to_owned),
            p.project_root().map(str::to_owned),
        )
        .with_sandbox_session(p.sandbox_session_id().map(str::to_owned));
        match p {
            Pending::Network(net) => {
                self.notify_network_ui(
                    &route,
                    &UiPush::NetworkRequest {
                        id: net.id.clone(),
                        host: Some(net.host.clone()),
                        port: Some(net.port),
                        scheme: Some(net.scheme.clone()),
                        url: Some(net.url.clone()),
                        cwd: net.cwd.clone(),
                        home: net.home.clone(),
                        project_root: net.project_root.clone(),
                    },
                )
                .await;
            }
            Pending::Elevation(elev) => {
                self.notify_ui(
                    &route,
                    &UiPush::ElevationRequest {
                        id: elev.id.clone(),
                        argv: Some(elev.argv.clone()),
                        cwd: elev.cwd.clone(),
                        home: elev.home.clone(),
                        project_root: elev.project_root.clone(),
                    },
                )
                .await;
            }
            Pending::Filesystem(fs) => {
                self.notify_standalone_ui(
                    &route,
                    &UiPush::FilesystemRequest {
                        id: fs.id.clone(),
                        path: fs.path.clone(),
                        access: fs.access,
                        cwd: fs.cwd.clone(),
                        home: fs.home.clone(),
                        project_root: fs.project_root.clone(),
                    },
                )
                .await;
            }
        }
    }

    pub fn new_client_handle(writer: std::sync::Arc<Mutex<OwnedWriteHalf>>) -> UiClientHandle {
        UiClientHandle {
            id: CLIENT_ID.fetch_add(1, Ordering::Relaxed),
            writer,
        }
    }

    pub async fn ui_context_for_session(&self, session_id: &str) -> Option<SessionContext> {
        self.inner
            .lock()
            .await
            .ui_context_by_session
            .get(session_id)
            .map(|ctx| SessionContext {
                cwd: ctx.cwd.clone(),
                home: ctx.home.clone(),
                project_root: ctx.project_root.clone(),
            })
    }

    pub(crate) async fn wait_for_matching_ui_client(
        &self,
        route: &UiRoute,
        timeout: Duration,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.has_ui_for_route(route).await {
                return true;
            }
            time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    pub(crate) async fn wait_for_omp_ui_client(&self, route: &UiRoute, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.route_owned_by_omp_ui(route).await {
                return true;
            }
            time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    pub(crate) async fn wait_for_standalone_ui_client(
        &self,
        route: &UiRoute,
        timeout: Duration,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.has_standalone_ui_for_route(route).await {
                return true;
            }
            time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    pub(crate) async fn notify_ui(&self, route: &UiRoute, payload: &UiPush) {
        let targets = self.ui_notification_targets_for(route).await;
        if targets.is_empty() {
            return;
        }
        let line = agent_sandbox_core::RpcMessage::UiPush(payload.clone()).to_string();
        let mut dead = Vec::new();
        for (id, writer) in self
            .inner
            .lock()
            .await
            .ui_clients
            .iter()
            .map(|(id, c)| (*id, c.writer.clone()))
        {
            if !targets.iter().any(|t| std::sync::Arc::ptr_eq(t, &writer)) {
                continue;
            }
            let mut w = writer.lock().await;
            if w.write_all(line.as_bytes()).await.is_err() {
                dead.push(id);
            }
        }
        if !dead.is_empty() {
            let mut inner = self.inner.lock().await;
            for id in dead {
                if let Some(client) = inner.ui_clients.remove(&id) {
                    inner.session_allow.remove(&client.session_id);
                    inner.session_deny.remove(&client.session_id);
                    inner.session_sudo_allow.remove(&client.session_id);
                    inner.session_sudo_deny.remove(&client.session_id);
                    inner.session_filesystem_allow.remove(&client.session_id);
                    inner.session_filesystem_deny.remove(&client.session_id);
                    inner.ui_context_by_session.remove(&client.session_id);
                }
            }
        }
    }

    /// Send a network prompt to OMP if registered, otherwise to standalone UI only.
    /// Never falls back to generic `notify_ui`. Tracks standalone-delivered ids so
    /// late OMP registration cannot produce a duplicate prompt.
    pub(crate) async fn notify_network_ui(&self, route: &UiRoute, payload: &UiPush) {
        let net_id = match payload {
            UiPush::NetworkRequest { id, .. } => Some(id.as_str()),
            _ => None,
        };

        // OMP-first: if OMP owns the route, deliver there
        if self.route_owned_by_omp_ui(route).await {
            // But skip if this pending was already delivered to standalone (late OMP registration)
            if let Some(id) = net_id
                && self
                    .inner
                    .lock()
                    .await
                    .network_pending_delivered_to_standalone
                    .contains(id)
            {
                return;
            }
            let targets = self.omp_ui_notification_targets_for(route).await;
            if !targets.is_empty() {
                self.send_to_targets(payload, &targets).await;
                return;
            }
        }

        // Fallback: standalone-only, never `notify_ui`
        let targets = self.standalone_ui_notification_targets_for(route).await;
        if !targets.is_empty() {
            if let Some(id) = net_id {
                self.inner
                    .lock()
                    .await
                    .network_pending_delivered_to_standalone
                    .insert(id.to_string());
            }
            self.send_to_targets(payload, &targets).await;
        }
    }

    async fn omp_ui_notification_targets_for(
        &self,
        route: &UiRoute,
    ) -> Vec<std::sync::Arc<Mutex<OwnedWriteHalf>>> {
        let inner = self.inner.lock().await;
        let omp_clients = Self::omp_clients(&inner);
        let matching_omps: HashSet<String> = inner
            .ui_clients
            .values()
            .filter(|client| {
                client.ui_client == "omp"
                    && inner
                        .ui_context_by_session
                        .get(&client.session_id)
                        .is_some_and(|ctx| {
                            ui_client_matches_with_contexts(
                                client,
                                ctx,
                                route,
                                &omp_clients,
                                &inner.ui_context_by_session,
                            )
                        })
            })
            .map(|c| c.session_id.clone())
            .collect();
        inner
            .ui_clients
            .values()
            .filter(|c| matching_omps.contains(&c.session_id))
            .map(|c| c.writer.clone())
            .collect()
    }

    async fn send_to_targets(
        &self,
        payload: &UiPush,
        targets: &[std::sync::Arc<Mutex<OwnedWriteHalf>>],
    ) {
        let line = agent_sandbox_core::RpcMessage::UiPush(payload.clone()).to_string();
        let mut dead = Vec::new();
        for (id, writer) in self
            .inner
            .lock()
            .await
            .ui_clients
            .iter()
            .map(|(id, c)| (*id, c.writer.clone()))
        {
            if !targets.iter().any(|t| std::sync::Arc::ptr_eq(t, &writer)) {
                continue;
            }
            let mut w = writer.lock().await;
            if w.write_all(line.as_bytes()).await.is_err() {
                dead.push(id);
            }
        }
        if !dead.is_empty() {
            let mut inner = self.inner.lock().await;
            for id in dead {
                if let Some(client) = inner.ui_clients.remove(&id) {
                    inner.session_allow.remove(&client.session_id);
                    inner.session_deny.remove(&client.session_id);
                    inner.session_sudo_allow.remove(&client.session_id);
                    inner.session_sudo_deny.remove(&client.session_id);
                    inner.session_filesystem_allow.remove(&client.session_id);
                    inner.session_filesystem_deny.remove(&client.session_id);
                    inner.ui_context_by_session.remove(&client.session_id);
                }
            }
        }
    }

    pub(crate) async fn notify_standalone_ui(&self, route: &UiRoute, payload: &UiPush) {
        let targets = self.standalone_ui_notification_targets_for(route).await;
        if targets.is_empty() {
            return;
        }
        let line = agent_sandbox_core::RpcMessage::UiPush(payload.clone()).to_string();
        let mut dead = Vec::new();
        for (id, writer) in self
            .inner
            .lock()
            .await
            .ui_clients
            .iter()
            .map(|(id, c)| (*id, c.writer.clone()))
        {
            if !targets.iter().any(|t| std::sync::Arc::ptr_eq(t, &writer)) {
                continue;
            }
            let mut w = writer.lock().await;
            if w.write_all(line.as_bytes()).await.is_err() {
                dead.push(id);
            }
        }
        if !dead.is_empty() {
            let mut inner = self.inner.lock().await;
            for id in dead {
                if let Some(client) = inner.ui_clients.remove(&id) {
                    inner.session_allow.remove(&client.session_id);
                    inner.session_deny.remove(&client.session_id);
                    inner.session_sudo_allow.remove(&client.session_id);
                    inner.session_sudo_deny.remove(&client.session_id);
                    inner.session_filesystem_allow.remove(&client.session_id);
                    inner.session_filesystem_deny.remove(&client.session_id);
                    inner.ui_context_by_session.remove(&client.session_id);
                }
            }
        }
    }

    pub async fn flush_pending_to_ui(&self) {
        let pending: Vec<Pending> = self.inner.lock().await.pending.values().cloned().collect();
        for p in pending {
            self.notify_pending(&p).await;
        }
    }
}

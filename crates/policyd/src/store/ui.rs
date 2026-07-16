//! Policy store: ui.
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use agent_sandbox_core::{ResolvedRequestContext, SessionContext, UiPush, attach_ui_aliases};
use tokio::io::AsyncWriteExt;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::wire::{UiSpawnContext, UiSpawnGate};

use super::types::{
    CLIENT_ID, Pending, PendingFilesystem, PendingResource, PolicyStore, UiClient, UiClientHandle,
    UiSessionContext,
};
use super::ui_route::{UiRoute, paths_match};

#[derive(Clone, Copy)]
enum UiRoutingKind {
    General,
    Standalone,
}
const UI_SPAWN_WAIT: Duration = Duration::from_secs(3);
const UI_SPAWN_POLL: Duration = Duration::from_millis(25);
type UiNotificationTarget = (u64, std::sync::Arc<Mutex<OwnedWriteHalf>>);

impl UiRoutingKind {
    const fn for_pending(pending: &Pending) -> Self {
        match pending {
            Pending::Filesystem(_) | Pending::Resource(_) => Self::Standalone,
            Pending::Elevation(_) | Pending::Network(_) | Pending::Http(_) | Pending::Dbus(_) => {
                Self::General
            }
        }
    }
}

impl PolicyStore {
    fn route_for_context(ctx: &ResolvedRequestContext) -> UiRoute {
        let cwd = ctx.paths.cwd_path();
        let project_root = ctx.paths.project_root_path();
        UiRoute::from_parts(
            cwd.as_deref(),
            project_root.as_deref(),
            ctx.sandbox_session_id.as_deref(),
        )
    }

    fn route_for_pending_fields(
        cwd: Option<&Path>,
        project_root: Option<&Path>,
        sandbox_session_id: Option<&str>,
    ) -> UiRoute {
        UiRoute::from_parts(cwd, project_root, sandbox_session_id)
    }

    fn route_for_pending(pending: &Pending) -> UiRoute {
        Self::route_for_pending_fields(
            pending.cwd(),
            pending.project_root(),
            pending.sandbox_session_id(),
        )
    }

    fn matching_ui_session_ids(
        inner: &super::types::StoreInner,
        route: &UiRoute,
        _kind: UiRoutingKind,
    ) -> HashSet<String> {
        inner
            .ui_clients
            .values()
            .filter(|client| {
                inner
                    .ui_context_by_session
                    .get(&client.session_id)
                    .is_some_and(|ctx| paths_match(ctx, route))
            })
            .map(|c| c.session_id.clone())
            .collect()
    }
    async fn session_ids_for_route(&self, route: &UiRoute, kind: UiRoutingKind) -> HashSet<String> {
        let inner = self.inner.lock().await;
        Self::matching_ui_session_ids(&inner, route, kind)
    }

    pub(crate) async fn session_ids_for_context(
        &self,
        ctx: &ResolvedRequestContext,
    ) -> HashSet<String> {
        let route = Self::route_for_context(ctx);
        self.session_ids_for_route(&route, UiRoutingKind::General)
            .await
    }

    pub(crate) async fn standalone_session_ids_for_context(
        &self,
        ctx: &ResolvedRequestContext,
    ) -> HashSet<String> {
        let route = Self::route_for_context(ctx);
        self.session_ids_for_route(&route, UiRoutingKind::Standalone)
            .await
    }

    pub(crate) async fn standalone_session_ids_for_filesystem_pending(
        &self,
        pending: &PendingFilesystem,
    ) -> HashSet<String> {
        let route = Self::route_for_pending_fields(
            pending.cwd.as_deref(),
            pending.project_root.as_deref(),
            pending.sandbox_session_id.as_deref(),
        );
        self.session_ids_for_route(&route, UiRoutingKind::Standalone)
            .await
    }

    pub(crate) async fn standalone_session_ids_for_resource_pending(
        &self,
        pending: &PendingResource,
    ) -> HashSet<String> {
        let route = Self::route_for_pending_fields(
            pending.cwd.as_deref(),
            pending.project_root.as_deref(),
            pending.sandbox_session_id.as_deref(),
        );
        self.session_ids_for_route(&route, UiRoutingKind::Standalone)
            .await
    }

    async fn has_ui_for_route(&self, route: &UiRoute, kind: UiRoutingKind) -> bool {
        !self.session_ids_for_route(route, kind).await.is_empty()
    }

    pub(crate) async fn has_ui_for_context(&self, ctx: &ResolvedRequestContext) -> bool {
        let route = Self::route_for_context(ctx);
        self.has_ui_for_route(&route, UiRoutingKind::General).await
    }

    pub(crate) async fn has_standalone_ui_for_context(&self, ctx: &ResolvedRequestContext) -> bool {
        let route = Self::route_for_context(ctx);
        self.has_ui_for_route(&route, UiRoutingKind::Standalone)
            .await
    }

    pub(crate) async fn has_ui_for_pending(&self, pending: &Pending) -> bool {
        let route = Self::route_for_pending(pending);
        self.has_ui_for_route(&route, UiRoutingKind::for_pending(pending))
            .await
    }

    async fn ui_notification_targets_for(
        &self,
        route: &UiRoute,
        kind: UiRoutingKind,
    ) -> Vec<UiNotificationTarget> {
        let inner = self.inner.lock().await;
        let session_ids = Self::matching_ui_session_ids(&inner, route, kind);
        let mut targets: Vec<_> = inner
            .ui_clients
            .iter()
            .filter(|(_, c)| session_ids.contains(&c.session_id))
            .map(|(id, c)| (*id, c.writer.clone()))
            .collect();
        targets.sort_unstable_by_key(|(id, _)| *id);
        drop(inner);
        targets
    }

    pub(crate) async fn start_ui_session(
        &self,
        handle: &UiClientHandle,
        peer: crate::server::ClientPeer,
        context: UiSessionContext,
    ) -> String {
        let session_id = Uuid::now_v7().simple().to_string();
        let mut inner = self.inner.lock().await;
        let mut ctx = context;
        ctx.client_id = handle.id;
        if ctx.owner_uid.is_none() && peer.uid > 0 {
            ctx.owner_uid = Some(peer.uid);
        }
        inner.ui_clients.insert(
            handle.id,
            UiClient {
                session_id: session_id.clone(),
                writer: handle.writer.clone(),
            },
        );
        inner.ui_context_by_session.insert(session_id.clone(), ctx);
        session_id
    }

    pub async fn end_ui_session(&self, client_id: u64) {
        self.end_ui_session_by_id(client_id).await;
    }

    pub async fn try_acquire_connection(&self, peer: crate::server::ClientPeer) -> bool {
        if peer.uid == 0 {
            return true;
        }
        let mut inner = self.inner.lock().await;
        let count = inner.connections_by_uid.entry(peer.uid).or_insert(0);
        if *count >= super::types::MAX_CONNECTIONS_PER_UID {
            return false;
        }
        *count += 1;
        drop(inner);
        true
    }

    pub async fn release_connection(&self, peer: crate::server::ClientPeer) {
        if peer.uid == 0 {
            return;
        }
        let mut inner = self.inner.lock().await;
        if let Some(count) = inner.connections_by_uid.get_mut(&peer.uid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.connections_by_uid.remove(&peer.uid);
            }
        }
    }

    async fn end_ui_session_by_id(&self, client_id: u64) {
        self.remove_ui_client(client_id, true).await;
    }

    fn remove_ui_client_locked(inner: &mut super::types::StoreInner, client_id: u64) -> bool {
        inner.ui_clients.remove(&client_id).is_some_and(|client| {
            inner.session_allow.remove(&client.session_id);
            inner.session_deny.remove(&client.session_id);
            inner.session_sudo_allow.remove(&client.session_id);
            inner.session_sudo_deny.remove(&client.session_id);
            inner.session_filesystem_allow.remove(&client.session_id);
            inner.session_dbus_allow.remove(&client.session_id);
            inner.session_dbus_deny.remove(&client.session_id);
            inner.session_filesystem_deny.remove(&client.session_id);
            inner.ui_context_by_session.remove(&client.session_id);
            true
        })
    }

    async fn remove_ui_client(&self, client_id: u64, reroute_pending: bool) {
        let removed = {
            let mut inner = self.inner.lock().await;
            Self::remove_ui_client_locked(&mut inner, client_id)
        };
        if removed && reroute_pending {
            self.reroute_orphaned_pending().await;
        }
    }

    /// Re-notify pending requests that lost their UI, and spawn a UI when needed.
    pub(crate) async fn reroute_orphaned_pending(&self) {
        let pending: Vec<Pending> = self.inner.lock().await.pending.values().cloned().collect();
        let deadline = tokio::time::Instant::now() + UI_SPAWN_WAIT;
        let mut registration_flush_observed = false;
        for p in pending {
            if registration_flush_observed && self.has_ui_for_pending(&p).await {
                continue;
            }
            if !self.has_ui_for_pending(&p).await {
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
                self.spawn_policy_ui(spawn).await;
                if self.args.ui_spawn_cmd.is_some()
                    && self.wait_for_ui_for_pending(&p, deadline).await
                {
                    registration_flush_observed = true;
                    continue;
                }
            }
            self.notify_pending_once(&p).await;
        }
    }

    async fn wait_for_ui_for_pending(
        &self,
        pending: &Pending,
        deadline: tokio::time::Instant,
    ) -> bool {
        loop {
            if self.has_ui_for_pending(pending).await {
                return true;
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return false;
            }
            tokio::time::sleep(UI_SPAWN_POLL.min(deadline - now)).await;
        }
    }

    async fn notify_pending(&self, pending: &Pending) {
        let delivered = self.notify_pending_once(pending).await;
        if !delivered {
            self.reroute_orphaned_pending().await;
        }
    }

    async fn notify_pending_once(&self, pending: &Pending) -> bool {
        let push = match pending {
            Pending::Network(net) => UiPush::NetworkRequest {
                id: net.id.clone(),
                host: Some(net.host.clone()),
                port: Some(net.port),
                scheme: Some(net.scheme.clone()),
                url: attach_ui_aliases(Some(net.url.clone()), &net.aliases),
                cwd: net.cwd.clone(),
                home: net.home.clone(),
                project_root: net.project_root.clone(),
            },
            Pending::Http(http) => UiPush::HttpRequest {
                id: http.pending_id,
                request: http.request.clone(),
                cwd: http.context.cwd.clone(),
                home: http.context.home.clone(),
                project_root: http.context.project_root.clone(),
                sandbox_session_id: http.context.sandbox_session_id.clone(),
            },
            Pending::Elevation(elev) => UiPush::ElevationRequest {
                id: elev.id.clone(),
                argv: Some(elev.argv.clone()),
                cwd: elev.cwd.clone(),
                home: elev.home.clone(),
                project_root: elev.project_root.clone(),
            },
            Pending::Filesystem(fs) => UiPush::FilesystemRequest {
                id: fs.id.clone(),
                path: fs.path.clone(),
                access: fs.access,
                cwd: fs.cwd.clone(),
                home: fs.home.clone(),
                project_root: fs.project_root.clone(),
            },
            Pending::Resource(res) => UiPush::ResourceRequest {
                id: res.id.clone(),
                kind: res.kind,
                path: res.path.clone(),
                access: res.access,
                cwd: res.cwd.clone(),
                home: res.home.clone(),
                project_root: res.project_root.clone(),
            },
            Pending::Dbus(res) => UiPush::DbusRequest {
                id: res.id.clone(),
                target: res.target.clone(),
                cwd: res.cwd.clone(),
                home: res.home.clone(),
                project_root: res.project_root.clone(),
                sandbox_session_id: res.sandbox_session_id.clone(),
            },
        };
        let route = Self::route_for_pending(pending);
        self.notify_ui(&route, &push, UiRoutingKind::for_pending(pending))
            .await
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

    async fn notify_ui(&self, route: &UiRoute, payload: &UiPush, kind: UiRoutingKind) -> bool {
        let targets = self.ui_notification_targets_for(route, kind).await;
        if targets.is_empty() {
            tracing::warn!(
                kind = ?payload,
                "policy push dropped: no matching policy UI for route"
            );
            return false;
        }
        self.send_to_targets(payload, &targets).await
    }

    pub(crate) async fn notify_general_ui(&self, ctx: &ResolvedRequestContext, payload: &UiPush) {
        let route = Self::route_for_context(ctx);
        if !self
            .notify_ui(&route, payload, UiRoutingKind::General)
            .await
        {
            self.reroute_orphaned_pending().await;
        }
    }

    /// Filesystem delivery: targets standalone-matching UI clients (which is
    /// every UI client under the unified registration model).
    pub(crate) async fn notify_standalone_ui(
        &self,
        ctx: &ResolvedRequestContext,
        payload: &UiPush,
    ) {
        let route = Self::route_for_context(ctx);
        if !self
            .notify_ui(&route, payload, UiRoutingKind::Standalone)
            .await
        {
            self.reroute_orphaned_pending().await;
        }
    }

    async fn send_to_targets(&self, payload: &UiPush, targets: &[UiNotificationTarget]) -> bool {
        let line = agent_sandbox_core::RpcMessage::UiPush(payload.clone()).to_string();
        for (id, writer) in targets {
            let mut w = writer.lock().await;
            if w.write_all(line.as_bytes()).await.is_ok() {
                return true;
            }
            drop(w);
            let mut inner = self.inner.lock().await;
            Self::remove_ui_client_locked(&mut inner, *id);
        }
        false
    }

    pub async fn flush_pending_to_ui(&self) {
        let pending: Vec<Pending> = self.inner.lock().await.pending.values().cloned().collect();
        for p in pending {
            self.notify_pending(&p).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use agent_sandbox_core::FileAccess;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;
    use tokio::sync::{Mutex, oneshot};

    use super::PolicyStore;
    use crate::store::types::UiClient;
    use crate::store::{Pending, PendingFilesystem, PendingNetwork, PolicydArgs, UiSessionContext};

    fn test_store() -> PolicyStore {
        PolicyStore::new(PolicydArgs {
            host_socket: "/tmp/test.sock".into(),
            sandbox_socket: "/tmp/test-sandbox.sock".into(),
            declarative: "/tmp/declarative.json".into(),
            export_json: "/tmp/export.json".into(),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
            proxy_socket: None,
            proxy_gid: None,
        })
    }

    async fn register_ui(
        store: &PolicyStore,
        client_id: u64,
        session_id: &str,
        sandbox_session_id: &str,
    ) -> tokio::net::unix::OwnedReadHalf {
        let (a, b) = UnixStream::pair().expect("unix stream pair");
        let (_, write) = a.into_split();
        let (read, _) = b.into_split();
        let mut inner = store.inner.lock().await;
        inner.ui_clients.insert(
            client_id,
            UiClient {
                session_id: session_id.into(),
                writer: Arc::new(Mutex::new(write)),
            },
        );
        inner.ui_context_by_session.insert(
            session_id.into(),
            UiSessionContext {
                cwd: Some("/repo".into()),
                home: Some("/home/user".into()),
                project_root: Some("/repo".into()),
                sandbox_session_id: Some(sandbox_session_id.into()),
                client_id,
                ..Default::default()
            },
        );
        read
    }

    fn pending_network(id: &str) -> Pending {
        Pending::Network(PendingNetwork {
            id: id.into(),
            created_at: 0.0,
            host: "example.com".into(),
            port: 443,
            scheme: "tcp".into(),
            url: "tcp://example.com:443".into(),
            aliases: Vec::new(),
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            sandbox_session_id: Some("sandbox-a".into()),
        })
    }

    fn pending_filesystem(id: &str) -> Pending {
        Pending::Filesystem(PendingFilesystem {
            id: id.into(),
            created_at: 0.0,
            path: "/repo/file.txt".into(),
            access: FileAccess::Read,
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            sandbox_session_id: Some("sandbox-a".into()),
        })
    }

    #[tokio::test]
    async fn reroute_waits_for_spawned_ui_registration_before_notifying() {
        let mut store = test_store();
        store.args.ui_spawn_cmd = Some("/bin/true".into());
        let store = Arc::new(store);
        let pending = pending_network("net:spawn-race");
        let pending_second = pending_network("net:spawn-race-second");
        let mut inner = store.inner.lock().await;
        inner.pending.insert("net:spawn-race".into(), pending);
        inner
            .pending
            .insert("net:spawn-race-second".into(), pending_second);
        drop(inner);

        let (read_tx, read_rx) = oneshot::channel();
        let registration_store = Arc::clone(&store);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let read = register_ui(&registration_store, 1, "ui-spawned", "sandbox-a").await;
            registration_store.flush_pending_to_ui().await;
            read_tx
                .send(read)
                .expect("test receiver should remain connected");
        });

        store.reroute_orphaned_pending().await;

        let mut read = tokio::time::timeout(Duration::from_secs(1), read_rx)
            .await
            .expect("spawned UI registration should complete")
            .expect("registration task should send its reader");
        let mut received = String::new();
        for _ in 0..2 {
            let mut buf = [0_u8; 1024];
            let n = tokio::time::timeout(Duration::from_secs(1), read.read(&mut buf))
                .await
                .expect("matching UI should receive the pending prompt")
                .expect("read should succeed");
            received.push_str(&String::from_utf8_lossy(&buf[..n]));
            if received.contains("net:spawn-race") && received.contains("net:spawn-race-second") {
                break;
            }
        }
        assert_eq!(
            received.matches("\"id\":\"net:spawn-race\"").count(),
            1,
            "first pending prompt should be delivered exactly once: {received}",
        );
        assert_eq!(
            received.matches("\"id\":\"net:spawn-race-second\"").count(),
            1,
            "second pending prompt should be delivered exactly once: {received}",
        );
        let mut duplicate_buf = [0_u8; 1024];
        let duplicate =
            tokio::time::timeout(Duration::from_millis(150), read.read(&mut duplicate_buf)).await;
        assert!(
            duplicate.is_err(),
            "registration flush and reroute must not duplicate prompts",
        );
    }

    #[tokio::test]
    async fn end_ui_session_reroutes_general_pending_to_matching_sandbox_ui() {
        let store = test_store();
        let _dead_read = register_ui(&store, 1, "ui-dead", "sandbox-a").await;
        let mut foreign_read = register_ui(&store, 2, "ui-foreign", "sandbox-b").await;
        let mut live_read = register_ui(&store, 3, "ui-live", "sandbox-a").await;
        store
            .inner
            .lock()
            .await
            .pending
            .insert("net:reroute".into(), pending_network("net:reroute"));

        store.end_ui_session(1).await;

        let mut live_buf = [0u8; 1024];
        let live_n = tokio::time::timeout(Duration::from_secs(1), live_read.read(&mut live_buf))
            .await
            .expect("matching sandbox UI should receive rerouted network prompt")
            .expect("read should succeed");
        let live_msg = String::from_utf8_lossy(&live_buf[..live_n]);
        assert!(
            live_msg.contains("net:reroute"),
            "expected rerouted network prompt, got: {live_msg}"
        );

        let mut foreign_buf = [0u8; 256];
        let foreign = tokio::time::timeout(
            Duration::from_millis(150),
            foreign_read.read(&mut foreign_buf),
        )
        .await;
        assert!(
            foreign.is_err(),
            "foreign sandbox UI must not receive rerouted general prompt"
        );
    }

    #[tokio::test]
    async fn end_ui_session_reroutes_standalone_pending_to_matching_sandbox_ui() {
        let store = test_store();
        let _dead_read = register_ui(&store, 1, "ui-dead", "sandbox-a").await;
        let mut foreign_read = register_ui(&store, 2, "ui-foreign", "sandbox-b").await;
        let mut live_read = register_ui(&store, 3, "ui-live", "sandbox-a").await;
        store
            .inner
            .lock()
            .await
            .pending
            .insert("fs:reroute".into(), pending_filesystem("fs:reroute"));

        store.end_ui_session(1).await;

        let mut live_buf = [0u8; 1024];
        let live_n = tokio::time::timeout(Duration::from_secs(1), live_read.read(&mut live_buf))
            .await
            .expect("matching sandbox UI should receive rerouted filesystem prompt")
            .expect("read should succeed");
        let live_msg = String::from_utf8_lossy(&live_buf[..live_n]);
        assert!(
            live_msg.contains("fs:reroute"),
            "expected rerouted filesystem prompt, got: {live_msg}"
        );

        let mut foreign_buf = [0u8; 256];
        let foreign = tokio::time::timeout(
            Duration::from_millis(150),
            foreign_read.read(&mut foreign_buf),
        )
        .await;
        assert!(
            foreign.is_err(),
            "foreign sandbox UI must not receive rerouted standalone prompt"
        );
    }
    #[tokio::test]
    async fn notify_pending_arbitrates_matching_ui_clients_deterministically() {
        let store = test_store();
        let mut higher_id_read = register_ui(&store, 20, "ui-higher", "sandbox-a").await;
        let mut lower_id_read = register_ui(&store, 10, "ui-lower", "sandbox-a").await;
        let pending = pending_network("net:arbitrate");

        store.notify_pending(&pending).await;

        let mut lower_buf = [0u8; 1024];
        let lower_n =
            tokio::time::timeout(Duration::from_secs(1), lower_id_read.read(&mut lower_buf))
                .await
                .expect("one matching UI should receive the network prompt")
                .expect("lower-id UI read should succeed");
        let lower_msg = String::from_utf8_lossy(&lower_buf[..lower_n]);
        assert!(lower_msg.contains("net:arbitrate"));

        let mut higher_buf = [0u8; 1024];
        let higher = tokio::time::timeout(
            Duration::from_millis(150),
            higher_id_read.read(&mut higher_buf),
        )
        .await;
        assert!(
            higher.is_err(),
            "a pending request must not be broadcast to a second matching UI"
        );

        store.notify_pending(&pending).await;

        let lower_n =
            tokio::time::timeout(Duration::from_secs(1), lower_id_read.read(&mut lower_buf))
                .await
                .expect("repeated dispatch should use the same matching UI")
                .expect("lower-id UI read should succeed");
        let lower_msg = String::from_utf8_lossy(&lower_buf[..lower_n]);
        assert!(lower_msg.contains("net:arbitrate"));

        let higher = tokio::time::timeout(
            Duration::from_millis(150),
            higher_id_read.read(&mut higher_buf),
        )
        .await;
        assert!(
            higher.is_err(),
            "repeated dispatch must remain deterministic"
        );
    }
    #[tokio::test]
    async fn notify_pending_fails_over_when_lowest_id_ui_is_stale() {
        let store = test_store();
        let dead_read = register_ui(&store, 10, "ui-dead", "sandbox-a").await;
        drop(dead_read);
        let mut live_read = register_ui(&store, 20, "ui-live", "sandbox-a").await;
        let pending = pending_network("net:failover");

        store.notify_pending(&pending).await;

        let mut live_buf = [0u8; 1024];
        let live_n = tokio::time::timeout(Duration::from_secs(1), live_read.read(&mut live_buf))
            .await
            .expect("live matching UI should receive after stale-client failover")
            .expect("live UI read should succeed");
        let live_msg = String::from_utf8_lossy(&live_buf[..live_n]);
        assert!(live_msg.contains("net:failover"));
        assert!(
            !store.inner.lock().await.ui_clients.contains_key(&10),
            "stale selected UI should be removed after write failure"
        );
    }
    #[tokio::test]
    async fn notify_pending_recovers_other_pending_routes_after_all_targets_die() {
        let store = test_store();
        let dead_read = register_ui(&store, 10, "ui-dead", "sandbox-a").await;
        drop(dead_read);
        let mut live_read = register_ui(&store, 20, "ui-live", "sandbox-b").await;
        let dead_pending = pending_network("net:dead");
        let mut recovered_pending = pending_network("net:recovered");
        if let Pending::Network(network) = &mut recovered_pending {
            network.sandbox_session_id = Some("sandbox-b".into());
        }
        {
            let mut inner = store.inner.lock().await;
            inner
                .pending
                .insert("net:dead".into(), dead_pending.clone());
            inner
                .pending
                .insert("net:recovered".into(), recovered_pending);
        }

        store.notify_pending(&dead_pending).await;

        let mut live_buf = [0u8; 1024];
        let live_n = tokio::time::timeout(Duration::from_secs(1), live_read.read(&mut live_buf))
            .await
            .expect("orphan recovery should notify another live pending route")
            .expect("live UI read should succeed");
        let live_msg = String::from_utf8_lossy(&live_buf[..live_n]);
        assert!(live_msg.contains("net:recovered"));
        assert!(!live_msg.contains("net:dead"));
        assert!(
            !store.inner.lock().await.ui_clients.contains_key(&10),
            "all failed UI targets should be removed before orphan recovery"
        );
    }
}

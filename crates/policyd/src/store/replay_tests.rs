//! A verdict decided for one sandbox must not answer another sandbox.
//!
//! Every capability kind keeps a short verdict cache. Each test records a
//! verdict as sandbox A's prompt finishing does, then asks as A, which the
//! cache answers, and as B, which must be judged on its own: with no UI to
//! ask, that is a blocked reply, not A's verdict.

use std::{path::PathBuf, time::Duration};

use agent_sandbox_core::{
    ApprovalScope, AttributionToken, DbusMessageKind, DbusTarget, FileAccess, FilesystemRuleKey,
    HttpMethod, HttpMethodMatcher, HttpRequest, HttpRuleTarget, HttpUrl, NetworkRuleKey,
    ProcessIds, ProxyRequestId, ProxySessionToken, ResolvedRequestContext, ResourceAccess,
    ResourceKind, ResourceRuleKey, RpcReply, SandboxPaths, SecretAccess, SecretOperation,
    SecretPartition, SecretRequest, SocketAccess, Verdict, VerdictSource,
};

use super::{
    DecisionAction, PolicyStore, SecretVerdictCacheKey,
    dbus::DbusApproval,
    decision_context::ContextKey,
    filesystem::FilesystemApproval,
    resource::ResourceApproval,
    secrets::SecretApproval,
    test_args,
    types::{UiClient, UiSessionContext},
};
use crate::wire::{NetworkScopeOp, ScopeWire};

fn store() -> PolicyStore {
    PolicyStore::new(test_args(
        "/tmp/replay.sock".into(),
        "/tmp/replay-sandbox.sock".into(),
        "/tmp/replay-declarative.json".into(),
        "/tmp/replay-export.json".into(),
        Duration::from_millis(150),
        true,
    ))
}

fn sandbox(session: &str, package: Option<&str>) -> ResolvedRequestContext {
    ResolvedRequestContext {
        paths: SandboxPaths::from_wire(
            Some("/repo".into()),
            Some("/home/user".into()),
            Some("/repo".into()),
        ),
        ids: ProcessIds::from_options(None, Some(1000)),
        sandbox_session_id: Some(session.into()),
        package: package.map(Into::into),
    }
}

fn once_allowed() -> Verdict {
    Verdict::allowed(VerdictSource::Scope(ApprovalScope::Once))
}

fn dbus_target() -> DbusTarget {
    DbusTarget::session(
        "org.example.Service",
        "/org/example/Object",
        "org.example.Interface",
        "Read",
        DbusMessageKind::MethodCall,
        "s",
        Vec::new(),
    )
}

fn secret_request() -> SecretRequest {
    SecretRequest {
        partition: SecretPartition::Host,
        collection: "login".into(),
        is_default_collection: false,
        attributes: std::collections::BTreeMap::from([("service".to_owned(), "gh".to_owned())]),
        label: "GitHub CLI".into(),
        access: SecretAccess::Read,
        operation: SecretOperation::GetSecret,
        replace: false,
        batch: None,
    }
}

#[tokio::test]
async fn network_verdict_is_not_replayed_to_another_session() {
    let store = store();
    let (a, b) = (sandbox("a", None), sandbox("b", None));
    let rule = NetworkRuleKey::new("example.com", 443);
    let ask = |ctx: &ResolvedRequestContext| {
        store.request_network_approval(
            "example.com".into(),
            443,
            "tcp".into(),
            "tcp://example.com:443".into(),
            ctx.clone(),
        )
    };

    store
        .finish_network(
            "net:a",
            true,
            once_allowed().source,
            Some(ContextKey::new(&a, rule)),
        )
        .await;

    assert!(ask(&a).await.verdict.allowed, "the cache answers A");

    let reply = ask(&b).await;
    assert!(!reply.verdict.allowed, "B must not ride A's approval");
    assert!(reply.error.is_some(), "B is judged on its own: {reply:?}");
}

#[tokio::test]
async fn filesystem_verdict_is_not_replayed_to_another_session() {
    let store = store();
    let (a, b) = (sandbox("a", None), sandbox("b", None));
    let path = PathBuf::from("/tmp/agent-sandbox-replay-fs");
    let rule = FilesystemRuleKey {
        path: path.clone(),
        access: FileAccess::Read,
    };

    store
        .finish_prompt::<FilesystemApproval>(
            "fs:a",
            ContextKey::new(&a, rule),
            Verdict::denied(VerdictSource::User),
        )
        .await;

    let cached = store
        .request_filesystem_approval(path.clone(), FileAccess::Read, a)
        .await;
    assert!(!cached.verdict.allowed);
    assert!(
        cached.error.is_none(),
        "A is answered by the cache: {cached:?}"
    );

    let reply = store
        .request_filesystem_approval(path, FileAccess::Read, b)
        .await;
    assert!(
        reply.error.is_some(),
        "B must be judged on its own, not denied from A's cache: {reply:?}"
    );
}

#[tokio::test]
async fn resource_verdict_is_not_replayed_to_another_session() {
    let store = store();
    let (a, b) = (sandbox("a", None), sandbox("b", None));
    let path = PathBuf::from("/repo/replay.sock");
    let access = ResourceAccess::Socket(SocketAccess::Connect);

    store
        .finish_prompt::<ResourceApproval>(
            "res:a",
            ContextKey::new(&a, ResourceRuleKey {
                kind: ResourceKind::UnixSocket,
                path: path.clone(),
                access,
            }),
            once_allowed(),
        )
        .await;

    let cached = store
        .request_resource_approval(ResourceKind::UnixSocket, path.clone(), access, a)
        .await;
    assert!(cached.verdict.allowed, "the cache answers A");

    let reply = store
        .request_resource_approval(ResourceKind::UnixSocket, path, access, b)
        .await;
    assert!(!reply.verdict.allowed, "B must not ride A's approval");
    assert!(reply.error.is_some(), "B is judged on its own: {reply:?}");
}

#[tokio::test]
async fn dbus_verdict_is_not_replayed_to_another_session() {
    let store = store();
    let (a, b) = (sandbox("a", None), sandbox("b", None));

    store
        .finish_prompt::<DbusApproval>("dbus:a", ContextKey::new(&a, dbus_target()), once_allowed())
        .await;

    assert!(
        store
            .request_dbus_approval(dbus_target(), a)
            .await
            .verdict
            .allowed,
        "the cache answers A"
    );

    let reply = store.request_dbus_approval(dbus_target(), b).await;
    assert!(!reply.verdict.allowed, "B must not ride A's approval");
    assert!(reply.error.is_some(), "B is judged on its own: {reply:?}");
}

#[tokio::test]
async fn secret_verdict_is_not_replayed_to_another_session() {
    let store = store();
    let (a, b) = (sandbox("a", Some("pkg")), sandbox("b", Some("pkg")));
    let key = SecretVerdictCacheKey {
        request: secret_request(),
        package: Some("pkg".into()),
    };

    store
        .finish_prompt::<SecretApproval>("secret:a", ContextKey::new(&a, key), once_allowed())
        .await;

    assert!(
        store
            .request_secret_approval(secret_request(), a)
            .await
            .verdict
            .allowed,
        "the cache answers A"
    );

    let reply = store.request_secret_approval(secret_request(), b).await;
    assert!(!reply.verdict.allowed, "B must not ride A's approval");
    assert!(reply.error.is_some(), "B is judged on its own: {reply:?}");
}

#[tokio::test]
async fn a_package_is_part_of_the_context_of_a_cached_verdict() {
    let store = store();
    let attributed = sandbox("a", Some("pkg"));
    let claimed = sandbox("a", None);

    store
        .finish_prompt::<DbusApproval>(
            "dbus:a",
            ContextKey::new(&attributed, dbus_target()),
            once_allowed(),
        )
        .await;

    // A process that names the session but was not verified against it has
    // no package.
    let reply = store.request_dbus_approval(dbus_target(), claimed).await;
    assert!(!reply.verdict.allowed);
    assert!(reply.error.is_some(), "got: {reply:?}");
}

#[tokio::test]
async fn a_request_without_a_session_never_shares_a_verdict_with_a_sessioned_one() {
    let store = store();
    let sessioned = sandbox("a", None);
    let sessionless = ResolvedRequestContext {
        sandbox_session_id: None,
        ..sandbox("a", None)
    };

    store
        .finish_prompt::<DbusApproval>(
            "dbus:a",
            ContextKey::new(&sessioned, dbus_target()),
            once_allowed(),
        )
        .await;

    let reply = store
        .request_dbus_approval(dbus_target(), sessionless)
        .await;
    assert!(!reply.verdict.allowed);
    assert!(reply.error.is_some(), "got: {reply:?}");
}

#[tokio::test]
async fn identical_prompts_of_different_sandboxes_are_not_coalesced() {
    let store = std::sync::Arc::new(store());
    let (a, b) = (sandbox("a", None), sandbox("b", None));

    let first = {
        let store = store.clone();
        tokio::spawn(async move { store.request_dbus_approval(dbus_target(), a).await })
    };
    let second = {
        let store = store.clone();
        tokio::spawn(async move { store.request_dbus_approval(dbus_target(), b).await })
    };

    // Both prompts are pending at once, side by side: they would be one
    // prompt, and one verdict for both, if they were coalesced.
    let deadline = std::time::Instant::now() + Duration::from_millis(120);
    let mut most = 0;

    while std::time::Instant::now() < deadline {
        most = most.max(store.inner.lock().await.pending.pending.len());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert_eq!(most, 2, "each sandbox has its own prompt");
    let _ = (first.await, second.await);
}

#[tokio::test]
async fn a_once_allow_is_neither_seen_nor_spent_by_another_sandbox() {
    let store = store();
    let (a, b, claimant) = (
        sandbox("a", Some("pkg")),
        sandbox("b", Some("pkg")),
        sandbox("a", None),
    );

    let reply = store
        .apply_network_scope(
            NetworkScopeOp {
                host: "example.com".into(),
                port: 443,
                scope: ApprovalScope::Once,
                wire: ScopeWire::from_resolved(&a, None),
            },
            DecisionAction::Approve,
        )
        .await;
    assert!(matches!(reply, RpcReply::ScopeAction(_)), "got: {reply:?}");

    for other in [&b, &claimant, &ResolvedRequestContext::default()] {
        assert!(
            store
                .network_verdict("example.com", 443, other, true)
                .await
                .is_none_or(|verdict| !verdict.allowed),
            "another sandbox rode A's once approval"
        );
    }

    assert_eq!(
        store.inner.lock().await.session.once_allow.len(),
        1,
        "another sandbox's check spent A's once approval"
    );

    assert!(
        store
            .network_verdict("example.com", 443, &a, true)
            .await
            .is_some_and(|verdict| verdict.allowed),
        "A keeps its once approval"
    );
    assert!(store.inner.lock().await.session.once_allow.is_empty());
}

#[tokio::test]
async fn an_http_once_decision_is_neither_seen_nor_spent_by_another_sandbox() {
    let store = store();
    let request = HttpRequest::parse_absolute("GET", "https://example.com/").expect("request");
    let target = HttpRuleTarget::new(
        HttpMethodMatcher::Exact(HttpMethod::parse("GET").expect("method")),
        HttpUrl::parse("https://example.com/").expect("url"),
    )
    .expect("target");
    let (a, b, claimant) = (
        sandbox("a", Some("pkg")),
        sandbox("b", Some("pkg")),
        sandbox("a", None),
    );

    store
        .apply_http_scope(target, ApprovalScope::Once, None, a.clone(), true)
        .await
        .expect("once approval");

    let ask = |ctx: ResolvedRequestContext| {
        store.request_http_approval(
            ProxySessionToken::new(),
            ProxyRequestId::new(),
            AttributionToken::new(),
            request.clone(),
            ctx,
        )
    };

    for other in [b, claimant] {
        let reply = ask(other).await.expect("evaluation");
        assert!(!reply.verdict.allowed, "rode A's once approval: {reply:?}");
    }

    assert_eq!(
        store.inner.lock().await.session.http_once_allow.len(),
        1,
        "another sandbox's request spent A's once approval"
    );

    assert!(
        ask(a.clone()).await.expect("evaluation").verdict.allowed,
        "A keeps its once approval"
    );
    assert!(store.inner.lock().await.session.http_once_allow.is_empty());
}

async fn register_ui(store: &PolicyStore, ui_session: &str, sandbox_session: Option<&str>) {
    let (stream, _peer) = tokio::net::UnixStream::pair().expect("unix stream pair");
    let (_, writer) = stream.into_split();
    let mut inner = store.inner.lock().await;
    let client_id = inner.ui_clients.len() as u64 + 1;

    inner.ui_clients.insert(client_id, UiClient {
        session_id: ui_session.into(),
        writer: std::sync::Arc::new(tokio::sync::Mutex::new(writer)),
    });

    inner
        .ui_context_by_session
        .insert(ui_session.into(), UiSessionContext {
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            sandbox_session_id: sandbox_session.map(Into::into),
            client_id,
            ..Default::default()
        });
}

async fn session_allow(store: &PolicyStore, ui_session: &str, ctx: &ResolvedRequestContext) {
    let reply = store
        .apply_network_scope(
            NetworkScopeOp {
                host: "example.com".into(),
                port: 443,
                scope: ApprovalScope::Session,
                wire: ScopeWire::from_resolved(ctx, Some(ui_session.into())),
            },
            DecisionAction::Approve,
        )
        .await;
    assert!(matches!(reply, RpcReply::ScopeAction(_)), "got: {reply:?}");
}

async fn allowed(store: &PolicyStore, ctx: &ResolvedRequestContext) -> bool {
    store
        .network_verdict("example.com", 443, ctx, false)
        .await
        .is_some_and(|verdict| verdict.allowed)
}

#[tokio::test]
async fn a_session_allow_applies_to_its_own_sandbox_session_only() {
    let store = store();
    let (a, b) = (sandbox("a", Some("pkg")), sandbox("b", Some("pkg")));
    let standing_in_the_same_project = ResolvedRequestContext {
        sandbox_session_id: None,
        package: None,
        ..a.clone()
    };

    register_ui(&store, "ui-a", Some("a")).await;
    register_ui(&store, "ui-b", Some("b")).await;
    session_allow(&store, "ui-a", &a).await;

    assert!(allowed(&store, &a).await, "A's own session allow");
    assert!(!allowed(&store, &b).await, "B rode A's session allow");
    assert!(
        !allowed(&store, &standing_in_the_same_project).await,
        "a request without a session rode a sandbox's session allow by its directory"
    );
}

#[tokio::test]
async fn a_session_allow_of_a_standalone_ui_does_not_reach_a_sandbox_session() {
    let store = store();
    let a = sandbox("a", Some("pkg"));
    let standalone = ResolvedRequestContext {
        sandbox_session_id: None,
        package: None,
        ..a.clone()
    };

    register_ui(&store, "ui-standalone", None).await;
    session_allow(&store, "ui-standalone", &standalone).await;

    assert!(allowed(&store, &standalone).await, "the standalone request");
    assert!(
        !allowed(&store, &a).await,
        "a sandbox rode a standalone allow"
    );
}

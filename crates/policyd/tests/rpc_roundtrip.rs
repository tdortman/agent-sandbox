//! In-process RPC round-trip tests for the policy daemon.
//!
//! Spins up a `PolicyServer` and drives request/reply exchanges over the daemon
//! Unix-socket RPC wire format.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use agent_sandbox_core::{
    ProcessIds, ResolvedRequestContext, RpcReply, SandboxPaths, SecretAccess, SecretOperation,
    SecretPartition, SecretRequest, VerdictSource,
};
use agent_sandbox_policyd::{PackageDeclarative, PolicyServer, PolicyStore, PolicydArgs};
use tempfile::tempdir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;

fn test_args(root: &Path) -> PolicydArgs {
    PolicydArgs {
        host_socket: root.join("host.sock"),
        sandbox_socket: root.join("sandbox.sock"),
        proxy_socket: None,
        proxy_gid: None,
        declarative: root.join("declarative.json"),
        export_json: root.join("export.json"),
        export_nix: None,
        approval_timeout: Duration::from_secs(1),
        interactive_approval: false,
        ui_spawn_cmd: None,
        package_declarative: Vec::new(),
        fs_monitor_cmd: None,
        fs_ignore_static_allows: true,
        syscall_broker_cmd: None,
    }
}

async fn connect_when_ready(path: &Path) -> UnixStream {
    for _ in 0..100 {
        match UnixStream::connect(path).await {
            Ok(stream) => return stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }

    panic!("timed out waiting for {}", path.display());
}

async fn rpc(stream: UnixStream, request: &str) -> RpcReply {
    let (reader, mut writer) = stream.into_split();

    writer
        .write_all(request.as_bytes())
        .await
        .expect("write request");

    writer.write_all(b"\n").await.expect("write newline");
    writer.flush().await.expect("flush request");
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read reply");
    serde_json::from_str(line.trim()).expect("valid RPC reply")
}

#[tokio::test]
async fn sandbox_filesystem_rpc_applies_allow_and_deny_policy() {
    let root = tempdir().expect("temporary directory");
    let args = test_args(root.path());

    std::fs::write(
        &args.declarative,
        r#"{
            "filesystem": {
                "allow": [{"path": "/workspace", "access": "write"}],
                "deny": [{"path": "/workspace/secret", "access": "write"}]
            }
        }"#,
    )
    .expect("declarative policy");

    let sandbox_socket = args.sandbox_socket.clone();
    let server = tokio::spawn(PolicyServer::new(Arc::new(PolicyStore::new(args))).run());

    let allowed = rpc(
        connect_when_ready(&sandbox_socket).await,
        r#"{"op":"check_filesystem","path":"/workspace/file","access":"write","ctx":{}}"#,
    )
    .await;

    match allowed {
        RpcReply::FilesystemCheck(reply) => {
            assert!(reply.ok);
            assert!(reply.verdict.allowed);
            assert_eq!(reply.path, Path::new("/workspace/file"));
        }

        other => panic!("allowed filesystem check returned unexpected reply: {other:?}"),
    }

    let denied = rpc(
        connect_when_ready(&sandbox_socket).await,
        r#"{"op":"check_filesystem","path":"/workspace/secret","access":"write","ctx":{}}"#,
    )
    .await;

    match denied {
        RpcReply::FilesystemCheck(reply) => {
            assert!(reply.ok);
            assert!(!reply.verdict.allowed);
            assert_eq!(reply.path, Path::new("/workspace/secret"));
        }

        other => panic!("denied filesystem check returned unexpected reply: {other:?}"),
    }

    server.abort();
}

fn host_read_secret_request(
    partition: SecretPartition,
    collection: &str,
    is_default_collection: bool,
    service: &str,
    access: SecretAccess,
) -> SecretRequest {
    let mut attributes = BTreeMap::new();
    attributes.insert("service".to_owned(), service.to_owned());
    SecretRequest {
        partition,
        collection: collection.to_owned(),
        is_default_collection,
        attributes,
        label: "GitHub CLI".to_owned(),
        access,
        operation: SecretOperation::GetSecret,
        replace: false,
        batch: None,
    }
}

fn read_proc_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    let mut fields = stat[end + 1..].split_whitespace();
    fields.next()?;
    fields.next()?.parse().ok()
}

#[tokio::test]
async fn resolve_sandbox_package_and_check_secret_enforce_host_socket_and_policy() {
    let root = tempdir().expect("temporary directory");
    let mut args = test_args(root.path());
    let pkg_base = root.path().join("pkg-codex.json");
    std::fs::write(
        &pkg_base,
        r#"{
            "secrets": {
                "allow": [
                    { "partition": "own_package", "access": "all", "comment": "codex own partition" }
                ]
            }
        }"#,
    )
    .expect("write package base policy");
    args.package_declarative = vec![PackageDeclarative {
        name: "codex".into(),
        path: pkg_base,
    }];

    std::fs::write(
        &args.declarative,
        r#"{
            "secrets": {
                "allow": [
                    { "partition": "host", "collection": "kdewallet", "attributes": { "service": "gh" }, "access": "read", "comment": "shared gh read" }
                ],
                "deny": [
                    { "partition": "host", "collection": "default", "attributes": { "service": "gh-denied" }, "access": "all" }
                ]
            }
        }"#,
    )
    .expect("write declarative policy");

    let host_socket = args.host_socket.clone();
    let sandbox_socket = args.sandbox_socket.clone();
    let server = tokio::spawn(PolicyServer::new(Arc::new(PolicyStore::new(args))).run());

    let launcher_pid = read_proc_ppid(std::process::id()).expect("parent pid of test process");
    let registered = rpc(
        connect_when_ready(&host_socket).await,
        &format!(
            r#"{{"op":"register_sandbox","session_id":"sandbox-codex","package":"codex","launcher_pid":{launcher_pid}}}"#
        ),
    )
    .await;
    assert!(matches!(registered, RpcReply::Simple(reply) if reply.ok));

    // Host socket resolves registered package and returns None for unregistered
    // session.
    let resolved = rpc(
        connect_when_ready(&host_socket).await,
        r#"{"op":"resolve_sandbox_package","ctx":{"sandbox_session_id":"sandbox-codex"}}"#,
    )
    .await;
    match resolved {
        RpcReply::SandboxPackage(reply) => {
            assert!(reply.ok);
            assert_eq!(reply.package.as_deref(), Some("codex"));
        }
        other => panic!("expected SandboxPackage reply, got {other:?}"),
    }

    let unattributed = rpc(
        connect_when_ready(&host_socket).await,
        r#"{"op":"resolve_sandbox_package","ctx":{"sandbox_session_id":"unknown-session"}}"#,
    )
    .await;
    match unattributed {
        RpcReply::SandboxPackage(reply) => {
            assert!(reply.ok);
            assert_eq!(reply.package, None);
        }
        other => panic!("expected SandboxPackage reply, got {other:?}"),
    }

    // Sandbox socket must reject both ResolveSandboxPackage and CheckSecret.
    let rejected_resolve = rpc(
        connect_when_ready(&sandbox_socket).await,
        r#"{"op":"resolve_sandbox_package","ctx":{"sandbox_session_id":"sandbox-codex"}}"#,
    )
    .await;
    assert!(matches!(rejected_resolve, RpcReply::Error(_)));

    let rejected_check = rpc(
        connect_when_ready(&sandbox_socket).await,
        r#"{"op":"check_secret","request":{"partition":"own_package","collection":"kdewallet","is_default_collection":true,"attributes":{},"label":"tok","access":"read","operation":"get_secret"},"ctx":{"sandbox_session_id":"sandbox-codex"}}"#,
    )
    .await;
    assert!(matches!(rejected_check, RpcReply::Error(_)));

    // Attributed package is allowed its own_package secret via package base
    // layer.
    let allowed_own = rpc(
        connect_when_ready(&host_socket).await,
        r#"{"op":"check_secret","request":{"partition":"own_package","collection":"kdewallet","is_default_collection":true,"attributes":{"service":"openai"},"label":"API key","access":"read","operation":"get_secret"},"ctx":{"sandbox_session_id":"sandbox-codex"}}"#,
    )
    .await;
    match allowed_own {
        RpcReply::SecretCheck(reply) => {
            assert!(reply.ok);
            assert!(reply.verdict.allowed);
            assert_eq!(
                reply.verdict.source,
                VerdictSource::policy_with_comment("codex own partition")
            );
        }
        other => panic!("expected allowed SecretCheck reply, got {other:?}"),
    }

    // Unattributed sandbox cannot match own_package rules and fails closed.
    let blocked_unattributed = rpc(
        connect_when_ready(&host_socket).await,
        r#"{"op":"check_secret","request":{"partition":"own_package","collection":"kdewallet","is_default_collection":true,"attributes":{"service":"openai"},"label":"API key","access":"read","operation":"get_secret"},"ctx":{"sandbox_session_id":"unknown-session"}}"#,
    )
    .await;
    match blocked_unattributed {
        RpcReply::SecretCheck(reply) => {
            assert!(reply.ok);
            assert!(!reply.verdict.allowed);
            assert_eq!(reply.verdict.source, VerdictSource::Blocked);
        }
        other => panic!("expected blocked SecretCheck reply, got {other:?}"),
    }

    // Declarative host allow rule permits matching host read.
    let allowed_host = rpc(
        connect_when_ready(&host_socket).await,
        r#"{"op":"check_secret","request":{"partition":"host","collection":"kdewallet","is_default_collection":true,"attributes":{"service":"gh"},"label":"GitHub CLI","access":"read","operation":"get_secret"},"ctx":{"sandbox_session_id":"sandbox-codex"}}"#,
    )
    .await;
    match allowed_host {
        RpcReply::SecretCheck(reply) => {
            assert!(reply.ok);
            assert!(reply.verdict.allowed);
            assert_eq!(
                reply.verdict.source,
                VerdictSource::policy_with_comment("shared gh read")
            );
        }
        other => panic!("expected allowed host SecretCheck reply, got {other:?}"),
    }

    server.abort();
}

#[test]
fn check_secret_evaluates_all_six_layers_with_deny_wins() {
    let root = tempdir().expect("temporary directory");
    let home = root.path().join("home");
    let project = root.path().join("project");
    std::fs::create_dir_all(home.join(".config/agent-sandbox/packages"))
        .expect("create home packages dir");
    std::fs::create_dir_all(project.join(".agent-sandbox/packages"))
        .expect("create project packages dir");

    let pkg_base = root.path().join("pkg-base.json");
    let mut args = test_args(root.path());
    args.package_declarative = vec![PackageDeclarative {
        name: "codex".into(),
        path: pkg_base.clone(),
    }];

    // Layer 0 (declarative): allow host service=gh on concrete kdewallet; deny
    // own_package delete.
    std::fs::write(
        &args.declarative,
        r#"{
            "secrets": {
                "allow": [
                    { "partition": "host", "collection": "kdewallet", "attributes": { "service": "gh" }, "access": "read" }
                ],
                "deny": [
                    { "partition": "own_package", "collection": "*", "access": "delete" }
                ]
            }
        }"#,
    )
    .expect("write declarative");

    // Layer 1 (package base): allow own_package all.
    std::fs::write(
        &pkg_base,
        r#"{
            "secrets": {
                "allow": [
                    { "partition": "own_package", "collection": "default", "access": "all" }
                ]
            }
        }"#,
    )
    .expect("write pkg base");

    // Layer 2 (package home): allow host service=pkg-home.
    std::fs::write(
        home.join(".config/agent-sandbox/packages/codex.json"),
        r#"{
            "secrets": {
                "allow": [
                    { "partition": "host", "attributes": { "service": "pkg-home" }, "access": "read" }
                ]
            }
        }"#,
    )
    .expect("write pkg home");

    // Layer 3 (user): allow host service=user-secret.
    std::fs::write(
        home.join(".config/agent-sandbox/policy.json"),
        r#"{
            "secrets": {
                "allow": [
                    { "partition": "host", "attributes": { "service": "user-secret" }, "access": "read" }
                ]
            }
        }"#,
    )
    .expect("write user policy");

    // Layer 4 (project): deny host service=gh on "default" collection
    // (conservative vs kdewallet).
    std::fs::write(
        project.join(".agent-sandbox/policy.json"),
        r#"{
            "secrets": {
                "deny": [
                    { "partition": "host", "collection": "default", "attributes": { "service": "gh" }, "access": "read" }
                ]
            }
        }"#,
    )
    .expect("write project policy");

    // Layer 5 (package project): allow host service=pkg-project.
    std::fs::write(
        project.join(".agent-sandbox/packages/codex.json"),
        r#"{
            "secrets": {
                "allow": [
                    { "partition": "host", "attributes": { "service": "pkg-project" }, "access": "read" }
                ]
            }
        }"#,
    )
    .expect("write pkg project");

    let store = PolicyStore::new(args);
    let ctx = ResolvedRequestContext {
        paths: SandboxPaths::from_wire(Some(project.clone()), Some(home), Some(project)),
        ids: ProcessIds::default(),
        sandbox_session_id: None,
        package: Some("codex".into()),
    };

    // Narrow declarative delete deny beats package base all allow for Delete,
    // while Read on own_package remains allowed.
    let own_read = store.check_secret(
        host_read_secret_request(
            SecretPartition::OwnPackage,
            "kdewallet",
            true,
            "any",
            SecretAccess::Read,
        ),
        &ctx,
    );
    assert!(own_read.verdict.allowed);

    let own_delete = store.check_secret(
        host_read_secret_request(
            SecretPartition::OwnPackage,
            "kdewallet",
            true,
            "any",
            SecretAccess::Delete,
        ),
        &ctx,
    );
    assert!(!own_delete.verdict.allowed);
    assert_eq!(own_delete.verdict.source, VerdictSource::policy());

    // Conservative merge kept both declarative kdewallet allow and project
    // default deny: when kdewallet IS default, project deny wins; when
    // kdewallet is NOT default, declarative allow wins.
    let gh_when_default = store.check_secret(
        host_read_secret_request(
            SecretPartition::Host,
            "kdewallet",
            true,
            "gh",
            SecretAccess::Read,
        ),
        &ctx,
    );
    assert!(!gh_when_default.verdict.allowed);
    assert_eq!(gh_when_default.verdict.source, VerdictSource::policy());

    let gh_when_not_default = store.check_secret(
        host_read_secret_request(
            SecretPartition::Host,
            "kdewallet",
            false,
            "gh",
            SecretAccess::Read,
        ),
        &ctx,
    );
    assert!(gh_when_not_default.verdict.allowed);

    // Layers 2, 3, and 5 all contribute allow rules.
    for service in ["pkg-home", "user-secret", "pkg-project"] {
        let reply = store.check_secret(
            host_read_secret_request(
                SecretPartition::Host,
                "kdewallet",
                true,
                service,
                SecretAccess::Read,
            ),
            &ctx,
        );
        assert!(reply.verdict.allowed, "expected layer allow for {service}");
    }
}

struct LegacySecretsWarnCounter {
    count: Arc<AtomicUsize>,
}

struct MessageVisitor {
    found_legacy_secrets_warning: bool,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if format!("{value:?}").contains("org.freedesktop.secrets") {
            self.found_legacy_secrets_warning = true;
        }
    }

    fn record_str(&mut self, _field: &tracing::field::Field, value: &str) {
        if value.contains("org.freedesktop.secrets") {
            self.found_legacy_secrets_warning = true;
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LegacySecretsWarnCounter {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() == Level::WARN {
            let mut visitor = MessageVisitor {
                found_legacy_secrets_warning: false,
            };
            event.record(&mut visitor);
            if visitor.found_legacy_secrets_warning {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

#[test]
fn legacy_org_freedesktop_secrets_dbus_rule_warns_once_per_policy_path() {
    let root = tempdir().expect("temporary directory");
    let home = root.path().join("home");
    std::fs::create_dir_all(home.join(".config/agent-sandbox")).expect("create home policy dir");
    let args = test_args(root.path());

    // Declarative policy has a legacy literal org.freedesktop.secrets D-Bus
    // allow rule.
    std::fs::write(
        &args.declarative,
        r#"{
            "dbus": {
                "allow": [
                    {
                        "target": {
                            "bus": "session",
                            "destination": "org.freedesktop.secrets",
                            "object_path": "/org/freedesktop/secrets",
                            "interface": "org.freedesktop.Secret.Service",
                            "member": "OpenSession",
                            "message_kind": "method_call",
                            "signature": "sv",
                            "fd_metadata": []
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("write declarative policy");

    // User policy has a wildcard D-Bus rule (NOT literal
    // org.freedesktop.secrets) -> must not warn.
    std::fs::write(
        home.join(".config/agent-sandbox/policy.json"),
        r#"{
            "dbus": {
                "allow": [
                    {
                        "target": {
                            "bus": "session",
                            "destination": "org.freedesktop.*",
                            "object_path": "*",
                            "interface": "*",
                            "member": "*",
                            "message_kind": "method_call",
                            "signature": "*",
                            "fd_metadata": []
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("write user policy");

    let store = PolicyStore::new(args);
    let ctx = ResolvedRequestContext {
        paths: SandboxPaths::from_wire(None, Some(home.clone()), None),
        ids: ProcessIds::default(),
        sandbox_session_id: None,
        package: None,
    };

    let warn_count = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(LegacySecretsWarnCounter {
        count: Arc::clone(&warn_count),
    });

    tracing::subscriber::with_default(subscriber, || {
        let _ = store.merged_for(&ctx);
        let _ = store.merged_for(&ctx);
        assert_eq!(
            warn_count.load(Ordering::SeqCst),
            1,
            "legacy org.freedesktop.secrets rule must warn exactly once per path"
        );

        // Now add a legacy literal deny rule to the user policy path -> second
        // distinct path warns once.
        let user_path: PathBuf = home.join(".config/agent-sandbox/policy.json");
        std::fs::write(
            &user_path,
            r#"{
                "dbus": {
                    "deny": [
                        {
                            "target": {
                                "bus": "session",
                                "destination": "org.freedesktop.secrets",
                                "object_path": "*",
                                "interface": "*",
                                "member": "*",
                                "message_kind": "method_call",
                                "signature": "*",
                                "fd_metadata": []
                            }
                        }
                    ]
                }
            }"#,
        )
        .expect("rewrite user policy");

        let _ = store.merged_for(&ctx);
        let _ = store.merged_for(&ctx);
        assert_eq!(
            warn_count.load(Ordering::SeqCst),
            2,
            "second policy file path with legacy deny rule must also warn once"
        );
    });
}

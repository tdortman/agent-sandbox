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
use serde_json::Value;
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

#[tokio::test]
async fn check_secret_evaluates_all_six_layers_with_deny_wins() {
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
    let own_read = store
        .check_secret(
            host_read_secret_request(
                SecretPartition::OwnPackage,
                "kdewallet",
                true,
                "any",
                SecretAccess::Read,
            ),
            ctx.clone(),
        )
        .await;
    assert!(own_read.verdict.allowed);

    let own_delete = store
        .check_secret(
            host_read_secret_request(
                SecretPartition::OwnPackage,
                "kdewallet",
                true,
                "any",
                SecretAccess::Delete,
            ),
            ctx.clone(),
        )
        .await;
    assert!(!own_delete.verdict.allowed);
    assert_eq!(own_delete.verdict.source, VerdictSource::policy());

    // Conservative merge kept both declarative kdewallet allow and project
    // default deny: when kdewallet IS default, project deny wins; when
    // kdewallet is NOT default, declarative allow wins.
    let gh_when_default = store
        .check_secret(
            host_read_secret_request(
                SecretPartition::Host,
                "kdewallet",
                true,
                "gh",
                SecretAccess::Read,
            ),
            ctx.clone(),
        )
        .await;
    assert!(!gh_when_default.verdict.allowed);
    assert_eq!(gh_when_default.verdict.source, VerdictSource::policy());

    let gh_when_not_default = store
        .check_secret(
            host_read_secret_request(
                SecretPartition::Host,
                "kdewallet",
                false,
                "gh",
                SecretAccess::Read,
            ),
            ctx.clone(),
        )
        .await;
    assert!(gh_when_not_default.verdict.allowed);

    // Layers 2, 3, and 5 all contribute allow rules.
    for service in ["pkg-home", "user-secret", "pkg-project"] {
        let reply = store
            .check_secret(
                host_read_secret_request(
                    SecretPartition::Host,
                    "kdewallet",
                    true,
                    service,
                    SecretAccess::Read,
                ),
                ctx.clone(),
            )
            .await;
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

async fn rpc_line(socket: &Path, request: &str) -> Value {
    let stream = connect_when_ready(socket).await;
    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(format!("{request}\n").as_bytes())
        .await
        .expect("write RPC line");
    writer.flush().await.expect("flush RPC line");

    let mut line = String::new();
    let mut reader = BufReader::new(reader);
    reader.read_line(&mut line).await.expect("read RPC line");
    serde_json::from_str(line.trim()).expect("parse RPC reply JSON")
}

struct RegisteredUi {
    reader: tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    _writer: tokio::net::unix::OwnedWriteHalf,
    session_id: String,
}

async fn connect_and_register_ui(
    host_socket: &Path,
    project: &Path,
    home: &Path,
    sandbox_session_id: &str,
) -> RegisteredUi {
    let stream = connect_when_ready(host_socket).await;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    let register = serde_json::json!({
        "op": "register_ui",
        "ui_client": "test-ui",
        "ctx": {
            "cwd": project,
            "home": home,
            "project_root": project,
            "sandbox_session_id": sandbox_session_id,
        }
    });
    write
        .write_all(format!("{register}\n").as_bytes())
        .await
        .expect("write register_ui");
    write.flush().await.expect("flush register_ui");

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .expect("read register_ui reply");
    let reply: Value = serde_json::from_str(line.trim()).expect("parse register_ui reply");
    assert_eq!(reply["result"], "register_ui");
    assert_eq!(reply["ok"], true);
    let session_id = reply["session_id"]
        .as_str()
        .expect("ui session_id")
        .to_owned();
    RegisteredUi {
        reader,
        _writer: write,
        session_id,
    }
}

async fn read_ui_push(reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> Value {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("timed out waiting for UI push")
        .expect("read UI push");
    serde_json::from_str(line.trim()).expect("parse UI push JSON")
}

#[tokio::test]
async fn interactive_secret_approval_covers_six_scopes_dedup_settlement_and_validation() {
    let root = tempdir().expect("temporary directory");
    let project = root.path().join("project");
    let home = root.path().join("home");
    std::fs::create_dir_all(project.join(".agent-sandbox/packages")).expect("create project dirs");
    std::fs::create_dir_all(home.join(".config/agent-sandbox/packages")).expect("create home dirs");

    let mut args = test_args(root.path());
    args.interactive_approval = true;
    args.approval_timeout = Duration::from_secs(10);

    let host_socket = args.host_socket.clone();
    let store = Arc::new(PolicyStore::new(args));
    let launcher_pid = read_proc_ppid(std::process::id()).expect("parent pid of test process");
    let owner_uid = std::fs::metadata("/proc/self")
        .map(|meta| std::os::unix::fs::MetadataExt::uid(&meta))
        .expect("uid of current process");

    let server = tokio::spawn(PolicyServer::new(Arc::clone(&store)).run());
    let reg = rpc_line(
        &host_socket,
        &serde_json::json!({
            "op": "register_sandbox",
            "session_id": "sandbox-codex",
            "package": "codex",
            "launcher_pid": launcher_pid,
        })
        .to_string(),
    )
    .await;
    assert_eq!(reg["ok"], true);

    let RegisteredUi {
        reader: mut ui_reader,
        _writer: _ui_writer,
        session_id: ui_session_id,
    } = connect_and_register_ui(&host_socket, &project, &home, "sandbox-codex").await;

    // 1. Missing PID fails closed when undecided in interactive mode.
    let no_pid_reply = rpc_line(
        &host_socket,
        &serde_json::json!({
            "op": "check_secret",
            "request": {
                "partition": "host",
                "collection": "kdewallet",
                "is_default_collection": true,
                "attributes": { "service": "no-pid" },
                "label": "No PID",
                "access": "read",
                "operation": "get_secret"
            },
            "ctx": {
                "cwd": project,
                "home": home,
                "project_root": project,
                "sandbox_session_id": "sandbox-codex"
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(no_pid_reply["result"], "secret_check");
    assert_eq!(no_pid_reply["allowed"], false);
    assert_eq!(no_pid_reply["source"], "blocked");

    // 2. Concurrent identical requests deduplicate to ONE UiPush, invalid
    //    target edits are rejected while keeping pending alive, and a valid
    //    Once approval resolves both waiters.
    let approval_ctx = ResolvedRequestContext {
        paths: SandboxPaths::from_wire(
            Some(project.clone()),
            Some(home.clone()),
            Some(project.clone()),
        ),
        // No pid: a prompt freezes the requester's agent scope and fails
        // closed for a pid outside one, such as the test runner.
        ids: ProcessIds::from_options(None, Some(owner_uid)),
        sandbox_session_id: Some("sandbox-codex".into()),
        package: Some("codex".into()),
    };

    let dedup_req = SecretRequest {
        partition: SecretPartition::Host,
        collection: "kdewallet".into(),
        is_default_collection: true,
        attributes: BTreeMap::from([("service".into(), "dedup-svc".into())]),
        label: "Dedup Secret".into(),
        access: SecretAccess::Read,
        operation: SecretOperation::GetSecret,
        replace: false,
        batch: None,
    };

    let w1 = tokio::spawn({
        let store = Arc::clone(&store);
        let req = dedup_req.clone();
        let ctx = approval_ctx.clone();
        async move { store.request_secret_approval(req, ctx).await }
    });
    let push = read_ui_push(&mut ui_reader).await;
    assert_eq!(push["type"], "secret_request");
    let pending_id = push["id"].as_str().expect("pending id").to_owned();

    // Launch a second identical waiter while the first is pending.
    let w2 = tokio::spawn({
        let store = Arc::clone(&store);
        let req = dedup_req.clone();
        let ctx = approval_ctx.clone();
        async move { store.request_secret_approval(req, ctx).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Status exposes PendingSummary::Secret.
    let status = rpc_line(
        &host_socket,
        &serde_json::json!({
            "op": "status",
            "ctx": { "cwd": project, "home": home, "project_root": project }
        })
        .to_string(),
    )
    .await;
    let pending_list = status["pending"].as_array().expect("pending array");
    assert_eq!(pending_list.len(), 1);
    assert_eq!(pending_list[0]["kind"], "secret");
    assert_eq!(pending_list[0]["id"], pending_id);

    // Invalid targets (cross-partition, empty-selector host allow, reserved
    // attribute, non-covering selector) must fail and preserve pending.
    for bad_target in [
        serde_json::json!({
            "kind": "secret",
            "target": {
                "partition": "own_package",
                "collection": "default",
                "attributes": { "service": "dedup-svc" },
                "access": "read"
            }
        }),
        serde_json::json!({
            "kind": "secret",
            "target": {
                "partition": "host",
                "collection": "default",
                "attributes": {},
                "access": "read"
            }
        }),
        serde_json::json!({
            "kind": "secret",
            "target": {
                "partition": "host",
                "collection": "default",
                "attributes": { "agent-sandbox:package": "codex" },
                "access": "read"
            }
        }),
        serde_json::json!({
            "kind": "secret",
            "target": {
                "partition": "host",
                "collection": "default",
                "attributes": { "service": "other-svc" },
                "access": "read"
            }
        }),
    ] {
        let bad = rpc_line(
            &host_socket,
            &serde_json::json!({
                "op": "approve",
                "id": pending_id,
                "scope": "session",
                "session_id": ui_session_id,
                "target": bad_target,
                "ctx": { "cwd": project, "home": home, "project_root": project }
            })
            .to_string(),
        )
        .await;
        assert_eq!(
            bad["result"], "error",
            "expected rejection for {bad_target}"
        );
    }

    // Valid Once approval resolves both deduplicated waiters without writing
    // any policy file.
    let once_reply = rpc_line(
        &host_socket,
        &serde_json::json!({
            "op": "approve",
            "id": pending_id,
            "scope": "once",
            "ctx": { "cwd": project, "home": home, "project_root": project }
        })
        .to_string(),
    )
    .await;
    assert_eq!(once_reply["ok"], true);
    assert_eq!(once_reply["scope"], "once");

    let r1 = w1.await.expect("w1 join");
    let r2 = w2.await.expect("w2 join");
    assert!(r1.verdict.allowed);
    assert_eq!(
        r1.verdict.source,
        VerdictSource::Scope(agent_sandbox_core::ApprovalScope::Once)
    );
    assert!(r2.verdict.allowed);
    assert_eq!(
        r2.verdict.source,
        VerdictSource::Scope(agent_sandbox_core::ApprovalScope::Once)
    );

    // 3. Sibling settlement + Session scope: queue two distinct own_package
    //    requests, approve the first with broad own_package All at Session
    //    scope, and verify the sibling resolves automatically!
    let make_own_req = |svc: &str| SecretRequest {
        partition: SecretPartition::OwnPackage,
        collection: "kdewallet".into(),
        is_default_collection: true,
        attributes: BTreeMap::from([("service".into(), svc.into())]),
        label: svc.into(),
        access: SecretAccess::Write,
        operation: SecretOperation::CreateItem,
        replace: true,
        batch: None,
    };

    let own1 = tokio::spawn({
        let store = Arc::clone(&store);
        let req = make_own_req("own-a");
        let ctx = approval_ctx.clone();
        async move { store.request_secret_approval(req, ctx).await }
    });
    let push_own1 = read_ui_push(&mut ui_reader).await;
    let own1_id = push_own1["id"].as_str().expect("own1 id").to_owned();

    let own2 = tokio::spawn({
        let store = Arc::clone(&store);
        let req = make_own_req("own-b");
        let ctx = approval_ctx.clone();
        async move { store.request_secret_approval(req, ctx).await }
    });
    let _push_own2 = read_ui_push(&mut ui_reader).await;

    let session_approve = rpc_line(
        &host_socket,
        &serde_json::json!({
            "op": "approve",
            "id": own1_id,
            "scope": "session",
            "session_id": ui_session_id,
            "target": {
                "kind": "secret",
                "target": {
                    "partition": "own_package",
                    "collection": "default",
                    "attributes": {},
                    "access": "all"
                }
            },
            "ctx": { "cwd": project, "home": home, "project_root": project }
        })
        .to_string(),
    )
    .await;
    assert_eq!(session_approve["ok"], true);
    assert_eq!(session_approve["scope"], "session");

    let own1_res = own1.await.expect("own1 join");
    let own2_res = own2.await.expect("own2 join");
    assert!(own1_res.verdict.allowed);
    assert!(own2_res.verdict.allowed);
    assert_eq!(
        own2_res.verdict.source,
        VerdictSource::Scope(agent_sandbox_core::ApprovalScope::Session)
    );

    // Subsequent check_secret in the same session hits the session allow
    // bucket immediately without prompting or freezing.
    let session_hit = store
        .check_secret(make_own_req("own-c"), approval_ctx.clone())
        .await;
    assert!(session_hit.verdict.allowed);
    assert_eq!(
        session_hit.verdict.source,
        VerdictSource::Scope(agent_sandbox_core::ApprovalScope::Session)
    );

    // 4. Persistent scopes: project_package, project, global_package, global.
    struct ScopeCase {
        scope: &'static str,
        service: &'static str,
        expected_path: PathBuf,
    }

    for case in [
        ScopeCase {
            scope: "project_package",
            service: "svc-proj-pkg",
            expected_path: project.join(".agent-sandbox/packages/codex.json"),
        },
        ScopeCase {
            scope: "project",
            service: "svc-proj",
            expected_path: project.join(".agent-sandbox/policy.json"),
        },
        ScopeCase {
            scope: "global_package",
            service: "svc-glob-pkg",
            expected_path: home.join(".config/agent-sandbox/packages/codex.json"),
        },
        ScopeCase {
            scope: "global",
            service: "svc-glob",
            expected_path: home.join(".config/agent-sandbox/policy.json"),
        },
    ] {
        let req = SecretRequest {
            partition: SecretPartition::Host,
            collection: "kdewallet".into(),
            is_default_collection: true,
            attributes: BTreeMap::from([("service".into(), case.service.into())]),
            label: case.service.into(),
            access: SecretAccess::Read,
            operation: SecretOperation::GetSecret,
            replace: false,
            batch: None,
        };

        let waiter = tokio::spawn({
            let store = Arc::clone(&store);
            let req = req.clone();
            let ctx = approval_ctx.clone();
            async move { store.request_secret_approval(req, ctx).await }
        });
        let p = read_ui_push(&mut ui_reader).await;
        let id = p["id"].as_str().expect("pending id").to_owned();

        let approved = rpc_line(
            &host_socket,
            &serde_json::json!({
                "op": "approve",
                "id": id,
                "scope": case.scope,
                "comment": format!("allow {}", case.service),
                "ctx": { "cwd": project, "home": home, "project_root": project }
            })
            .to_string(),
        )
        .await;
        assert_eq!(
            approved["ok"], true,
            "scope {} failed: {approved}",
            case.scope
        );
        assert_eq!(approved["scope"], case.scope);

        let reply = waiter.await.expect("waiter join");
        assert!(reply.verdict.allowed);
        assert_eq!(reply.verdict.source.to_string(), case.scope);
        assert!(
            case.expected_path.exists(),
            "expected persisted file {}",
            case.expected_path.display()
        );
        let persisted = agent_sandbox_core::load_policy(&case.expected_path, Some(&home), None);
        assert!(
            persisted.secrets.allow.iter().any(|rule| {
                rule.target.attributes.get("service").map(String::as_str) == Some(case.service)
            }),
            "expected persisted rule for {} in {}",
            case.service,
            case.expected_path.display()
        );

        // Fresh check_secret now matches the persisted policy layer.
        let check_hit = store.check_secret(req, approval_ctx.clone()).await;
        assert!(check_hit.verdict.allowed);
    }

    // 5. Upserting Write on the same project_package key unions Read + Write
    //    into ReadWrite atomically.
    let write_req = SecretRequest {
        partition: SecretPartition::Host,
        collection: "kdewallet".into(),
        is_default_collection: true,
        attributes: BTreeMap::from([("service".into(), "svc-proj-pkg".into())]),
        label: "svc-proj-pkg".into(),
        access: SecretAccess::Write,
        operation: SecretOperation::SetSecret,
        replace: false,
        batch: None,
    };

    let waiter = tokio::spawn({
        let store = Arc::clone(&store);
        let req = write_req.clone();
        let ctx = approval_ctx.clone();
        async move { store.request_secret_approval(req, ctx).await }
    });
    let p = read_ui_push(&mut ui_reader).await;
    let id = p["id"].as_str().expect("pending id").to_owned();
    let approved = rpc_line(
        &host_socket,
        &serde_json::json!({
            "op": "approve",
            "id": id,
            "scope": "project_package",
            "ctx": { "cwd": project, "home": home, "project_root": project }
        })
        .to_string(),
    )
    .await;
    assert_eq!(approved["ok"], true);
    let reply = waiter.await.expect("waiter join");
    assert!(reply.verdict.allowed);

    let proj_pkg_policy = agent_sandbox_core::load_policy(
        &project.join(".agent-sandbox/packages/codex.json"),
        Some(&home),
        None,
    );
    assert_eq!(proj_pkg_policy.secrets.allow.len(), 1);
    assert_eq!(
        proj_pkg_policy.secrets.allow[0].target.access,
        SecretAccess::ReadWrite
    );

    server.abort();
}

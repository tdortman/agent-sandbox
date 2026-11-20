//! Integration tests for the Secret Service mediator in `dbus-proxy`.
//!
//! Spins up a real local `dbus-daemon`, a fake `org.freedesktop.secrets`
//! service simulating KWallet/KeePassXC quirks (sequential integer item paths,
//! prompt signals, and an extra internal interface on the same `:1.x` owner),
//! a mock `policyd` Unix socket, and the real `agent_sandbox_dbus_proxy::run`
//! relay.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use agent_sandbox_core::{
    DbusBus, RequestContext, RpcReply, RpcRequest, SandboxPackageReply,
};
use crate::{RelayConfig, run_for_test};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
    sync::Mutex,
    task::JoinHandle,
};
use zbus::{
    Connection, MatchRule, MessageStream,
    connection::Builder,
    message::{Message, Type},
    zvariant::{OwnedObjectPath, OwnedValue, Type as ZType, Value},
};

const SECRETS_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const COLL_PATH: &str = "/org/freedesktop/secrets/collection/kdewallet";
const DEFAULT_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";
const ITEM_HOST: &str = "/org/freedesktop/secrets/collection/kdewallet/1";
const ITEM_CODEX: &str = "/org/freedesktop/secrets/collection/kdewallet/2";
const ITEM_OMP: &str = "/org/freedesktop/secrets/collection/kdewallet/3";
const SESSION_PATH: &str = "/org/freedesktop/secrets/session/s1";
const PROMPT_TRACKED: &str = "/org/freedesktop/secrets/prompt/p1";
const PROMPT_UNTRACKED: &str = "/org/freedesktop/secrets/prompt/p_other";

fn owned_str(s: &str) -> OwnedValue {
    OwnedValue::try_from(Value::from(s)).expect("owned string value")
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct OpenSessionArgs {
    algorithm: String,
    input: OwnedValue,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct OpenSessionReply {
    output: OwnedValue,
    result: OwnedObjectPath,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct ServiceSearchItemsReply {
    unlocked: Vec<OwnedObjectPath>,
    locked: Vec<OwnedObjectPath>,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct UnlockReply {
    unlocked: Vec<OwnedObjectPath>,
    prompt: OwnedObjectPath,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct PropertiesGetArgs {
    interface: String,
    property: String,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct PropertiesSetArgs {
    interface: String,
    property: String,
    value: OwnedValue,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct PropertiesChangedArgs {
    interface: String,
    changed: HashMap<String, OwnedValue>,
    invalidated: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct PromptCompletedArgs {
    dismissed: bool,
    result: OwnedValue,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct RawSecret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct CreateItemArgs {
    properties: HashMap<String, OwnedValue>,
    secret: RawSecret,
    replace: bool,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct GetSecretsArgs {
    items: Vec<OwnedObjectPath>,
    session: OwnedObjectPath,
}

struct LocalDbusDaemon {
    child: Child,
    address: String,
    _dir: TempDir,
}

impl LocalDbusDaemon {
    async fn start() -> Self {
        let dir = tempfile::tempdir().expect("create temp dir for dbus-daemon");
        let sock_path = dir.path().join("bus.sock");
        let conf_path = dir.path().join("bus.conf");
        let address = format!("unix:path={}", sock_path.display());

        let conf = format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>{address}</listen>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#
        );
        std::fs::write(&conf_path, conf).expect("write dbus-daemon config");

        let child = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", conf_path.display()))
            .arg("--nofork")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn local dbus-daemon");

        for _ in 0..100 {
            if sock_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(sock_path.exists(), "dbus-daemon socket never appeared");

        Self {
            child,
            address,
            _dir: dir,
        }
    }
}

impl Drop for LocalDbusDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct MockPolicyd {
    socket_path: PathBuf,
    check_dbus_targets: Arc<Mutex<Vec<agent_sandbox_core::DbusTarget>>>,
    resolve_package_calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl MockPolicyd {
    fn start(dir: &Path, package: Option<&str>) -> Self {
        let socket_path = dir.join(format!(
            "policyd-{}.sock",
            package.unwrap_or("unattributed")
        ));
        let listener = UnixListener::bind(&socket_path).expect("bind mock policyd socket");
        let check_dbus_targets = Arc::new(Mutex::new(Vec::new()));
        let resolve_package_calls = Arc::new(AtomicUsize::new(0));
        let package = package.map(str::to_owned);

        let check_targets = Arc::clone(&check_dbus_targets);
        let resolve_counter = Arc::clone(&resolve_package_calls);

        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let package = package.clone();
                let check_targets = Arc::clone(&check_targets);
                let resolve_counter = Arc::clone(&resolve_counter);

                tokio::spawn(async move {
                    let (read, mut write) = stream.into_split();
                    let mut reader = BufReader::new(read);
                    let mut line = String::new();

                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            line.clear();
                            continue;
                        }
                        let req: RpcRequest =
                            serde_json::from_str(trimmed).expect("valid RPC request");
                        let reply = match req {
                            RpcRequest::ResolveSandboxPackage { .. } => {
                                resolve_counter.fetch_add(1, Ordering::SeqCst);
                                RpcReply::SandboxPackage(SandboxPackageReply::ok(package.clone()))
                            }
                            RpcRequest::CheckDbus { target, .. } => {
                                check_targets.lock().await.push(target.clone());
                                RpcReply::DbusCheck(agent_sandbox_core::DbusCheckReply::denied(
                                    agent_sandbox_core::VerdictSource::Blocked,
                                    target,
                                ))
                            }
                            other => panic!("unexpected RPC request in Ticket 11 test: {other:?}"),
                        };
                        let encoded =
                            serde_json::to_string(&reply).expect("serialize RPC reply");
                        let _ = write.write_all(format!("{encoded}\n").as_bytes()).await;
                        let _ = write.flush().await;
                        line.clear();
                    }
                });
            }
        });

        Self {
            socket_path,
            check_dbus_targets,
            resolve_package_calls,
            task,
        }
    }
}

impl Drop for MockPolicyd {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct FakeItem {
    attributes: HashMap<String, String>,
    label: String,
}

struct FakeSecretsService {
    connection: Connection,
    unique_name: String,
    task: JoinHandle<()>,
}

impl FakeSecretsService {
    async fn start(bus_address: &str) -> Self {
        let stream = Builder::address(bus_address)
            .expect("valid bus address")
            .build_message_stream()
            .await
            .expect("connect fake secret service");
        let connection = Connection::from(&stream);
        let unique_name = connection
            .unique_name()
            .expect("fake service unique name")
            .to_string();

        // Claim org.freedesktop.secrets on the test bus.
        let reply = connection
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "RequestName",
                &(SECRETS_NAME, 0_u32),
            )
            .await
            .expect("RequestName org.freedesktop.secrets");
        let code: u32 = reply.body().deserialize().expect("RequestName code");
        assert_eq!(code, 1, "expected primary owner for org.freedesktop.secrets");

        let items = Arc::new(Mutex::new(HashMap::from([
            (
                ITEM_HOST.to_owned(),
                FakeItem {
                    attributes: HashMap::from([("service".to_owned(), "gh:github.com".to_owned())]),
                    label: "Host GitHub Token".to_owned(),
                },
            ),
            (
                ITEM_CODEX.to_owned(),
                FakeItem {
                    attributes: HashMap::from([
                        ("service".to_owned(), "gh:github.com".to_owned()),
                        ("agent-sandbox:package".to_owned(), "codex".to_owned()),
                    ]),
                    label: "Codex Token".to_owned(),
                },
            ),
            (
                ITEM_OMP.to_owned(),
                FakeItem {
                    attributes: HashMap::from([
                        ("service".to_owned(), "gh:github.com".to_owned()),
                        ("agent-sandbox:package".to_owned(), "omp".to_owned()),
                    ]),
                    label: "Omp Token".to_owned(),
                },
            ),
        ])));

        let conn_for_task = connection.clone();
        let task = tokio::spawn(async move {
            let mut stream = stream;
            while let Some(Ok(msg)) = stream.next().await {
                if msg.message_type() != Type::MethodCall {
                    continue;
                }
                handle_fake_service_call(&conn_for_task, &items, &msg).await;
            }
        });

        Self {
            connection,
            unique_name,
            task,
        }
    }

    async fn emit_signal<B: Serialize + ZType + Sync>(
        &self,
        path: &str,
        interface: &str,
        member: &str,
        body: &B,
    ) {
        let sig = Message::signal(path, interface, member)
            .expect("signal builder")
            .build(body)
            .expect("build signal");
        self.connection.send(&sig).await.expect("send signal");
    }
}

impl Drop for FakeSecretsService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle_fake_service_call(
    conn: &Connection,
    items: &Arc<Mutex<HashMap<String, FakeItem>>>,
    msg: &Message,
) {
    let header = msg.header();
    let iface = header.interface().map_or_default(|i| i.as_str());
    let member = header.member().map_or_default(|m| m.as_str());
    let path = header.path().map_or_default(|p| p.as_str());

    // Return order deliberately puts Host first, Omp second, Codex third so
    // the mediator must both filter Omp out and reorder Codex ahead of Host!
    let all_item_paths = || {
        vec![
            OwnedObjectPath::try_from(ITEM_HOST).expect("host path"),
            OwnedObjectPath::try_from(ITEM_OMP).expect("omp path"),
            OwnedObjectPath::try_from(ITEM_CODEX).expect("codex path"),
        ]
    };

    match (iface, member) {
        ("org.freedesktop.DBus.Peer", "Ping") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&())
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.DBus.Introspectable", "Introspect") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&("<node/>",))
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Service", "OpenSession") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&OpenSessionReply {
                    output: owned_str(""),
                    result: OwnedObjectPath::try_from(SESSION_PATH).expect("session path"),
                })
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Session", "Close") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&())
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Service", "ReadAlias") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&(OwnedObjectPath::try_from(COLL_PATH).expect("coll path"),))
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Service", "SearchItems") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&ServiceSearchItemsReply {
                    unlocked: all_item_paths(),
                    locked: Vec::new(),
                })
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Collection", "SearchItems") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&(all_item_paths(),))
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Service", "Unlock") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&UnlockReply {
                    unlocked: Vec::new(),
                    prompt: OwnedObjectPath::try_from(PROMPT_TRACKED).expect("prompt path"),
                })
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Prompt", "Prompt") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&())
                .expect("build");
            let _ = conn.send(&reply).await;

            // Emit Prompt.Completed on the prompted object path.
            let sig = Message::signal(path, "org.freedesktop.Secret.Prompt", "Completed")
                .expect("signal")
                .build(&PromptCompletedArgs {
                    dismissed: false,
                    result: OwnedValue::try_from(Value::from(vec![
                        OwnedObjectPath::try_from(COLL_PATH).expect("coll"),
                    ]))
                    .expect("owned object path array"),
                })
                .expect("build signal");
            let _ = conn.send(&sig).await;
        }

        ("org.freedesktop.Secret.Prompt", "Dismiss") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&())
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.DBus.Properties", "Get") => {
            let args: PropertiesGetArgs = msg.body().deserialize().expect("Properties.Get args");
            match (args.interface.as_str(), args.property.as_str()) {
                ("org.freedesktop.Secret.Collection", "Items") => {
                    let val = Value::from(all_item_paths());
                    let reply = Message::method_return(&header)
                        .expect("reply")
                        .build(&val)
                        .expect("build");
                    let _ = conn.send(&reply).await;
                }
                ("org.freedesktop.Secret.Collection", "Label") => {
                    let val = Value::from("kdewallet");
                    let reply = Message::method_return(&header)
                        .expect("reply")
                        .build(&val)
                        .expect("build");
                    let _ = conn.send(&reply).await;
                }
                ("org.freedesktop.Secret.Item", "Attributes") => {
                    let map = items.lock().await;
                    if let Some(item) = map.get(path) {
                        let val = Value::from(item.attributes.clone());
                        let reply = Message::method_return(&header)
                            .expect("reply")
                            .build(&val)
                            .expect("build");
                        let _ = conn.send(&reply).await;
                    } else {
                        let err = Message::error(&header, "org.freedesktop.Secret.Error.NoSuchObject")
                            .expect("err")
                            .build(&("no such item",))
                            .expect("build");
                        let _ = conn.send(&err).await;
                    }
                }
                ("org.freedesktop.Secret.Item", "Label") => {
                    let map = items.lock().await;
                    if let Some(item) = map.get(path) {
                        let val = Value::from(item.label.as_str());
                        let reply = Message::method_return(&header)
                            .expect("reply")
                            .build(&val)
                            .expect("build");
                        let _ = conn.send(&reply).await;
                    } else {
                        let err = Message::error(&header, "org.freedesktop.Secret.Error.NoSuchObject")
                            .expect("err")
                            .build(&("no such item",))
                            .expect("build");
                        let _ = conn.send(&err).await;
                    }
                }
                _ => {
                    let err = Message::error(&header, "org.freedesktop.DBus.Error.InvalidArgs")
                        .expect("err")
                        .build(&("unknown property",))
                        .expect("build");
                    let _ = conn.send(&err).await;
                }
            }
        }

        ("org.freedesktop.DBus.Properties", "GetAll") => {
            let iface_arg: String = msg.body().deserialize().expect("Properties.GetAll args");
            let mut props: HashMap<String, OwnedValue> = HashMap::new();
            match iface_arg.as_str() {
                "org.freedesktop.Secret.Collection" => {
                    props.insert("Label".to_owned(), owned_str("kdewallet"));
                    props.insert(
                        "Items".to_owned(),
                        OwnedValue::try_from(Value::from(all_item_paths())).expect("Items value"),
                    );
                }
                "org.freedesktop.Secret.Item" => {
                    let map = items.lock().await;
                    if let Some(item) = map.get(path) {
                        props.insert("Label".to_owned(), owned_str(&item.label));
                        props.insert(
                            "Attributes".to_owned(),
                            OwnedValue::try_from(Value::from(item.attributes.clone()))
                                .expect("Attributes value"),
                        );
                    }
                }
                _ => {}
            }
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&props)
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        // Extra daemon-internal interface on the same `:1.x` owner that MUST
        // be blocked by the interface allowlist!
        ("org.kde.kwallet.Internal", "MasterSecret") => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&("LEAKED-MASTER-SECRET",))
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        _ => {
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&("SHOULD-NOT-REACH-SERVICE",))
                .expect("build");
            let _ = conn.send(&reply).await;
        }
    }
}

struct StartedRelay {
    socket: PathBuf,
    task: JoinHandle<()>,
}

async fn start_relay(
    dir: &Path,
    name: &str,
    upstream_address: &str,
    policy_socket: &Path,
) -> StartedRelay {
    let listen = dir.join(format!("relay-{name}.sock"));
    let mut config = RelayConfig::new(&listen, upstream_address, policy_socket);
    config.bus = DbusBus::Session;
    config.context = RequestContext {
        sandbox_session_id: Some(format!("session-{name}")),
        ..RequestContext::default()
    };

    let task = tokio::spawn(async move {
        let _ = run_for_test(config).await;
    });

    for _ in 0..100 {
        if listen.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(listen.exists(), "relay socket never appeared");

    StartedRelay {
        socket: listen,
        task,
    }
}

fn assert_access_denied<T: std::fmt::Debug>(result: zbus::Result<T>, context: &str) {
    match result {
        Err(zbus::Error::MethodError(name, _, _)) => {
            assert_eq!(
                name.as_str(),
                "org.freedesktop.DBus.Error.AccessDenied",
                "expected AccessDenied for {context}, got {name}"
            );
        }
        other => panic!("expected AccessDenied for {context}, got {other:?}"),
    }
}

#[tokio::test]
async fn secret_service_trap_isolates_partitions_pins_owner_and_tracks_prompts() {
    let daemon = LocalDbusDaemon::start().await;
    let fake_service = FakeSecretsService::start(&daemon.address).await;
    let owner = fake_service.unique_name.clone();

    let workdir = tempfile::tempdir().expect("create test workdir");
    let codex_policyd = MockPolicyd::start(workdir.path(), Some("codex"));
    let StartedRelay {
        socket: codex_relay_sock,
        task: codex_relay_task,
    } = start_relay(
        workdir.path(),
        "codex",
        &daemon.address,
        &codex_policyd.socket_path,
    )
    .await;

    let codex_addr = format!("unix:path={}", codex_relay_sock.display());
    let codex_stream = Builder::address(codex_addr.as_str())
        .expect("codex relay address")
        .build_message_stream()
        .await
        .expect("connect codex client to relay");
    let codex = Connection::from(&codex_stream);

    // Subscribe to signals from the fake service's unique name.
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(owner.as_str())
        .expect("sender rule")
        .build();
    codex
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "AddMatch",
            &(rule.to_string(),),
        )
        .await
        .expect("AddMatch for secret service signals");

    // 1. Safe operations pass through via both well-known name and pinned `:1.x`.
    let open_reply: OpenSessionReply = codex
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "OpenSession",
            &OpenSessionArgs {
                algorithm: "plain".into(),
                input: owned_str(""),
            },
        )
        .await
        .expect("OpenSession should pass through")
        .body()
        .deserialize()
        .expect("OpenSession reply");
    assert_eq!(open_reply.result.as_str(), SESSION_PATH);

    let alias: OwnedObjectPath = codex
        .call_method(
            Some(owner.as_str()),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "ReadAlias",
            &("default",),
        )
        .await
        .expect("ReadAlias via pinned owner should pass through")
        .body()
        .deserialize()
        .expect("ReadAlias reply");
    assert_eq!(alias.as_str(), COLL_PATH);

    codex
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.DBus.Peer"),
            "Ping",
            &(),
        )
        .await
        .expect("Peer.Ping should pass through");

    let xml: String = codex
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.DBus.Introspectable"),
            "Introspect",
            &(),
        )
        .await
        .expect("Introspect should pass through")
        .body()
        .deserialize()
        .expect("Introspect reply");
    assert!(xml.contains("node"));

    codex
        .call_method(
            Some(SECRETS_NAME),
            SESSION_PATH,
            Some("org.freedesktop.Secret.Session"),
            "Close",
            &(),
        )
        .await
        .expect("Session.Close should pass through");

    // 2. Daemon-internal interface on `:1.x` is blocked via both well-known
    //    and unique owner destinations.
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                SERVICE_PATH,
                Some("org.kde.kwallet.Internal"),
                "MasterSecret",
                &(),
            )
            .await,
        "internal interface via well-known name",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(owner.as_str()),
                SERVICE_PATH,
                Some("org.kde.kwallet.Internal"),
                "MasterSecret",
                &(),
            )
            .await,
        "internal interface via unique owner",
    );

    // 3. Collection-admin and rename ops are unconditionally denied.
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "Lock",
                &(vec![OwnedObjectPath::try_from(COLL_PATH).expect("coll")],),
            )
            .await,
        "Service.Lock",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "CreateCollection",
                &(HashMap::<String, OwnedValue>::new(), ""),
            )
            .await,
        "Service.CreateCollection",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                COLL_PATH,
                Some("org.freedesktop.Secret.Collection"),
                "Delete",
                &(),
            )
            .await,
        "Collection.Delete",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "SetAlias",
                &("default", OwnedObjectPath::try_from(COLL_PATH).expect("coll")),
            )
            .await,
        "Service.SetAlias",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                COLL_PATH,
                Some("org.freedesktop.DBus.Properties"),
                "Set",
                &PropertiesSetArgs {
                    interface: "org.freedesktop.Secret.Collection".into(),
                    property: "Label".into(),
                    value: owned_str("Renamed"),
                },
            )
            .await,
        "Properties.Set(Collection, Label)",
    );

    // 4. Secret-bearing operations fail closed in Ticket 11 (until Ticket 12).
    assert_access_denied(
        codex
            .call_method(
                Some(owner.as_str()),
                ITEM_CODEX,
                Some("org.freedesktop.Secret.Item"),
                "GetSecret",
                &(OwnedObjectPath::try_from(SESSION_PATH).expect("session"),),
            )
            .await,
        "Item.GetSecret fail-closed",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "GetSecrets",
                &GetSecretsArgs {
                    items: vec![OwnedObjectPath::try_from(ITEM_CODEX).expect("item")],
                    session: OwnedObjectPath::try_from(SESSION_PATH).expect("session"),
                },
            )
            .await,
        "Service.GetSecrets fail-closed",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                COLL_PATH,
                Some("org.freedesktop.Secret.Collection"),
                "CreateItem",
                &CreateItemArgs {
                    properties: HashMap::new(),
                    secret: RawSecret {
                        session: OwnedObjectPath::try_from(SESSION_PATH).expect("session"),
                        parameters: Vec::new(),
                        value: b"secret".to_vec(),
                        content_type: "text/plain".into(),
                    },
                    replace: false,
                },
            )
            .await,
        "Collection.CreateItem fail-closed",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                ITEM_CODEX,
                Some("org.freedesktop.Secret.Item"),
                "SetSecret",
                &(RawSecret {
                    session: OwnedObjectPath::try_from(SESSION_PATH).expect("session"),
                    parameters: Vec::new(),
                    value: b"new".to_vec(),
                    content_type: "text/plain".into(),
                },),
            )
            .await,
        "Item.SetSecret fail-closed",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                ITEM_CODEX,
                Some("org.freedesktop.Secret.Item"),
                "Delete",
                &(),
            )
            .await,
        "Item.Delete fail-closed",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                ITEM_CODEX,
                Some("org.freedesktop.DBus.Properties"),
                "Set",
                &PropertiesSetArgs {
                    interface: "org.freedesktop.Secret.Item".into(),
                    property: "Label".into(),
                    value: owned_str("New Label"),
                },
            )
            .await,
        "Properties.Set(Item, Label) fail-closed",
    );

    // 5. Discovery hides omp's item and sorts codex's package secret AHEAD of
    //    the host secret across all four discovery surfaces.
    let expected_codex_order = vec![ITEM_CODEX.to_owned(), ITEM_HOST.to_owned()];

    let svc_search: ServiceSearchItemsReply = codex
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "SearchItems",
            &(HashMap::from([("service", "gh:github.com")]),),
        )
        .await
        .expect("Service.SearchItems")
        .body()
        .deserialize()
        .expect("Service.SearchItems reply");
    let svc_paths: Vec<String> = svc_search
        .unlocked
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect();
    assert_eq!(svc_paths, expected_codex_order);

    let coll_search: Vec<OwnedObjectPath> = codex
        .call_method(
            Some(SECRETS_NAME),
            COLL_PATH,
            Some("org.freedesktop.Secret.Collection"),
            "SearchItems",
            &(HashMap::from([("service", "gh:github.com")]),),
        )
        .await
        .expect("Collection.SearchItems")
        .body()
        .deserialize()
        .expect("Collection.SearchItems reply");
    let coll_paths: Vec<String> = coll_search
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect();
    assert_eq!(coll_paths, expected_codex_order);

    let items_prop_raw: OwnedValue = codex
        .call_method(
            Some(SECRETS_NAME),
            COLL_PATH,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &PropertiesGetArgs {
                interface: "org.freedesktop.Secret.Collection".into(),
                property: "Items".into(),
            },
        )
        .await
        .expect("Properties.Get(Collection, Items)")
        .body()
        .deserialize()
        .expect("Items property reply");
    let items_prop: Vec<OwnedObjectPath> =
        Vec::try_from(items_prop_raw).expect("decode Items array");
    assert_eq!(
        items_prop
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect::<Vec<_>>(),
        expected_codex_order
    );

    let all_props: HashMap<String, OwnedValue> = codex
        .call_method(
            Some(SECRETS_NAME),
            COLL_PATH,
            Some("org.freedesktop.DBus.Properties"),
            "GetAll",
            &("org.freedesktop.Secret.Collection",),
        )
        .await
        .expect("Properties.GetAll(Collection)")
        .body()
        .deserialize()
        .expect("GetAll reply");
    let all_items: Vec<OwnedObjectPath> =
        Vec::try_from(all_props["Items"].try_clone().expect("clone Items"))
            .expect("decode GetAll Items");
    assert_eq!(
        all_items
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect::<Vec<_>>(),
        expected_codex_order
    );

    // Item Properties.Get/GetAll allow own & host, deny other package.
    let codex_label: OwnedValue = codex
        .call_method(
            Some(SECRETS_NAME),
            ITEM_CODEX,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &PropertiesGetArgs {
                interface: "org.freedesktop.Secret.Item".into(),
                property: "Label".into(),
            },
        )
        .await
        .expect("Properties.Get on own item")
        .body()
        .deserialize()
        .expect("Label value");
    assert_eq!(String::try_from(codex_label).expect("string"), "Codex Token");

    let host_props: HashMap<String, OwnedValue> = codex
        .call_method(
            Some(SECRETS_NAME),
            ITEM_HOST,
            Some("org.freedesktop.DBus.Properties"),
            "GetAll",
            &("org.freedesktop.Secret.Item",),
        )
        .await
        .expect("Properties.GetAll on host item")
        .body()
        .deserialize()
        .expect("host item props");
    assert!(host_props.contains_key("Attributes"));

    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                ITEM_OMP,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &PropertiesGetArgs {
                    interface: "org.freedesktop.Secret.Item".into(),
                    property: "Label".into(),
                },
            )
            .await,
        "Properties.Get on omp item",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                ITEM_OMP,
                Some("org.freedesktop.DBus.Properties"),
                "GetAll",
                &("org.freedesktop.Secret.Item",),
            )
            .await,
        "Properties.GetAll on omp item",
    );

    // 6. Service.Unlock and connection-local Prompt lifecycle.
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "Unlock",
                &(vec![OwnedObjectPath::try_from(ITEM_OMP).expect("omp")],),
            )
            .await,
        "Unlock on omp item",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                PROMPT_UNTRACKED,
                Some("org.freedesktop.Secret.Prompt"),
                "Prompt",
                &("",),
            )
            .await,
        "Prompt.Prompt on untracked prompt",
    );

    let unlock_reply: UnlockReply = codex
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "Unlock",
            &(vec![OwnedObjectPath::try_from(DEFAULT_ALIAS_PATH).expect("alias")],),
        )
        .await
        .expect("Unlock on default alias")
        .body()
        .deserialize()
        .expect("Unlock reply");
    assert_eq!(unlock_reply.prompt.as_str(), PROMPT_TRACKED);

    // Emit an untracked Prompt.Completed (must be dropped), then trigger the
    // tracked prompt (must succeed and deliver Prompt.Completed, then untrack).
    fake_service
        .emit_signal(
            PROMPT_UNTRACKED,
            "org.freedesktop.Secret.Prompt",
            "Completed",
            &PromptCompletedArgs {
                dismissed: true,
                result: owned_str(""),
            },
        )
        .await;

    codex
        .call_method(
            Some(SECRETS_NAME),
            PROMPT_TRACKED,
            Some("org.freedesktop.Secret.Prompt"),
            "Prompt",
            &("",),
        )
        .await
        .expect("Prompt.Prompt on tracked prompt");

    let mut codex_stream = codex_stream;
    let completed = next_signal(&mut codex_stream, "Completed").await;
    assert_eq!(
        completed.header().path().map(|p| p.as_str()),
        Some(PROMPT_TRACKED),
        "only the tracked Prompt.Completed should reach the client"
    );

    // After Prompt.Completed removed the prompt path, re-calling Prompt fails.
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                PROMPT_TRACKED,
                Some("org.freedesktop.Secret.Prompt"),
                "Prompt",
                &("",),
            )
            .await,
        "Prompt.Prompt after completion",
    );

    // 7. Upstream signal filtering: omp ItemCreated & Item PropertiesChanged
    //    are dropped, codex ItemCreated & PropertiesChanged are forwarded, and
    //    Collection PropertiesChanged filters & orders `Items`.
    fake_service
        .emit_signal(
            COLL_PATH,
            "org.freedesktop.Secret.Collection",
            "ItemCreated",
            &(OwnedObjectPath::try_from(ITEM_OMP).expect("omp"),),
        )
        .await;
    fake_service
        .emit_signal(
            COLL_PATH,
            "org.freedesktop.Secret.Collection",
            "ItemCreated",
            &(OwnedObjectPath::try_from(ITEM_CODEX).expect("codex"),),
        )
        .await;

    let item_created = next_signal(&mut codex_stream, "ItemCreated").await;
    let created_path: OwnedObjectPath = item_created.body().deserialize().expect("ItemCreated path");
    assert_eq!(
        created_path.as_str(),
        ITEM_CODEX,
        "foreign package ItemCreated must be dropped"
    );

    fake_service
        .emit_signal(
            ITEM_OMP,
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &PropertiesChangedArgs {
                interface: "org.freedesktop.Secret.Item".into(),
                changed: HashMap::from([("Label".to_owned(), owned_str("Omp Updated"))]),
                invalidated: Vec::new(),
            },
        )
        .await;
    fake_service
        .emit_signal(
            ITEM_CODEX,
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &PropertiesChangedArgs {
                interface: "org.freedesktop.Secret.Item".into(),
                changed: HashMap::from([("Label".to_owned(), owned_str("Codex Updated"))]),
                invalidated: Vec::new(),
            },
        )
        .await;

    let item_prop_changed = next_signal(&mut codex_stream, "PropertiesChanged").await;
    assert_eq!(
        item_prop_changed.header().path().map(|p| p.as_str()),
        Some(ITEM_CODEX),
        "foreign package Item PropertiesChanged must be dropped"
    );

    fake_service
        .emit_signal(
            COLL_PATH,
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &PropertiesChangedArgs {
                interface: "org.freedesktop.Secret.Collection".into(),
                changed: HashMap::from([(
                    "Items".to_owned(),
                    OwnedValue::try_from(Value::from(vec![
                        OwnedObjectPath::try_from(ITEM_HOST).expect("host"),
                        OwnedObjectPath::try_from(ITEM_OMP).expect("omp"),
                        OwnedObjectPath::try_from(ITEM_CODEX).expect("codex"),
                    ]))
                    .expect("Items value"),
                )]),
                invalidated: Vec::new(),
            },
        )
        .await;
    let coll_prop_changed = next_signal(&mut codex_stream, "PropertiesChanged").await;
    let changed_args: PropertiesChangedArgs = coll_prop_changed
        .body()
        .deserialize()
        .expect("Collection PropertiesChanged body");
    let changed_items: Vec<OwnedObjectPath> =
        Vec::try_from(changed_args.changed["Items"].try_clone().expect("clone Items"))
            .expect("decode changed Items");
    assert_eq!(
        changed_items
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect::<Vec<_>>(),
        expected_codex_order,
        "Collection PropertiesChanged must filter other packages and order own-package first"
    );

    // Tracked Prompt.Dismiss succeeds once and untracks the prompt.
    let unlock_again: UnlockReply = codex
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "Unlock",
            &(vec![OwnedObjectPath::try_from(COLL_PATH).expect("coll")],),
        )
        .await
        .expect("second Unlock")
        .body()
        .deserialize()
        .expect("second Unlock reply");
    assert_eq!(unlock_again.prompt.as_str(), PROMPT_TRACKED);
    codex
        .call_method(
            Some(SECRETS_NAME),
            PROMPT_TRACKED,
            Some("org.freedesktop.Secret.Prompt"),
            "Dismiss",
            &(),
        )
        .await
        .expect("Prompt.Dismiss on tracked prompt");
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                PROMPT_TRACKED,
                Some("org.freedesktop.Secret.Prompt"),
                "Dismiss",
                &(),
            )
            .await,
        "Prompt.Dismiss after dismissal",
    );

    // Owner change clears tracked prompts: unlock to register PROMPT_TRACKED,
    // drop the first fake service and spin up a new owner, then verify the old
    // prompt path is no longer accepted.
    let unlock_before_restart: UnlockReply = codex
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "Unlock",
            &(vec![OwnedObjectPath::try_from(COLL_PATH).expect("coll")],),
        )
        .await
        .expect("unlock before restart")
        .body()
        .deserialize()
        .expect("unlock reply");
    assert_eq!(unlock_before_restart.prompt.as_str(), PROMPT_TRACKED);

    drop(fake_service);
    let _replacement_service = FakeSecretsService::start(&daemon.address).await;
    // Give the side-channel watcher a moment to observe NameOwnerChanged.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                PROMPT_TRACKED,
                Some("org.freedesktop.Secret.Prompt"),
                "Prompt",
                &("",),
            )
            .await,
        "Prompt.Prompt after NameOwnerChanged",
    );

    // 8. Verify unattributed caller sees ONLY host secrets (all tagged items
    //    hidden) and ResolveSandboxPackage was cached once per relay.
    assert_eq!(codex_policyd.resolve_package_calls.load(Ordering::SeqCst), 1);
    let codex_dbus_targets = codex_policyd.check_dbus_targets.lock().await;
    assert!(
        codex_dbus_targets.iter().all(|target| {
            target.interface == "org.freedesktop.DBus" && target.member == "NameAcquired"
        }),
        "Secret Service traffic must never fall through to CheckDbus, saw: {codex_dbus_targets:?}"
    );
    drop(codex_dbus_targets);

    let unattr_policyd = MockPolicyd::start(workdir.path(), None);
    let StartedRelay {
        socket: unattr_relay_sock,
        task: unattr_relay_task,
    } = start_relay(
        workdir.path(),
        "unattributed",
        &daemon.address,
        &unattr_policyd.socket_path,
    )
    .await;
    let unattr_addr = format!("unix:path={}", unattr_relay_sock.display());
    let unattr = Builder::address(unattr_addr.as_str())
        .expect("unattr relay address")
        .build()
        .await
        .expect("connect unattr client");

    let unattr_search: ServiceSearchItemsReply = unattr
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "SearchItems",
            &(HashMap::from([("service", "gh:github.com")]),),
        )
        .await
        .expect("unattributed SearchItems")
        .body()
        .deserialize()
        .expect("unattributed SearchItems reply");
    assert_eq!(
        unattr_search
            .unlocked
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>(),
        vec![ITEM_HOST],
        "unattributed caller must not see any package-tagged secrets"
    );
    assert_access_denied(
        unattr
            .call_method(
                Some(SECRETS_NAME),
                ITEM_CODEX,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &PropertiesGetArgs {
                    interface: "org.freedesktop.Secret.Item".into(),
                    property: "Label".into(),
                },
            )
            .await,
        "unattributed Properties.Get on tagged item",
    );
    let unattr_dbus_targets = unattr_policyd.check_dbus_targets.lock().await;
    assert!(
        unattr_dbus_targets.iter().all(|target| {
            target.interface == "org.freedesktop.DBus" && target.member == "NameAcquired"
        }),
        "Secret Service traffic for unattributed caller must never fall through to CheckDbus, \
         saw: {unattr_dbus_targets:?}"
    );
    drop(unattr_dbus_targets);

    codex_relay_task.abort();
    unattr_relay_task.abort();
}

async fn next_signal(stream: &mut MessageStream, expected_member: &str) -> Message {
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(msg)) = stream.next().await {
            if msg.message_type() == Type::Signal
                && msg.header().member().map(|m| m.as_str()) == Some(expected_member)
            {
                return msg;
            }
        }
        panic!("stream closed while waiting for signal {expected_member}");
    })
    .await
    .expect("timed out waiting for upstream signal")
}

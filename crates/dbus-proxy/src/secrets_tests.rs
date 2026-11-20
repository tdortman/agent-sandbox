//! Integration tests for the Secret Service mediator in `dbus-proxy`.
//!
//! Spins up a real local `dbus-daemon`, a fake `org.freedesktop.secrets`
//! service simulating KWallet/KeePassXC quirks (sequential integer item paths,
//! prompt signals, and an extra internal interface on the same `:1.x` owner),
//! a mock `policyd` Unix socket, and the real `agent_sandbox_dbus_proxy::run`
//! relay.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use agent_sandbox_core::{
    DbusBus, RequestContext, RpcReply, RpcRequest, SandboxPackageReply, SecretAccess,
    SecretBatchInfo, SecretCheckReply, SecretOperation, SecretPartition, SecretRequest, SecretRule,
    SecretSection, SecretTarget, VerdictSource,
};
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

use crate::{RelayConfig, run_for_test};

const SECRETS_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const COLL_PATH: &str = "/org/freedesktop/secrets/collection/kdewallet";
const WORK_COLL_PATH: &str = "/org/freedesktop/secrets/collection/work";
const DEFAULT_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";
const WORK_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/work";
const ITEM_HOST: &str = "/org/freedesktop/secrets/collection/kdewallet/1";
const ITEM_CODEX: &str = "/org/freedesktop/secrets/collection/kdewallet/2";
const ITEM_OMP: &str = "/org/freedesktop/secrets/collection/kdewallet/3";
const ITEM_LOCKED: &str = "/org/freedesktop/secrets/collection/kdewallet/4";
const ITEM_UNKNOWN_OBJ: &str = "/org/freedesktop/secrets/collection/kdewallet/998";
const ITEM_MISSING: &str = "/org/freedesktop/secrets/collection/kdewallet/999";
const SESSION_PATH: &str = "/org/freedesktop/secrets/session/s1";
const PROMPT_TRACKED: &str = "/org/freedesktop/secrets/prompt/p1";
const PROMPT_CREATE: &str = "/org/freedesktop/secrets/prompt/p_create";
const PROMPT_DELETE: &str = "/org/freedesktop/secrets/prompt/p_delete";
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ZType)]
struct RawSecret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct SetSecretArgs {
    secret: RawSecret,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct CreateItemArgs {
    properties: HashMap<String, OwnedValue>,
    secret: RawSecret,
    replace: bool,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct CreateItemReply {
    item: OwnedObjectPath,
    prompt: OwnedObjectPath,
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
    check_secret_requests: Arc<Mutex<Vec<SecretRequest>>>,
    rules: Arc<Mutex<SecretSection>>,
    allow_name_acquired: Arc<AtomicBool>,
    fail_check_secret: Arc<AtomicBool>,
    resolve_package_calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl MockPolicyd {
    fn start(dir: &Path, package: Option<&str>) -> Self {
        Self::start_with_rules(dir, package, SecretSection::default())
    }

    fn start_with_rules(dir: &Path, package: Option<&str>, initial_rules: SecretSection) -> Self {
        let socket_path = dir.join(format!(
            "policyd-{}.sock",
            package.unwrap_or("unattributed")
        ));
        let listener = UnixListener::bind(&socket_path).expect("bind mock policyd socket");
        let check_dbus_targets = Arc::new(Mutex::new(Vec::new()));
        let check_secret_requests = Arc::new(Mutex::new(Vec::new()));
        let rules = Arc::new(Mutex::new(initial_rules));
        let allow_name_acquired = Arc::new(AtomicBool::new(false));
        let fail_check_secret = Arc::new(AtomicBool::new(false));
        let resolve_package_calls = Arc::new(AtomicUsize::new(0));
        let package = package.map(str::to_owned);

        let check_targets = Arc::clone(&check_dbus_targets);
        let secret_reqs = Arc::clone(&check_secret_requests);
        let shared_rules = Arc::clone(&rules);
        let shared_allow_name_acquired = Arc::clone(&allow_name_acquired);
        let shared_fail = Arc::clone(&fail_check_secret);
        let resolve_counter = Arc::clone(&resolve_package_calls);

        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let package = package.clone();
                let check_targets = Arc::clone(&check_targets);
                let secret_reqs = Arc::clone(&secret_reqs);
                let shared_rules = Arc::clone(&shared_rules);
                let shared_allow_name_acquired = Arc::clone(&shared_allow_name_acquired);
                let shared_fail = Arc::clone(&shared_fail);
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
                                if shared_allow_name_acquired.load(Ordering::SeqCst)
                                    && target.interface == "org.freedesktop.DBus"
                                    && target.member == "NameAcquired"
                                {
                                    RpcReply::DbusCheck(
                                        agent_sandbox_core::DbusCheckReply::allowed(
                                            VerdictSource::policy(),
                                            target,
                                        ),
                                    )
                                } else {
                                    RpcReply::DbusCheck(agent_sandbox_core::DbusCheckReply::denied(
                                        VerdictSource::Blocked,
                                        target,
                                    ))
                                }
                            }
                            RpcRequest::CheckSecret { request, .. } => {
                                secret_reqs.lock().await.push(request.clone());
                                if shared_fail.load(Ordering::SeqCst) {
                                    RpcReply::Error(agent_sandbox_core::ErrorReply::new(
                                        "simulated policyd failure",
                                    ))
                                } else {
                                    let section = shared_rules.lock().await;
                                    let attributed = package.is_some();
                                    let reply = if section
                                        .deny
                                        .iter()
                                        .any(|rule| rule.matches(&request, attributed))
                                    {
                                        SecretCheckReply::denied(VerdictSource::policy(), request)
                                    } else if section
                                        .allow
                                        .iter()
                                        .any(|rule| rule.matches(&request, attributed))
                                    {
                                        SecretCheckReply::allowed(VerdictSource::policy(), request)
                                    } else {
                                        SecretCheckReply::denied(VerdictSource::Blocked, request)
                                    };
                                    RpcReply::SecretCheck(reply)
                                }
                            }
                            other => panic!("unexpected RPC request in secrets test: {other:?}"),
                        };
                        let encoded = serde_json::to_string(&reply).expect("serialize RPC reply");
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
            check_secret_requests,
            rules,
            allow_name_acquired,
            fail_check_secret,
            resolve_package_calls,
            task,
        }
    }

    async fn take_secret_requests(&self) -> Vec<SecretRequest> {
        let mut guard = self.check_secret_requests.lock().await;
        std::mem::take(&mut *guard)
    }

    async fn set_rules(&self, section: SecretSection) {
        *self.rules.lock().await = section;
    }
}

impl Drop for MockPolicyd {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug, Clone)]
struct FakeItem {
    collection: String,
    attributes: HashMap<String, String>,
    label: String,
    secret: RawSecret,
    locked: bool,
}

struct FakeServiceState {
    items: HashMap<String, FakeItem>,
    item_order: Vec<String>,
    next_id: usize,
    get_secrets_calls: usize,
    properties_set_calls: usize,
}

impl FakeServiceState {
    fn new() -> Self {
        let session = OwnedObjectPath::try_from(SESSION_PATH).expect("session path");
        let items = HashMap::from([
            (ITEM_HOST.to_owned(), FakeItem {
                collection: "kdewallet".to_owned(),
                attributes: HashMap::from([
                    ("service".to_owned(), "gh:github.com".to_owned()),
                    ("Uuid".to_owned(), "host-uuid-1".to_owned()),
                    ("Path".to_owned(), "/Root/GitHub".to_owned()),
                    ("Totp".to_owned(), "otpauth://totp/host".to_owned()),
                    ("xdg:content-type".to_owned(), "text/plain".to_owned()),
                ]),
                label: "Host GitHub Token".to_owned(),
                secret: RawSecret {
                    session: session.clone(),
                    parameters: vec![0x01, 0x02, 0xFE, 0xFF],
                    value: b"host-gh-token-value".to_vec(),
                    content_type: "text/plain; charset=utf8".to_owned(),
                },
                locked: false,
            }),
            (ITEM_CODEX.to_owned(), FakeItem {
                collection: "kdewallet".to_owned(),
                attributes: HashMap::from([
                    ("service".to_owned(), "gh:github.com".to_owned()),
                    ("agent-sandbox:package".to_owned(), "codex".to_owned()),
                    ("Uuid".to_owned(), "codex-uuid-2".to_owned()),
                ]),
                label: "Codex Token".to_owned(),
                secret: RawSecret {
                    session: session.clone(),
                    parameters: vec![0x10, 0x20, 0x30, 0x40],
                    value: vec![0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x42],
                    content_type: "application/octet-stream".to_owned(),
                },
                locked: false,
            }),
            (ITEM_OMP.to_owned(), FakeItem {
                collection: "kdewallet".to_owned(),
                attributes: HashMap::from([
                    ("service".to_owned(), "gh:github.com".to_owned()),
                    ("agent-sandbox:package".to_owned(), "omp".to_owned()),
                ]),
                label: "Omp Token".to_owned(),
                secret: RawSecret {
                    session: session.clone(),
                    parameters: Vec::new(),
                    value: b"omp-secret-value".to_vec(),
                    content_type: "text/plain".to_owned(),
                },
                locked: false,
            }),
            (ITEM_LOCKED.to_owned(), FakeItem {
                collection: "kdewallet".to_owned(),
                attributes: HashMap::from([("service".to_owned(), "locked-svc".to_owned())]),
                label: "Locked Secret".to_owned(),
                secret: RawSecret {
                    session,
                    parameters: Vec::new(),
                    value: b"locked-value".to_vec(),
                    content_type: "text/plain".to_owned(),
                },
                locked: true,
            }),
        ]);
        // Return order deliberately puts Host first, Omp second, Codex third so
        // the mediator must both filter Omp out and reorder Codex ahead of
        // Host.
        let item_order = vec![
            ITEM_HOST.to_owned(),
            ITEM_OMP.to_owned(),
            ITEM_CODEX.to_owned(),
        ];

        Self {
            items,
            item_order,
            next_id: 10,
            get_secrets_calls: 0,
            properties_set_calls: 0,
        }
    }

    fn collection_items(&self, collection: &str) -> Vec<OwnedObjectPath> {
        self.item_order
            .iter()
            .filter(|path| {
                self.items
                    .get(*path)
                    .is_some_and(|item| item.collection == collection)
            })
            .map(|p| OwnedObjectPath::try_from(p.as_str()).expect("valid item path"))
            .collect()
    }

    fn all_visible_items(&self) -> Vec<OwnedObjectPath> {
        self.item_order
            .iter()
            .filter(|path| self.items.contains_key(*path))
            .map(|p| OwnedObjectPath::try_from(p.as_str()).expect("valid item path"))
            .collect()
    }

    /// Simulate KWallet/oo7 sequential integer item-path renumbering after
    /// restart or compaction by moving `old_path` to a freshly allocated
    /// integer path in the same collection.
    fn renumber_item(&mut self, old_path: &str) -> String {
        let item = self
            .items
            .remove(old_path)
            .expect("item exists to renumber");
        let new_id = self.next_id;
        self.next_id += 1;
        let new_path = format!(
            "/org/freedesktop/secrets/collection/{}/{new_id}",
            item.collection
        );
        self.items.insert(new_path.clone(), item);
        for slot in &mut self.item_order {
            if slot == old_path {
                slot.clone_from(&new_path);
            }
        }
        new_path
    }
}

struct FakeSecretsService {
    connection: Connection,
    unique_name: String,
    state: Arc<Mutex<FakeServiceState>>,
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
        assert_eq!(
            code, 1,
            "expected primary owner for org.freedesktop.secrets"
        );

        let state = Arc::new(Mutex::new(FakeServiceState::new()));
        let state_for_task = Arc::clone(&state);

        let conn_for_task = connection.clone();
        let task = tokio::spawn(async move {
            let mut stream = stream;
            while let Some(Ok(msg)) = stream.next().await {
                if msg.message_type() != Type::MethodCall {
                    continue;
                }
                handle_fake_service_call(&conn_for_task, &state_for_task, &msg).await;
            }
        });

        Self {
            connection,
            unique_name,
            state,
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

fn collection_segment_from_path(path: &str) -> Option<&str> {
    if path == DEFAULT_ALIAS_PATH {
        return Some("kdewallet");
    }
    if path == WORK_ALIAS_PATH {
        return Some("work");
    }
    path.strip_prefix("/org/freedesktop/secrets/collection/")
        .filter(|seg| !seg.is_empty() && !seg.contains('/'))
}

async fn send_item_lookup_error(conn: &Connection, header: &zbus::message::Header<'_>, path: &str) {
    let err_name = if path == ITEM_UNKNOWN_OBJ {
        "org.freedesktop.DBus.Error.UnknownObject"
    } else {
        "org.freedesktop.Secret.Error.NoSuchObject"
    };
    let err = Message::error(header, err_name)
        .expect("err")
        .build(&("no such item",))
        .expect("build");
    let _ = conn.send(&err).await;
}

async fn handle_fake_service_call(
    conn: &Connection,
    state: &Arc<Mutex<FakeServiceState>>,
    msg: &Message,
) {
    let header = msg.header();
    let iface = header.interface().map_or_default(|i| i.as_str());
    let member = header.member().map_or_default(|m| m.as_str());
    let path = header.path().map_or_default(|p| p.as_str());

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
            let alias: String = msg.body().deserialize().expect("ReadAlias arg");
            let target = match alias.as_str() {
                "default" => COLL_PATH,
                "work" => WORK_COLL_PATH,
                _ => "/",
            };
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&(OwnedObjectPath::try_from(target).expect("alias target"),))
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Service", "SearchItems") => {
            let query: HashMap<String, String> = msg.body().deserialize().unwrap_or_default();
            let guard = state.lock().await;
            let matched: Vec<OwnedObjectPath> = guard
                .all_visible_items()
                .into_iter()
                .filter(|item_path| {
                    guard.items.get(item_path.as_str()).is_some_and(|item| {
                        query.iter().all(|(k, v)| item.attributes.get(k) == Some(v))
                    })
                })
                .collect();
            drop(guard);
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&ServiceSearchItemsReply {
                    unlocked: matched,
                    locked: Vec::new(),
                })
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Collection", "SearchItems") => {
            let query: HashMap<String, String> = msg.body().deserialize().unwrap_or_default();
            let seg = collection_segment_from_path(path).unwrap_or("kdewallet");
            let guard = state.lock().await;
            let matched: Vec<OwnedObjectPath> = guard
                .collection_items(seg)
                .into_iter()
                .filter(|item_path| {
                    guard.items.get(item_path.as_str()).is_some_and(|item| {
                        query.iter().all(|(k, v)| item.attributes.get(k) == Some(v))
                    })
                })
                .collect();
            drop(guard);
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&(matched,))
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Collection", "CreateItem") => {
            let args: CreateItemArgs = msg.body().deserialize().expect("CreateItem args");
            let seg = collection_segment_from_path(path).unwrap_or("kdewallet");
            let attrs: HashMap<String, String> = args
                .properties
                .get("org.freedesktop.Secret.Item.Attributes")
                .map_or_default(|v| {
                    HashMap::<String, String>::try_from(v.try_clone().expect("clone attrs"))
                        .expect("decode attrs")
                });
            let label: String = args
                .properties
                .get("org.freedesktop.Secret.Item.Label")
                .map_or_default(|v| {
                    String::try_from(v.try_clone().expect("clone label")).expect("label")
                });

            let prompt_path = if label.contains("prompt-me") {
                PROMPT_CREATE
            } else {
                "/"
            };

            let mut guard = state.lock().await;
            // Simulate KWallet / gnome-keyring subset matching on replace=true:
            // an existing item matches iff every incoming (k, v) exists and
            // matches in the existing item's attributes.
            let existing_match = if args.replace && !attrs.is_empty() {
                guard.item_order.iter().find_map(|existing_path| {
                    let existing = guard.items.get(existing_path)?;
                    if existing.collection != seg {
                        return None;
                    }
                    let subset_match = attrs
                        .iter()
                        .all(|(k, v)| existing.attributes.get(k) == Some(v));
                    subset_match.then(|| existing_path.clone())
                })
            } else {
                None
            };

            let item_path = if let Some(matched_path) = existing_match {
                let entry = guard.items.get_mut(&matched_path).expect("matched item");
                entry.attributes = attrs;
                entry.label = label;
                entry.secret = args.secret;
                matched_path
            } else {
                let id = guard.next_id;
                guard.next_id += 1;
                let new_path = format!("/org/freedesktop/secrets/collection/{seg}/{id}");
                guard.items.insert(new_path.clone(), FakeItem {
                    collection: seg.to_owned(),
                    attributes: attrs,
                    label,
                    secret: args.secret,
                    locked: false,
                });
                guard.item_order.push(new_path.clone());
                new_path
            };
            drop(guard);

            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&CreateItemReply {
                    item: OwnedObjectPath::try_from(item_path.as_str()).expect("item path"),
                    prompt: OwnedObjectPath::try_from(prompt_path).expect("prompt path"),
                })
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Item", "GetSecret") => {
            let guard = state.lock().await;
            if let Some(item) = guard.items.get(path) {
                if item.locked {
                    let err = Message::error(&header, "org.freedesktop.Secret.Error.IsLocked")
                        .expect("err")
                        .build(&("item is locked",))
                        .expect("build");
                    let _ = conn.send(&err).await;
                } else {
                    let reply = Message::method_return(&header)
                        .expect("reply")
                        .build(&SetSecretArgs {
                            secret: item.secret.clone(),
                        })
                        .expect("build");
                    let _ = conn.send(&reply).await;
                }
            } else {
                drop(guard);
                send_item_lookup_error(conn, &header, path).await;
            }
        }

        ("org.freedesktop.Secret.Service", "GetSecrets") => {
            let args: GetSecretsArgs = msg.body().deserialize().expect("GetSecrets args");
            let mut guard = state.lock().await;
            guard.get_secrets_calls += 1;
            let mut out: HashMap<OwnedObjectPath, RawSecret> = HashMap::new();
            for item_path in args.items {
                if let Some(item) = guard.items.get(item_path.as_str()) {
                    out.insert(item_path, item.secret.clone());
                }
            }
            drop(guard);
            let reply = Message::method_return(&header)
                .expect("reply")
                .build(&(out,))
                .expect("build");
            let _ = conn.send(&reply).await;
        }

        ("org.freedesktop.Secret.Item", "SetSecret") => {
            let args: SetSecretArgs = msg.body().deserialize().expect("SetSecret args");
            let mut guard = state.lock().await;
            if let Some(item) = guard.items.get_mut(path) {
                item.secret = args.secret;
                drop(guard);
                let reply = Message::method_return(&header)
                    .expect("reply")
                    .build(&())
                    .expect("build");
                let _ = conn.send(&reply).await;
            } else {
                drop(guard);
                send_item_lookup_error(conn, &header, path).await;
            }
        }

        ("org.freedesktop.Secret.Item", "Delete") => {
            let mut guard = state.lock().await;
            if let Some(removed) = guard.items.remove(path) {
                guard.item_order.retain(|p| p != path);
                let prompt_path = if removed.label.contains("delete-prompt") {
                    PROMPT_DELETE
                } else {
                    "/"
                };
                drop(guard);
                let reply = Message::method_return(&header)
                    .expect("reply")
                    .build(&(OwnedObjectPath::try_from(prompt_path).expect("prompt path"),))
                    .expect("build");
                let _ = conn.send(&reply).await;
            } else {
                drop(guard);
                send_item_lookup_error(conn, &header, path).await;
            }
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
                    let seg = collection_segment_from_path(path).unwrap_or("kdewallet");
                    let items = state.lock().await.collection_items(seg);
                    let val = Value::from(items);
                    let reply = Message::method_return(&header)
                        .expect("reply")
                        .build(&val)
                        .expect("build");
                    let _ = conn.send(&reply).await;
                }
                ("org.freedesktop.Secret.Collection", "Label") => {
                    let seg = collection_segment_from_path(path).unwrap_or("kdewallet");
                    let val = Value::from(seg);
                    let reply = Message::method_return(&header)
                        .expect("reply")
                        .build(&val)
                        .expect("build");
                    let _ = conn.send(&reply).await;
                }
                ("org.freedesktop.Secret.Item", "Attributes") => {
                    let guard = state.lock().await;
                    if let Some(item) = guard.items.get(path) {
                        if item.locked {
                            let err =
                                Message::error(&header, "org.freedesktop.Secret.Error.IsLocked")
                                    .expect("err")
                                    .build(&("item is locked",))
                                    .expect("build");
                            let _ = conn.send(&err).await;
                        } else {
                            let val = Value::from(item.attributes.clone());
                            let reply = Message::method_return(&header)
                                .expect("reply")
                                .build(&val)
                                .expect("build");
                            let _ = conn.send(&reply).await;
                        }
                    } else {
                        drop(guard);
                        send_item_lookup_error(conn, &header, path).await;
                    }
                }
                ("org.freedesktop.Secret.Item", "Label") => {
                    let guard = state.lock().await;
                    if let Some(item) = guard.items.get(path) {
                        if item.locked {
                            let err =
                                Message::error(&header, "org.freedesktop.Secret.Error.IsLocked")
                                    .expect("err")
                                    .build(&("item is locked",))
                                    .expect("build");
                            let _ = conn.send(&err).await;
                        } else {
                            let val = Value::from(item.label.as_str());
                            let reply = Message::method_return(&header)
                                .expect("reply")
                                .build(&val)
                                .expect("build");
                            let _ = conn.send(&reply).await;
                        }
                    } else {
                        drop(guard);
                        send_item_lookup_error(conn, &header, path).await;
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
                    let seg = collection_segment_from_path(path).unwrap_or("kdewallet");
                    let items = state.lock().await.collection_items(seg);
                    props.insert("Label".to_owned(), owned_str(seg));
                    props.insert(
                        "Items".to_owned(),
                        OwnedValue::try_from(Value::from(items)).expect("Items value"),
                    );
                }
                "org.freedesktop.Secret.Item" => {
                    let guard = state.lock().await;
                    if let Some(item) = guard.items.get(path) {
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

        ("org.freedesktop.DBus.Properties", "Set") => {
            let args: PropertiesSetArgs = msg.body().deserialize().expect("Properties.Set args");
            let mut guard = state.lock().await;
            guard.properties_set_calls += 1;
            if let Some(item) = guard.items.get_mut(path) {
                match (args.interface.as_str(), args.property.as_str()) {
                    ("org.freedesktop.Secret.Item", "Attributes") => {
                        item.attributes =
                            HashMap::<String, String>::try_from(args.value).expect("attrs");
                    }
                    ("org.freedesktop.Secret.Item", "Label") => {
                        item.label = String::try_from(args.value).expect("label");
                    }
                    _ => {}
                }
                drop(guard);
                let reply = Message::method_return(&header)
                    .expect("reply")
                    .build(&())
                    .expect("build");
                let _ = conn.send(&reply).await;
            } else {
                drop(guard);
                send_item_lookup_error(conn, &header, path).await;
            }
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

fn assert_dbus_error<T: std::fmt::Debug>(
    result: zbus::Result<T>,
    expected_name: &str,
    context: &str,
) {
    match result {
        Err(zbus::Error::MethodError(name, ..)) => {
            assert_eq!(
                name.as_str(),
                expected_name,
                "expected {expected_name} for {context}, got {name}"
            );
        }
        other => panic!("expected {expected_name} for {context}, got {other:?}"),
    }
}

fn assert_access_denied<T: std::fmt::Debug>(result: zbus::Result<T>, context: &str) {
    assert_dbus_error(result, "org.freedesktop.DBus.Error.AccessDenied", context);
}

struct AttrPair<'a> {
    key: &'a str,
    value: &'a str,
}

fn attr<'a>(key: &'a str, value: &'a str) -> AttrPair<'a> {
    AttrPair { key, value }
}

fn secret_rule(
    partition: SecretPartition,
    collection: &str,
    attributes: &[AttrPair<'_>],
    label: Option<&str>,
    access: SecretAccess,
) -> SecretRule {
    SecretRule {
        target: SecretTarget {
            partition,
            collection: collection.to_owned(),
            attributes: attributes
                .iter()
                .map(|pair| (pair.key.to_owned(), pair.value.to_owned()))
                .collect(),
            label: label.map(str::to_owned),
            access,
        },
        comment: None,
    }
}

fn make_item_properties(label: &str, attrs: &[AttrPair<'_>]) -> HashMap<String, OwnedValue> {
    let map: HashMap<String, String> = attrs
        .iter()
        .map(|pair| (pair.key.to_owned(), pair.value.to_owned()))
        .collect();
    HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label".to_owned(),
            owned_str(label),
        ),
        (
            "org.freedesktop.Secret.Item.Attributes".to_owned(),
            OwnedValue::try_from(Value::from(map)).expect("encode attrs"),
        ),
    ])
}

async fn assert_no_secrets_dbus_fallback(policyd: &MockPolicyd) {
    let targets = policyd.check_dbus_targets.lock().await.clone();
    assert!(
        targets.iter().all(|target| {
            target.interface == "org.freedesktop.DBus" && target.member == "NameAcquired"
        }),
        "Secret Service traffic must never fall through to CheckDbus, saw: {targets:?}"
    );
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

    // 1. Safe operations pass through via both well-known name and pinned
    //    `:1.x`.
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

    // 2. Daemon-internal interface on `:1.x` is blocked via both well-known and
    //    unique owner destinations.
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
                &(
                    "default",
                    OwnedObjectPath::try_from(COLL_PATH).expect("coll"),
                ),
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

    // 4. Secret-bearing operations fail closed under default-deny CheckSecret
    //    policy.
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
    let coll_paths: Vec<String> = coll_search.iter().map(|p| p.as_str().to_owned()).collect();
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
    assert_eq!(
        String::try_from(codex_label).expect("string"),
        "Codex Token"
    );

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
            &(vec![
                OwnedObjectPath::try_from(DEFAULT_ALIAS_PATH).expect("alias"),
            ],),
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
    let created_path: OwnedObjectPath =
        item_created.body().deserialize().expect("ItemCreated path");
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
    let changed_items: Vec<OwnedObjectPath> = Vec::try_from(
        changed_args.changed["Items"]
            .try_clone()
            .expect("clone Items"),
    )
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
    assert_eq!(
        codex_policyd.resolve_package_calls.load(Ordering::SeqCst),
        1
    );
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

#[tokio::test]
async fn gated_create_get_set_delete_and_renumbering_work_with_durable_rules() {
    let daemon = LocalDbusDaemon::start().await;
    let fake_service = FakeSecretsService::start(&daemon.address).await;
    let owner = fake_service.unique_name.clone();
    let workdir = tempfile::tempdir().expect("create test workdir");

    let rules = SecretSection {
        allow: vec![
            secret_rule(
                SecretPartition::OwnPackage,
                "*",
                &[],
                None,
                SecretAccess::All,
            ),
            secret_rule(
                SecretPartition::Host,
                "default",
                &[attr("service", "gh:github.com")],
                None,
                SecretAccess::ReadWrite,
            ),
        ],
        deny: Vec::new(),
    };
    let codex_policyd = MockPolicyd::start_with_rules(workdir.path(), Some("codex"), rules);
    let StartedRelay {
        socket: relay_sock,
        task: relay_task,
    } = start_relay(
        workdir.path(),
        "codex-gated",
        &daemon.address,
        &codex_policyd.socket_path,
    )
    .await;

    let addr = format!("unix:path={}", relay_sock.display());
    let mut stream = Builder::address(addr.as_str())
        .expect("relay addr")
        .build_message_stream()
        .await
        .expect("connect client");
    let codex = Connection::from(&stream);

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
        .expect("AddMatch");

    let session = OwnedObjectPath::try_from(SESSION_PATH).expect("session");

    // 1. GetSecret on host item strips daemon-synthesized keys (Uuid, Path,
    //    Totp, xdg:content-type) and returns binary secret bytes verbatim.
    let host_secret: SetSecretArgs = codex
        .call_method(
            Some(SECRETS_NAME),
            ITEM_HOST,
            Some("org.freedesktop.Secret.Item"),
            "GetSecret",
            &(session.clone(),),
        )
        .await
        .expect("GetSecret on host item")
        .body()
        .deserialize()
        .expect("GetSecret reply");
    assert_eq!(host_secret.secret.parameters, vec![0x01, 0x02, 0xFE, 0xFF]);
    assert_eq!(host_secret.secret.value, b"host-gh-token-value");

    let reqs = codex_policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].partition, SecretPartition::Host);
    assert_eq!(reqs[0].collection, "kdewallet");
    assert!(reqs[0].is_default_collection);
    assert_eq!(
        reqs[0].attributes,
        BTreeMap::from([("service".to_owned(), "gh:github.com".to_owned())])
    );
    assert_eq!(reqs[0].label, "Host GitHub Token");
    assert_eq!(reqs[0].access, SecretAccess::Read);
    assert_eq!(reqs[0].operation, SecretOperation::GetSecret);

    // 2. Renumbering the host item's sequential integer path still matches the
    //    same durable SecretRule without any path rule.
    let renumbered_host = fake_service.state.lock().await.renumber_item(ITEM_HOST);
    assert_ne!(renumbered_host, ITEM_HOST);
    let renumbered_secret: SetSecretArgs = codex
        .call_method(
            Some(owner.as_str()),
            renumbered_host.as_str(),
            Some("org.freedesktop.Secret.Item"),
            "GetSecret",
            &(session.clone(),),
        )
        .await
        .expect("GetSecret after sequential path renumbering")
        .body()
        .deserialize()
        .expect("GetSecret reply");
    assert_eq!(renumbered_secret.secret.value, b"host-gh-token-value");
    let _ = codex_policyd.take_secret_requests().await;

    // 3. CreateItem via /aliases/default with replace=true and identical client
    //    attributes as host: stamps agent-sandbox:package=codex, preserves
    //    exact binary DH bytes, NEVER overwrites host secret, tracks returned
    //    prompt path, and puts codex's item ahead of host in SearchItems.
    let dh_secret = RawSecret {
        session: session.clone(),
        parameters: vec![0xAA, 0xBB, 0x00, 0xCC, 0xFF, 0x11, 0x22, 0x33],
        value: vec![0x00, 0x01, 0x80, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0xFE],
        content_type: "application/octet-stream".to_owned(),
    };
    let created: CreateItemReply = codex
        .call_method(
            Some(SECRETS_NAME),
            DEFAULT_ALIAS_PATH,
            Some("org.freedesktop.Secret.Collection"),
            "CreateItem",
            &CreateItemArgs {
                properties: make_item_properties("Codex DH prompt-me", &[
                    attr("service", "gh:github.com"),
                    attr("Uuid", "client-uuid"),
                ]),
                secret: dh_secret.clone(),
                replace: true,
            },
        )
        .await
        .expect("CreateItem via default alias")
        .body()
        .deserialize()
        .expect("CreateItem reply");
    assert_eq!(created.prompt.as_str(), PROMPT_CREATE);

    let reqs = codex_policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].partition, SecretPartition::OwnPackage);
    assert_eq!(reqs[0].collection, "kdewallet");
    assert!(reqs[0].is_default_collection);
    assert!(reqs[0].replace);
    assert_eq!(reqs[0].operation, SecretOperation::CreateItem);
    assert_eq!(reqs[0].access, SecretAccess::Write);
    assert_eq!(
        reqs[0].attributes,
        BTreeMap::from([("service".to_owned(), "gh:github.com".to_owned())])
    );

    // Prompt returned by CreateItem is tracked and completes cleanly.
    codex
        .call_method(
            Some(SECRETS_NAME),
            PROMPT_CREATE,
            Some("org.freedesktop.Secret.Prompt"),
            "Prompt",
            &("",),
        )
        .await
        .expect("Prompt.Prompt on CreateItem prompt");
    let completed = next_signal(&mut stream, "Completed").await;
    assert_eq!(
        completed.header().path().map(|p| p.as_str()),
        Some(PROMPT_CREATE)
    );

    // Host secret is completely untouched; codex's item carries tag + exact DH
    // bytes.
    {
        let (host_entry, created_entry) = {
            let guard = fake_service.state.lock().await;
            (
                guard
                    .items
                    .get(&renumbered_host)
                    .expect("host item intact")
                    .clone(),
                guard
                    .items
                    .get(created.item.as_str())
                    .expect("created codex item")
                    .clone(),
            )
        };
        assert_eq!(host_entry.secret.value, b"host-gh-token-value");
        assert!(!host_entry.attributes.contains_key("agent-sandbox:package"));
        assert_eq!(
            created_entry
                .attributes
                .get("agent-sandbox:package")
                .map(String::as_str),
            Some("codex")
        );
        assert_eq!(created_entry.secret, dh_secret);
    }

    // Reading back the created DH secret preserves every byte verbatim.
    let read_dh: SetSecretArgs = codex
        .call_method(
            Some(SECRETS_NAME),
            created.item.as_str(),
            Some("org.freedesktop.Secret.Item"),
            "GetSecret",
            &(session.clone(),),
        )
        .await
        .expect("GetSecret on created DH item")
        .body()
        .deserialize()
        .expect("GetSecret reply");
    assert_eq!(read_dh.secret, dh_secret);
    let _ = codex_policyd.take_secret_requests().await;

    // Shadowing a host-only secret with CreateItem(replace=true) when no
    // package secret exists yet creates a distinct package item without
    // modifying the host item, and SearchItems returns package secret first.
    let host_only_path = {
        let mut guard = fake_service.state.lock().await;
        let id = guard.next_id;
        guard.next_id += 1;
        let path = format!("/org/freedesktop/secrets/collection/kdewallet/{id}");
        guard.items.insert(path.clone(), FakeItem {
            collection: "kdewallet".to_owned(),
            attributes: HashMap::from([("service".to_owned(), "shadow-target".to_owned())]),
            label: "Host Shadow Target".to_owned(),
            secret: RawSecret {
                session: session.clone(),
                parameters: Vec::new(),
                value: b"host-original-secret".to_vec(),
                content_type: "text/plain".to_owned(),
            },
            locked: false,
        });
        guard.item_order.insert(0, path.clone());
        path
    };
    let shadowed: CreateItemReply = codex
        .call_method(
            Some(SECRETS_NAME),
            DEFAULT_ALIAS_PATH,
            Some("org.freedesktop.Secret.Collection"),
            "CreateItem",
            &CreateItemArgs {
                properties: make_item_properties("Codex Shadow", &[attr(
                    "service",
                    "shadow-target",
                )]),
                secret: RawSecret {
                    session: session.clone(),
                    parameters: Vec::new(),
                    value: b"codex-shadow-secret".to_vec(),
                    content_type: "text/plain".to_owned(),
                },
                replace: true,
            },
        )
        .await
        .expect("CreateItem(replace=true) shadowing host-only item")
        .body()
        .deserialize()
        .expect("CreateItem reply");
    assert_ne!(shadowed.item.as_str(), host_only_path.as_str());
    assert_eq!(
        fake_service.state.lock().await.items[&host_only_path]
            .secret
            .value,
        b"host-original-secret",
        "host-only secret must remain untouched when package calls CreateItem(replace=true)"
    );
    let shadow_search: ServiceSearchItemsReply = codex
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "SearchItems",
            &(HashMap::from([("service", "shadow-target")]),),
        )
        .await
        .expect("SearchItems for shadowed secret")
        .body()
        .deserialize()
        .expect("SearchItems reply");
    assert_eq!(
        shadow_search
            .unlocked
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect::<Vec<_>>(),
        vec![shadowed.item.as_str().to_owned(), host_only_path],
        "SearchItems must order newly shadowed package secret ahead of host secret"
    );
    let _ = codex_policyd.take_secret_requests().await;

    // 4. CreateItem via non-default alias (/aliases/work) resolves concrete
    //    collection `work` with `is_default_collection == false`.
    let work_created: CreateItemReply = codex
        .call_method(
            Some(SECRETS_NAME),
            WORK_ALIAS_PATH,
            Some("org.freedesktop.Secret.Collection"),
            "CreateItem",
            &CreateItemArgs {
                properties: make_item_properties("Work delete-prompt", &[attr(
                    "service", "work-api",
                )]),
                secret: RawSecret {
                    session: session.clone(),
                    parameters: Vec::new(),
                    value: b"work-token".to_vec(),
                    content_type: "text/plain".to_owned(),
                },
                replace: false,
            },
        )
        .await
        .expect("CreateItem via /aliases/work")
        .body()
        .deserialize()
        .expect("CreateItem reply");
    let reqs = codex_policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].collection, "work");
    assert!(!reqs[0].is_default_collection);

    // 5. Item.SetSecret updates host secret in place under host write rule.
    codex
        .call_method(
            Some(SECRETS_NAME),
            renumbered_host.as_str(),
            Some("org.freedesktop.Secret.Item"),
            "SetSecret",
            &SetSecretArgs {
                secret: RawSecret {
                    session: session.clone(),
                    parameters: Vec::new(),
                    value: b"updated-host-token".to_vec(),
                    content_type: "text/plain".to_owned(),
                },
            },
        )
        .await
        .expect("SetSecret on host item");
    assert_eq!(
        fake_service.state.lock().await.items[&renumbered_host]
            .secret
            .value,
        b"updated-host-token"
    );
    let reqs = codex_policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].operation, SecretOperation::SetSecret);
    assert_eq!(reqs[0].access, SecretAccess::Write);
    assert_eq!(reqs[0].partition, SecretPartition::Host);

    // 6. Item.Delete checks Delete access, removes item, and tracks returned
    //    non-"/" prompt path.
    let delete_prompt: OwnedObjectPath = codex
        .call_method(
            Some(SECRETS_NAME),
            work_created.item.as_str(),
            Some("org.freedesktop.Secret.Item"),
            "Delete",
            &(),
        )
        .await
        .expect("Delete on own work item")
        .body()
        .deserialize()
        .expect("Delete reply");
    assert_eq!(delete_prompt.as_str(), PROMPT_DELETE);
    let reqs = codex_policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].operation, SecretOperation::Delete);
    assert_eq!(reqs[0].access, SecretAccess::Delete);
    assert_eq!(reqs[0].collection, "work");
    assert!(!reqs[0].is_default_collection);

    codex
        .call_method(
            Some(SECRETS_NAME),
            PROMPT_DELETE,
            Some("org.freedesktop.Secret.Prompt"),
            "Prompt",
            &("",),
        )
        .await
        .expect("Prompt.Prompt on Delete prompt");
    let del_completed = next_signal(&mut stream, "Completed").await;
    assert_eq!(
        del_completed.header().path().map(|p| p.as_str()),
        Some(PROMPT_DELETE)
    );

    // 7. Direct cross-package GetSecret / SetSecret / Delete / Properties.Get /
    //    Properties.Set on omp's item all fail closed with ZERO CheckSecret
    //    calls.
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                ITEM_OMP,
                Some("org.freedesktop.Secret.Item"),
                "GetSecret",
                &(session.clone(),),
            )
            .await,
        "cross-package GetSecret",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                ITEM_OMP,
                Some("org.freedesktop.Secret.Item"),
                "SetSecret",
                &SetSecretArgs {
                    secret: RawSecret {
                        session,
                        parameters: Vec::new(),
                        value: b"hijack".to_vec(),
                        content_type: "text/plain".to_owned(),
                    },
                },
            )
            .await,
        "cross-package SetSecret",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                ITEM_OMP,
                Some("org.freedesktop.Secret.Item"),
                "Delete",
                &(),
            )
            .await,
        "cross-package Delete",
    );
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                ITEM_OMP,
                Some("org.freedesktop.DBus.Properties"),
                "Set",
                &PropertiesSetArgs {
                    interface: "org.freedesktop.Secret.Item".into(),
                    property: "Label".into(),
                    value: owned_str("Hijacked"),
                },
            )
            .await,
        "cross-package Properties.Set",
    );
    assert!(
        codex_policyd.take_secret_requests().await.is_empty(),
        "cross-package operations must fail before CheckSecret"
    );

    assert_no_secrets_dbus_fallback(&codex_policyd).await;
    relay_task.abort();
}

#[tokio::test]
async fn get_secrets_enforces_all_or_nothing_batch_info_and_cap() {
    let daemon = LocalDbusDaemon::start().await;
    let fake_service = FakeSecretsService::start(&daemon.address).await;
    let workdir = tempfile::tempdir().expect("create test workdir");

    // Allow own_package Read, allow host Read.
    let policyd = MockPolicyd::start_with_rules(workdir.path(), Some("codex"), SecretSection {
        allow: vec![
            secret_rule(
                SecretPartition::OwnPackage,
                "default",
                &[],
                None,
                SecretAccess::Read,
            ),
            secret_rule(
                SecretPartition::Host,
                "default",
                &[attr("service", "gh:github.com")],
                None,
                SecretAccess::Read,
            ),
        ],
        deny: Vec::new(),
    });
    let StartedRelay {
        socket: relay_sock,
        task: relay_task,
    } = start_relay(
        workdir.path(),
        "codex-batch",
        &daemon.address,
        &policyd.socket_path,
    )
    .await;

    let addr = format!("unix:path={}", relay_sock.display());
    let codex = Builder::address(addr.as_str())
        .expect("relay addr")
        .build()
        .await
        .expect("connect");
    let session = OwnedObjectPath::try_from(SESSION_PATH).expect("session");
    let codex_path = OwnedObjectPath::try_from(ITEM_CODEX).expect("codex");
    let host_path = OwnedObjectPath::try_from(ITEM_HOST).expect("host");
    let omp_path = OwnedObjectPath::try_from(ITEM_OMP).expect("omp");

    // 1. Single-item batch sends batch == None and returns exact binary bytes.
    let single: HashMap<OwnedObjectPath, RawSecret> = codex
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "GetSecrets",
            &GetSecretsArgs {
                items: vec![codex_path.clone()],
                session: session.clone(),
            },
        )
        .await
        .expect("single-item GetSecrets")
        .body()
        .deserialize()
        .expect("GetSecrets reply");
    assert_eq!(single[&codex_path].value, vec![
        0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x42
    ]);
    let reqs = policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].operation, SecretOperation::GetSecrets);
    assert_eq!(reqs[0].batch, None);

    // 2. Multi-item batch sends 1..=2 SecretBatchInfo and returns both items.
    let multi: HashMap<OwnedObjectPath, RawSecret> = codex
        .call_method(
            Some(SECRETS_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.Secret.Service"),
            "GetSecrets",
            &GetSecretsArgs {
                items: vec![codex_path.clone(), host_path.clone()],
                session: session.clone(),
            },
        )
        .await
        .expect("multi-item GetSecrets")
        .body()
        .deserialize()
        .expect("GetSecrets reply");
    assert_eq!(multi.len(), 2);
    assert_eq!(multi[&host_path].value, b"host-gh-token-value");
    let reqs = policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].batch, Some(SecretBatchInfo { index: 1, total: 2 }));
    assert_eq!(reqs[1].batch, Some(SecretBatchInfo { index: 2, total: 2 }));

    let calls_before_denials = fake_service.state.lock().await.get_secrets_calls;

    // 3. All-or-nothing when second item is denied by policy: returns
    //    AccessDenied and never forwards GetSecrets to the service.
    policyd
        .set_rules(SecretSection {
            allow: vec![secret_rule(
                SecretPartition::OwnPackage,
                "default",
                &[],
                None,
                SecretAccess::Read,
            )],
            deny: Vec::new(),
        })
        .await;
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "GetSecrets",
                &GetSecretsArgs {
                    items: vec![codex_path.clone(), host_path.clone()],
                    session: session.clone(),
                },
            )
            .await,
        "all-or-nothing policy denial",
    );
    assert_eq!(
        fake_service.state.lock().await.get_secrets_calls,
        calls_before_denials
    );
    assert_eq!(policyd.take_secret_requests().await.len(), 2);

    // 4. Batch containing another package's item fails immediately with ZERO
    //    CheckSecret calls and never reaches the service.
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "GetSecrets",
                &GetSecretsArgs {
                    items: vec![codex_path.clone(), omp_path],
                    session: session.clone(),
                },
            )
            .await,
        "batch with foreign item",
    );
    assert_eq!(policyd.take_secret_requests().await, Vec::new());
    assert_eq!(
        fake_service.state.lock().await.get_secrets_calls,
        calls_before_denials
    );

    // 5. Batch exceeding 64 items is rejected before lookup or CheckSecret.
    let oversized = vec![codex_path; 65];
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "GetSecrets",
                &GetSecretsArgs {
                    items: oversized,
                    session,
                },
            )
            .await,
        "GetSecrets over 64-item cap",
    );
    assert_eq!(policyd.take_secret_requests().await, Vec::new());
    assert_eq!(
        fake_service.state.lock().await.get_secrets_calls,
        calls_before_denials
    );

    assert_no_secrets_dbus_fallback(&policyd).await;
    relay_task.abort();
}

#[tokio::test]
async fn properties_set_enforces_dual_identity_preserves_tag_and_rejects_reserved_prefix() {
    let daemon = LocalDbusDaemon::start().await;
    let fake_service = FakeSecretsService::start(&daemon.address).await;
    let workdir = tempfile::tempdir().expect("create test workdir");

    // Allow writes ONLY for `service=gh:github.com` initially (NOT
    // `service=other`).
    let policyd = MockPolicyd::start_with_rules(workdir.path(), Some("codex"), SecretSection {
        allow: vec![secret_rule(
            SecretPartition::OwnPackage,
            "default",
            &[attr("service", "gh:github.com")],
            None,
            SecretAccess::Write,
        )],
        deny: Vec::new(),
    });
    let StartedRelay {
        socket: relay_sock,
        task: relay_task,
    } = start_relay(
        workdir.path(),
        "codex-props",
        &daemon.address,
        &policyd.socket_path,
    )
    .await;

    let addr = format!("unix:path={}", relay_sock.display());
    let codex = Builder::address(addr.as_str())
        .expect("relay addr")
        .build()
        .await
        .expect("connect");
    let session = OwnedObjectPath::try_from(SESSION_PATH).expect("session");

    // 1. Reserved `agent-sandbox:*` attribute key is rejected on BOTH
    //    CreateItem and Properties.Set without calling CheckSecret.
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                COLL_PATH,
                Some("org.freedesktop.Secret.Collection"),
                "CreateItem",
                &CreateItemArgs {
                    properties: make_item_properties("Spoof", &[
                        attr("service", "gh:github.com"),
                        attr("agent-sandbox:package", "omp"),
                    ]),
                    secret: RawSecret {
                        session,
                        parameters: Vec::new(),
                        value: b"spoof".to_vec(),
                        content_type: "text/plain".to_owned(),
                    },
                    replace: false,
                },
            )
            .await,
        "CreateItem with agent-sandbox:*",
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
                    property: "Attributes".into(),
                    value: OwnedValue::try_from(Value::from(HashMap::from([
                        ("service".to_owned(), "gh:github.com".to_owned()),
                        ("agent-sandbox:custom".to_owned(), "bad".to_owned()),
                    ])))
                    .expect("attrs"),
                },
            )
            .await,
        "Properties.Set with agent-sandbox:*",
    );
    assert_eq!(policyd.take_secret_requests().await, Vec::new());

    // 2. Dual-identity check: old identity (`service=gh:github.com`) is allowed
    //    but new identity (`service=other`) is denied -> fails closed without
    //    calling Properties.Set on the service!
    assert_access_denied(
        codex
            .call_method(
                Some(SECRETS_NAME),
                ITEM_CODEX,
                Some("org.freedesktop.DBus.Properties"),
                "Set",
                &PropertiesSetArgs {
                    interface: "org.freedesktop.Secret.Item".into(),
                    property: "Attributes".into(),
                    value: OwnedValue::try_from(Value::from(HashMap::from([(
                        "service".to_owned(),
                        "other".to_owned(),
                    )])))
                    .expect("attrs"),
                },
            )
            .await,
        "Properties.Set denied on new identity",
    );
    assert_eq!(fake_service.state.lock().await.properties_set_calls, 0);
    let reqs = policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].operation, SecretOperation::SetAttributes);
    assert_eq!(reqs[0].attributes["service"], "gh:github.com");
    assert_eq!(reqs[1].operation, SecretOperation::SetAttributes);
    assert_eq!(reqs[1].attributes["service"], "other");

    // 3. Once BOTH old and new identities are allowed, Properties.Set succeeds
    //    and preserves `agent-sandbox:package=codex` unconditionally!
    policyd
        .set_rules(SecretSection {
            allow: vec![secret_rule(
                SecretPartition::OwnPackage,
                "default",
                &[],
                None,
                SecretAccess::Write,
            )],
            deny: Vec::new(),
        })
        .await;
    codex
        .call_method(
            Some(SECRETS_NAME),
            ITEM_CODEX,
            Some("org.freedesktop.DBus.Properties"),
            "Set",
            &PropertiesSetArgs {
                interface: "org.freedesktop.Secret.Item".into(),
                property: "Attributes".into(),
                value: OwnedValue::try_from(Value::from(HashMap::from([(
                    "service".to_owned(),
                    "other".to_owned(),
                )])))
                .expect("attrs"),
            },
        )
        .await
        .expect("Properties.Set(Attributes) allowed for both identities");
    {
        let updated = fake_service.state.lock().await.items[ITEM_CODEX].clone();
        assert_eq!(
            updated.attributes.get("service").map(String::as_str),
            Some("other")
        );
        assert_eq!(
            updated
                .attributes
                .get("agent-sandbox:package")
                .map(String::as_str),
            Some("codex"),
            "mediator must unconditionally preserve agent-sandbox:package tag"
        );
    }
    let reqs = policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 2);

    // 4. Properties.Set(Item, Label) checks both old and new labels when
    //    changed, and checks only once when label is unchanged.
    codex
        .call_method(
            Some(SECRETS_NAME),
            ITEM_CODEX,
            Some("org.freedesktop.DBus.Properties"),
            "Set",
            &PropertiesSetArgs {
                interface: "org.freedesktop.Secret.Item".into(),
                property: "Label".into(),
                value: owned_str("Renamed Codex Token"),
            },
        )
        .await
        .expect("Properties.Set(Label) rename");
    let reqs = policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].operation, SecretOperation::SetLabel);
    assert_eq!(reqs[0].label, "Codex Token");
    assert_eq!(reqs[1].operation, SecretOperation::SetLabel);
    assert_eq!(reqs[1].label, "Renamed Codex Token");
    assert_eq!(
        fake_service.state.lock().await.items[ITEM_CODEX].label,
        "Renamed Codex Token"
    );

    // Same label -> single check.
    codex
        .call_method(
            Some(SECRETS_NAME),
            ITEM_CODEX,
            Some("org.freedesktop.DBus.Properties"),
            "Set",
            &PropertiesSetArgs {
                interface: "org.freedesktop.Secret.Item".into(),
                property: "Label".into(),
                value: owned_str("Renamed Codex Token"),
            },
        )
        .await
        .expect("Properties.Set(Label) no-op");
    assert_eq!(policyd.take_secret_requests().await.len(), 1);

    assert_no_secrets_dbus_fallback(&policyd).await;
    relay_task.abort();
}

#[tokio::test]
async fn unattributed_create_item_targets_host_and_lookup_errors_propagate_cleanly() {
    let daemon = LocalDbusDaemon::start().await;
    let fake_service = FakeSecretsService::start(&daemon.address).await;
    let workdir = tempfile::tempdir().expect("create test workdir");

    let policyd = MockPolicyd::start(workdir.path(), None);
    let StartedRelay {
        socket: relay_sock,
        task: relay_task,
    } = start_relay(
        workdir.path(),
        "unattr-gated",
        &daemon.address,
        &policyd.socket_path,
    )
    .await;

    let addr = format!("unix:path={}", relay_sock.display());
    let unattr = Builder::address(addr.as_str())
        .expect("relay addr")
        .build()
        .await
        .expect("connect");
    let session = OwnedObjectPath::try_from(SESSION_PATH).expect("session");

    // 1. Unattributed CreateItem targets Host partition (denied without rule).
    assert_access_denied(
        unattr
            .call_method(
                Some(SECRETS_NAME),
                COLL_PATH,
                Some("org.freedesktop.Secret.Collection"),
                "CreateItem",
                &CreateItemArgs {
                    properties: make_item_properties("Host Write", &[attr("service", "shared")]),
                    secret: RawSecret {
                        session: session.clone(),
                        parameters: Vec::new(),
                        value: b"unattr-val".to_vec(),
                        content_type: "text/plain".to_owned(),
                    },
                    replace: false,
                },
            )
            .await,
        "unattributed CreateItem denied without host rule",
    );
    let reqs = policyd.take_secret_requests().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].partition, SecretPartition::Host);
    assert_eq!(reqs[0].operation, SecretOperation::CreateItem);

    // With explicit host write rule, unattributed CreateItem succeeds and
    // leaves the stored item untagged (no agent-sandbox:package).
    policyd
        .set_rules(SecretSection {
            allow: vec![secret_rule(
                SecretPartition::Host,
                "default",
                &[attr("service", "shared")],
                None,
                SecretAccess::Write,
            )],
            deny: Vec::new(),
        })
        .await;
    let created: CreateItemReply = unattr
        .call_method(
            Some(SECRETS_NAME),
            COLL_PATH,
            Some("org.freedesktop.Secret.Collection"),
            "CreateItem",
            &CreateItemArgs {
                properties: make_item_properties("Host Write", &[attr("service", "shared")]),
                secret: RawSecret {
                    session: session.clone(),
                    parameters: Vec::new(),
                    value: b"unattr-val".to_vec(),
                    content_type: "text/plain".to_owned(),
                },
                replace: false,
            },
        )
        .await
        .expect("unattributed CreateItem with host write rule")
        .body()
        .deserialize()
        .expect("CreateItem reply");
    {
        let stored = fake_service.state.lock().await.items[created.item.as_str()].clone();
        assert!(
            !stored.attributes.contains_key("agent-sandbox:package"),
            "unattributed CreateItem must not add package tag"
        );
    }
    let _ = policyd.take_secret_requests().await;

    // 2. Locked item returns org.freedesktop.Secret.Error.IsLocked directly
    //    without calling CheckSecret.
    assert_dbus_error(
        unattr
            .call_method(
                Some(SECRETS_NAME),
                ITEM_LOCKED,
                Some("org.freedesktop.Secret.Item"),
                "GetSecret",
                &(session.clone(),),
            )
            .await,
        "org.freedesktop.Secret.Error.IsLocked",
        "GetSecret on locked item",
    );
    assert_dbus_error(
        unattr
            .call_method(
                Some(SECRETS_NAME),
                SERVICE_PATH,
                Some("org.freedesktop.Secret.Service"),
                "GetSecrets",
                &GetSecretsArgs {
                    items: vec![OwnedObjectPath::try_from(ITEM_LOCKED).expect("locked")],
                    session: session.clone(),
                },
            )
            .await,
        "org.freedesktop.Secret.Error.IsLocked",
        "GetSecrets on locked item",
    );
    assert_dbus_error(
        unattr
            .call_method(
                Some(SECRETS_NAME),
                ITEM_LOCKED,
                Some("org.freedesktop.Secret.Item"),
                "Delete",
                &(),
            )
            .await,
        "org.freedesktop.Secret.Error.IsLocked",
        "Delete on locked item",
    );

    // 3. NoSuchObject and UnknownObject both map cleanly to
    //    org.freedesktop.Secret.Error.NoSuchObject without calling CheckSecret.
    assert_dbus_error(
        unattr
            .call_method(
                Some(SECRETS_NAME),
                ITEM_MISSING,
                Some("org.freedesktop.Secret.Item"),
                "GetSecret",
                &(session.clone(),),
            )
            .await,
        "org.freedesktop.Secret.Error.NoSuchObject",
        "GetSecret on NoSuchObject item",
    );
    assert_dbus_error(
        unattr
            .call_method(
                Some(SECRETS_NAME),
                ITEM_UNKNOWN_OBJ,
                Some("org.freedesktop.Secret.Item"),
                "GetSecret",
                &(session.clone(),),
            )
            .await,
        "org.freedesktop.Secret.Error.NoSuchObject",
        "GetSecret on UnknownObject item",
    );
    assert!(
        policyd.take_secret_requests().await.is_empty(),
        "IsLocked and NoSuchObject must not invoke CheckSecret"
    );

    // 4. policyd RPC failure fails closed with AccessDenied.
    policyd.fail_check_secret.store(true, Ordering::SeqCst);
    assert_access_denied(
        unattr
            .call_method(
                Some(SECRETS_NAME),
                ITEM_HOST,
                Some("org.freedesktop.Secret.Item"),
                "GetSecret",
                &(session,),
            )
            .await,
        "policyd RPC error fails closed",
    );

    assert_no_secrets_dbus_fallback(&policyd).await;
    relay_task.abort();
}

#[tokio::test]
async fn relay_does_not_forward_name_acquired_signal_before_hello_reply() {
    let daemon = LocalDbusDaemon::start().await;
    let workdir = tempfile::tempdir().expect("create test workdir");
    let policyd = MockPolicyd::start(workdir.path(), Some("codex"));
    policyd.allow_name_acquired.store(true, Ordering::SeqCst);

    let StartedRelay {
        socket: relay_sock,
        task: relay_task,
    } = start_relay(
        workdir.path(),
        "hello-order",
        &daemon.address,
        &policyd.socket_path,
    )
    .await;

    let addr = format!("unix:path={}", relay_sock.display());
    for attempt in 0..20 {
        let conn = Builder::address(addr.as_str())
            .expect("relay addr")
            .build()
            .await
            .unwrap_or_else(|err| {
                panic!("bus handshake failed on attempt {attempt}: {err}");
            });
        assert!(conn.unique_name().is_some());
    }

    relay_task.abort();
}

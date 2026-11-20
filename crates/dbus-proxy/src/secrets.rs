//! Session-bus mediator for freedesktop Secret Service
//! (`org.freedesktop.secrets`).
//!
//! Traps all traffic addressed to `org.freedesktop.secrets` and its pinned
//! unique bus owner (`:1.x`) using a dedicated side-channel connection so
//! client serials and verbatim replies on the primary relay stream are never
//! disturbed.

use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::Duration,
};

use agent_sandbox_core::{
    policy::{DbusBus, RESERVED_SECRET_ATTRIBUTE_PREFIX},
    rpc::{RequestContext, RpcReply, RpcRequest},
    rpc_client::PersistentRpcClient,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use zbus::{
    Connection, MatchRule, MessageStream,
    connection::Builder,
    message::{Builder as MessageBuilder, Message, Type},
    zvariant::{OwnedObjectPath, OwnedValue, Type as ZType, Value},
};

use crate::{RelayError, rewrite_message_with_destination};

const SECRETS_WELL_KNOWN_NAME: &str = "org.freedesktop.secrets";
const OWNERSHIP_ATTRIBUTE: &str = "agent-sandbox:package";

const DBUS_SERVICE: &str = "org.freedesktop.DBus";
const DBUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";
const DBUS_INTROSPECTABLE_IFACE: &str = "org.freedesktop.DBus.Introspectable";
const DBUS_PEER_IFACE: &str = "org.freedesktop.DBus.Peer";

const SECRET_SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const SECRET_COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const SECRET_ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
const SECRET_SESSION_IFACE: &str = "org.freedesktop.Secret.Session";
const SECRET_PROMPT_IFACE: &str = "org.freedesktop.Secret.Prompt";

const ALLOWED_INTERFACES: [&str; 8] = [
    SECRET_SERVICE_IFACE,
    SECRET_COLLECTION_IFACE,
    SECRET_ITEM_IFACE,
    SECRET_SESSION_IFACE,
    SECRET_PROMPT_IFACE,
    DBUS_PROPERTIES_IFACE,
    DBUS_INTROSPECTABLE_IFACE,
    DBUS_PEER_IFACE,
];

const ERROR_ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
const ERROR_IS_LOCKED: &str = "org.freedesktop.Secret.Error.IsLocked";
const ERROR_NO_SUCH_OBJECT: &str = "org.freedesktop.Secret.Error.NoSuchObject";
const ERROR_UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const RESOLVE_PACKAGE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DISCOVERY_ITEMS: usize = 256;
const MAX_TRACKED_ITEM_HINTS: usize = 1024;

/// Action returned by [`SecretsMediator::handle_client_message`].
pub enum ClientAction {
    /// Message does not target Secret Service; continue normal D-Bus relay.
    NotSecrets,
    /// Forward this message upstream without invoking `CheckDbus`.
    Forward(Message),
    /// Reject the message with a D-Bus error reply to the client.
    ReplyError {
        /// D-Bus error name (e.g. `org.freedesktop.DBus.Error.AccessDenied`).
        name: &'static str,
        /// Human-readable error detail.
        detail: String,
    },
}

/// Action returned by [`SecretsMediator::handle_upstream_message`].
pub enum UpstreamAction {
    /// Message is not from the trapped Secret Service; continue normal relay.
    NotSecrets,
    /// Forward this message to the downstream client without `CheckDbus`.
    Forward(Message),
    /// Silently drop this upstream message (e.g. foreign-package signal).
    Drop,
}

#[derive(Debug, Default)]
struct OwnerState {
    owner: Option<String>,
    generation: u64,
}

#[derive(Debug, Clone)]
enum PendingReplyKind {
    Unlock { owner: String },
    ServiceSearchItems { owner: String },
    CollectionSearchItems { owner: String },
    CollectionItemsProp { owner: String },
    CollectionGetAllProps { owner: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemOwnership {
    OwnPackage,
    Host,
    OtherPackage,
}

#[derive(Debug)]
enum LookupError {
    IsLocked,
    NoSuchObject,
    Other(String),
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct NameOwnerChangedArgs {
    name: String,
    old_owner: String,
    new_owner: String,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct PropertiesGetArgs {
    interface: String,
    property: String,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct PropertiesGetAllArgs {
    interface: String,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct PropertiesSetHeader {
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
struct ServiceSearchItemsReply {
    unlocked: Vec<OwnedObjectPath>,
    locked: Vec<OwnedObjectPath>,
}

#[derive(Debug, Serialize, Deserialize, ZType)]
struct UnlockReply {
    unlocked: Vec<OwnedObjectPath>,
    prompt: OwnedObjectPath,
}

struct ActiveMediator {
    side_channel: Connection,
    owner_state: Arc<Mutex<OwnerState>>,
    owner_watch: JoinHandle<()>,
    last_seen_generation: u64,
    package_resolved: bool,
    package: Option<String>,
    in_flight: HashMap<NonZeroU32, PendingReplyKind>,
    tracked_prompts: HashSet<String>,
    /// Bounded cache of item paths observed as visible (`OwnPackage` or `Host`)
    /// so `ItemDeleted` signals for those items can still be forwarded after
    /// the daemon removes the object.
    known_visible_items: HashSet<String>,
}

impl Drop for ActiveMediator {
    fn drop(&mut self) {
        self.owner_watch.abort();
    }
}

/// Deep mediator for freedesktop Secret Service traffic on the session bus.
///
/// On non-session buses (`DbusBus::System`), every call is a no-op returning
/// `NotSecrets`.
pub struct SecretsMediator {
    active: Option<ActiveMediator>,
}

impl SecretsMediator {
    /// Construct a new mediator for `bus`. Opens a dedicated side-channel
    /// connection to `upstream_address` only when `bus == DbusBus::Session`.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError`] if the side-channel connection or owner watch
    /// cannot be established on the session bus.
    pub async fn new(upstream_address: String, bus: DbusBus) -> Result<Self, RelayError> {
        if bus != DbusBus::Session {
            return Ok(Self { active: None });
        }

        let side_channel = Builder::address(upstream_address.as_str())?
            .build()
            .await?;

        let watch_stream = Builder::address(upstream_address.as_str())?
            .build_message_stream()
            .await?;
        let watch_conn = Connection::from(&watch_stream);

        let match_rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(DBUS_SERVICE)?
            .interface(DBUS_SERVICE)?
            .member("NameOwnerChanged")?
            .arg(0, SECRETS_WELL_KNOWN_NAME)?
            .build();

        watch_conn
            .call_method(
                Some(DBUS_SERVICE),
                DBUS_PATH,
                Some(DBUS_SERVICE),
                "AddMatch",
                &(match_rule.to_string(),),
            )
            .await?;

        let initial_owner = query_name_owner(&side_channel).await;
        let owner_state = Arc::new(Mutex::new(OwnerState {
            owner: initial_owner,
            generation: 0,
        }));

        let owner_watch = spawn_owner_watcher(watch_stream, Arc::clone(&owner_state));

        Ok(Self {
            active: Some(ActiveMediator {
                side_channel,
                owner_state,
                owner_watch,
                last_seen_generation: 0,
                package_resolved: false,
                package: None,
                in_flight: HashMap::new(),
                tracked_prompts: HashSet::new(),
                known_visible_items: HashSet::new(),
            }),
        })
    }

    /// Mediate one downstream message sent by the sandboxed client.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError`] only on unrecoverable local message-building
    /// failures. Policy and daemon errors return `ClientAction::ReplyError`.
    pub async fn handle_client_message(
        &mut self,
        msg: &Message,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Result<ClientAction, RelayError> {
        let Some(active) = self.active.as_mut() else {
            return Ok(ClientAction::NotSecrets);
        };

        active.handle_client_message(msg, policy, ctx).await
    }

    /// Mediate one upstream message received from the host bus.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError`] only on unrecoverable local message-building
    /// failures.
    pub async fn handle_upstream_message(
        &mut self,
        msg: &Message,
    ) -> Result<UpstreamAction, RelayError> {
        let Some(active) = self.active.as_mut() else {
            return Ok(UpstreamAction::NotSecrets);
        };

        active.handle_upstream_message(msg).await
    }
}

impl ActiveMediator {
    fn sync_owner_generation(&mut self) -> Option<String> {
        let state = self
            .owner_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation != self.last_seen_generation {
            self.last_seen_generation = state.generation;
            self.tracked_prompts.clear();
            self.known_visible_items.clear();
        }
        state.owner.clone()
    }

    async fn resolve_pinned_owner(&mut self) -> Option<String> {
        if let Some(owner) = self.sync_owner_generation() {
            return Some(owner);
        }

        let refreshed = query_name_owner(&self.side_channel).await;
        if let Some(owner) = refreshed {
            let mut state = self
                .owner_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let changed = state.owner.as_deref() != Some(owner.as_str());
            if changed {
                state.owner = Some(owner.clone());
                state.generation = state.generation.wrapping_add(1);
                self.last_seen_generation = state.generation;
            }
            drop(state);
            if changed {
                self.tracked_prompts.clear();
                self.known_visible_items.clear();
            }
            return Some(owner);
        }

        None
    }

    async fn ensure_package(
        &mut self,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Result<Option<String>, ()> {
        if self.package_resolved {
            return Ok(self.package.clone());
        }

        match policy
            .request(
                RpcRequest::ResolveSandboxPackage { ctx: ctx.clone() },
                RESOLVE_PACKAGE_TIMEOUT,
            )
            .await
        {
            Ok(RpcReply::SandboxPackage(reply)) if reply.ok => {
                self.package.clone_from(&reply.package);
                self.package_resolved = true;
                Ok(reply.package)
            }
            Ok(other) => {
                warn!(reply = %other, "unexpected policyd reply for ResolveSandboxPackage");
                Err(())
            }
            Err(error) => {
                warn!(%error, "ResolveSandboxPackage RPC failed; failing closed");
                Err(())
            }
        }
    }

    async fn handle_client_message(
        &mut self,
        msg: &Message,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Result<ClientAction, RelayError> {
        let current_owner = self.sync_owner_generation();
        let header = msg.header();
        let Some(destination) = header.destination().map(|dest| dest.as_str()) else {
            return Ok(ClientAction::NotSecrets);
        };

        let is_well_known = destination == SECRETS_WELL_KNOWN_NAME;
        let is_unique_owner = current_owner
            .as_deref()
            .is_some_and(|owner| owner == destination);

        if !is_well_known && !is_unique_owner {
            return Ok(ClientAction::NotSecrets);
        }

        // Everything addressed to org.freedesktop.secrets or its unique owner is
        // strictly trapped and never falls through to CheckDbus.
        if msg.message_type() != Type::MethodCall {
            return Ok(access_denied(
                "only method calls are permitted to org.freedesktop.secrets",
            ));
        }

        let Some(owner) = self.resolve_pinned_owner().await else {
            return Ok(access_denied("org.freedesktop.secrets has no active owner"));
        };

        if !is_well_known && destination != owner {
            return Ok(access_denied("org.freedesktop.secrets owner changed"));
        }

        let Some(interface) = header.interface().map(|iface| iface.as_str()) else {
            return Ok(access_denied(
                "Secret Service calls must specify an allowed interface",
            ));
        };

        if !ALLOWED_INTERFACES.contains(&interface) {
            return Ok(access_denied(format!(
                "interface `{interface}` is not allowed on org.freedesktop.secrets"
            )));
        }

        let Some(member) = header.member().map(|name| name.as_str()) else {
            return Ok(access_denied("Secret Service call missing member"));
        };

        let object_path = header.path().map_or_default(|path| path.as_str()).to_owned();

        if self.ensure_package(policy, ctx).await.is_err() {
            return Ok(access_denied(
                "unable to verify sandbox package identity for Secret Service call",
            ));
        }

        let serial = header.primary().serial_num();

        match (interface, member) {
            // Safe session, alias, introspection, and peer ping pass-throughs.
            (SECRET_SERVICE_IFACE, "OpenSession" | "ReadAlias")
            | (SECRET_SESSION_IFACE, "Close")
            | (DBUS_INTROSPECTABLE_IFACE, "Introspect")
            | (DBUS_PEER_IFACE, "Ping") => {
                let forwarded = rewrite_message_with_destination(msg, serial, None, &owner)?;
                Ok(ClientAction::Forward(forwarded))
            }

            // Unconditionally denied collection-admin and rename operations.
            (SECRET_SERVICE_IFACE, "Lock" | "CreateCollection" | "SetAlias")
            | (SECRET_COLLECTION_IFACE, "Delete") => Ok(access_denied(format!(
                "{interface}.{member} is not permitted from inside a sandbox"
            ))),

            // Discovery calls: forward pinned and filter/sort their replies.
            (SECRET_SERVICE_IFACE, "SearchItems") => {
                let forwarded = rewrite_message_with_destination(msg, serial, None, &owner)?;
                self.in_flight
                    .insert(serial, PendingReplyKind::ServiceSearchItems { owner });
                Ok(ClientAction::Forward(forwarded))
            }

            (SECRET_COLLECTION_IFACE, "SearchItems") => {
                let forwarded = rewrite_message_with_destination(msg, serial, None, &owner)?;
                self.in_flight
                    .insert(serial, PendingReplyKind::CollectionSearchItems { owner });
                Ok(ClientAction::Forward(forwarded))
            }

            // Service.Unlock: reject other packages' items, track returned prompt.
            (SECRET_SERVICE_IFACE, "Unlock") => {
                self.handle_unlock(msg, serial, &owner).await
            }

            // Connection-local prompt lifecycle.
            (SECRET_PROMPT_IFACE, "Prompt") => {
                if !self.tracked_prompts.contains(&object_path) {
                    return Ok(access_denied(
                        "Prompt.Prompt denied for untracked prompt path",
                    ));
                }
                let forwarded = rewrite_message_with_destination(msg, serial, None, &owner)?;
                Ok(ClientAction::Forward(forwarded))
            }

            (SECRET_PROMPT_IFACE, "Dismiss") => {
                if !self.tracked_prompts.remove(&object_path) {
                    return Ok(access_denied(
                        "Prompt.Dismiss denied for untracked prompt path",
                    ));
                }
                let forwarded = rewrite_message_with_destination(msg, serial, None, &owner)?;
                Ok(ClientAction::Forward(forwarded))
            }

            // Properties.Get / Properties.GetAll / Properties.Set.
            (DBUS_PROPERTIES_IFACE, "Get") => {
                self.handle_properties_get(msg, serial, &object_path, &owner)
                    .await
            }

            (DBUS_PROPERTIES_IFACE, "GetAll") => {
                self.handle_properties_get_all(msg, serial, &object_path, &owner)
                    .await
            }

            (DBUS_PROPERTIES_IFACE, "Set") => {
                let Ok(args) = msg.body().deserialize::<PropertiesSetHeader>() else {
                    return Ok(access_denied("malformed Properties.Set body"));
                };
                if args.interface == SECRET_COLLECTION_IFACE && args.property == "Label" {
                    return Ok(access_denied(
                        "Collection.Label modification is not permitted from inside a sandbox",
                    ));
                }
                Ok(access_denied(format!(
                    "Properties.Set on {}.{} is denied",
                    args.interface, args.property
                )))
            }

            // Secret-bearing operations fail closed until gated mediation is wired.
            (SECRET_ITEM_IFACE, "GetSecret" | "SetSecret" | "Delete")
            | (SECRET_SERVICE_IFACE, "GetSecrets")
            | (SECRET_COLLECTION_IFACE, "CreateItem") => Ok(access_denied(format!(
                "{interface}.{member} is denied by Secret Service mediator"
            ))),

            _ => Ok(access_denied(format!(
                "{interface}.{member} is not permitted on org.freedesktop.secrets"
            ))),
        }
    }

    async fn handle_unlock(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        owner: &str,
    ) -> Result<ClientAction, RelayError> {
        let Ok(objects) = msg.body().deserialize::<Vec<OwnedObjectPath>>() else {
            return Ok(access_denied("malformed Service.Unlock body"));
        };

        for object in &objects {
            let path = object.as_str();
            if is_item_path(path) {
                match self.lookup_item_ownership(owner, path).await {
                    Ok(ItemOwnership::OwnPackage | ItemOwnership::Host) => {
                        self.record_visible_item(path);
                    }
                    Ok(ItemOwnership::OtherPackage) => {
                        return Ok(access_denied(
                            "Service.Unlock cannot target another package's secret item",
                        ));
                    }
                    Err(LookupError::IsLocked) => {
                        // Some daemons (e.g. KeePassXC / oo7-daemon) return IsLocked on
                        // locked items; allow Unlock to proceed so subsequent operations
                        // enforce ownership once unlocked.
                    }
                    Err(LookupError::NoSuchObject) => {
                        return Ok(ClientAction::ReplyError {
                            name: ERROR_NO_SUCH_OBJECT,
                            detail: format!("secret item `{path}` does not exist"),
                        });
                    }
                    Err(LookupError::Other(detail)) => {
                        debug!(%path, %detail, "Unlock ownership lookup failed; failing closed");
                        return Ok(access_denied("unable to verify item ownership for Unlock"));
                    }
                }
            } else if is_collection_or_alias_path(path) {
                // Collection paths and /aliases/* pass through.
            } else {
                return Ok(access_denied(format!(
                    "Service.Unlock rejected unsupported object path `{path}`"
                )));
            }
        }

        let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
        self.in_flight.insert(serial, PendingReplyKind::Unlock {
            owner: owner.to_owned(),
        });
        Ok(ClientAction::Forward(forwarded))
    }

    async fn handle_properties_get(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        object_path: &str,
        owner: &str,
    ) -> Result<ClientAction, RelayError> {
        let Ok(args) = msg.body().deserialize::<PropertiesGetArgs>() else {
            return Ok(access_denied("malformed Properties.Get body"));
        };

        match args.interface.as_str() {
            SECRET_SERVICE_IFACE => {
                let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
                Ok(ClientAction::Forward(forwarded))
            }

            SECRET_COLLECTION_IFACE => {
                let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
                if args.property == "Items" {
                    self.in_flight
                        .insert(serial, PendingReplyKind::CollectionItemsProp {
                            owner: owner.to_owned(),
                        });
                }
                Ok(ClientAction::Forward(forwarded))
            }

            SECRET_ITEM_IFACE => {
                self.forward_item_if_owned(msg, serial, object_path, owner, "Properties.Get")
                    .await
            }

            _ => Ok(access_denied(format!(
                "Properties.Get on interface `{}` is not permitted",
                args.interface
            ))),
        }
    }

    async fn handle_properties_get_all(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        object_path: &str,
        owner: &str,
    ) -> Result<ClientAction, RelayError> {
        let Ok(args) = msg.body().deserialize::<PropertiesGetAllArgs>() else {
            return Ok(access_denied("malformed Properties.GetAll body"));
        };

        match args.interface.as_str() {
            SECRET_SERVICE_IFACE => {
                let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
                Ok(ClientAction::Forward(forwarded))
            }

            SECRET_COLLECTION_IFACE => {
                let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
                self.in_flight
                    .insert(serial, PendingReplyKind::CollectionGetAllProps {
                        owner: owner.to_owned(),
                    });
                Ok(ClientAction::Forward(forwarded))
            }

            SECRET_ITEM_IFACE => {
                self.forward_item_if_owned(msg, serial, object_path, owner, "Properties.GetAll")
                    .await
            }

            _ => Ok(access_denied(format!(
                "Properties.GetAll on interface `{}` is not permitted",
                args.interface
            ))),
        }
    }

    async fn forward_item_if_owned(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        object_path: &str,
        owner: &str,
        operation: &str,
    ) -> Result<ClientAction, RelayError> {
        if !is_item_path(object_path) {
            return Ok(access_denied(format!(
                "{operation} for Item requires a concrete item path"
            )));
        }

        match self.lookup_item_ownership(owner, object_path).await {
            Ok(ItemOwnership::OwnPackage | ItemOwnership::Host) => {
                self.record_visible_item(object_path);
                let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
                Ok(ClientAction::Forward(forwarded))
            }
            Ok(ItemOwnership::OtherPackage) => Ok(access_denied(
                "secret item belongs to another package's partition",
            )),
            Err(LookupError::IsLocked) => Ok(ClientAction::ReplyError {
                name: ERROR_IS_LOCKED,
                detail: "secret item is locked".into(),
            }),
            Err(LookupError::NoSuchObject) => Ok(ClientAction::ReplyError {
                name: ERROR_NO_SUCH_OBJECT,
                detail: format!("secret item `{object_path}` does not exist"),
            }),
            Err(LookupError::Other(detail)) => {
                debug!(%object_path, %detail, %operation, "Item ownership lookup failed");
                Ok(access_denied("unable to verify secret item ownership"))
            }
        }
    }

    async fn handle_upstream_message(&mut self, msg: &Message) -> Result<UpstreamAction, RelayError> {
        let current_owner = self.sync_owner_generation();
        let header = msg.header();

        match msg.message_type() {
            Type::MethodReturn => {
                let Some(reply_serial) = header.reply_serial() else {
                    return Ok(UpstreamAction::NotSecrets);
                };
                let Some(kind) = self.in_flight.remove(&reply_serial) else {
                    return Ok(UpstreamAction::NotSecrets);
                };

                self.handle_tracked_reply(msg, reply_serial, kind, current_owner.as_deref())
                    .await
            }

            Type::Error => {
                if let Some(reply_serial) = header.reply_serial() {
                    let _ = self.in_flight.remove(&reply_serial);
                }
                Ok(UpstreamAction::NotSecrets)
            }

            Type::Signal => {
                let Some(sender) = header.sender().map(|s| s.as_str()) else {
                    return Ok(UpstreamAction::NotSecrets);
                };
                let is_secrets_sender = sender == SECRETS_WELL_KNOWN_NAME
                    || current_owner
                        .as_deref()
                        .is_some_and(|owner| owner == sender);
                if !is_secrets_sender {
                    return Ok(UpstreamAction::NotSecrets);
                }

                let owner = current_owner.unwrap_or_else(|| sender.to_owned());
                self.handle_upstream_signal(msg, &owner).await
            }

            Type::MethodCall => Ok(UpstreamAction::NotSecrets),
        }
    }

    async fn handle_tracked_reply(
        &mut self,
        msg: &Message,
        reply_serial: NonZeroU32,
        kind: PendingReplyKind,
        current_owner: Option<&str>,
    ) -> Result<UpstreamAction, RelayError> {
        match kind {
            PendingReplyKind::Unlock { owner } => {
                if current_owner == Some(owner.as_str())
                    && let Ok(reply) = msg.body().deserialize::<UnlockReply>()
                {
                    let prompt_path = reply.prompt.as_str();
                    if prompt_path != "/" && !prompt_path.is_empty() {
                        self.tracked_prompts.insert(prompt_path.to_owned());
                    }
                }
                Ok(UpstreamAction::Forward(msg.clone()))
            }

            PendingReplyKind::ServiceSearchItems { owner } => {
                let Ok(reply) = msg.body().deserialize::<ServiceSearchItemsReply>() else {
                    return Ok(UpstreamAction::Drop);
                };
                let unlocked = self.filter_and_sort_items(&owner, reply.unlocked).await;
                let locked = self.filter_and_sort_items(&owner, reply.locked).await;
                let rebuilt = rebuild_reply(msg, reply_serial, &ServiceSearchItemsReply {
                    unlocked,
                    locked,
                })?;
                Ok(UpstreamAction::Forward(rebuilt))
            }

            PendingReplyKind::CollectionSearchItems { owner } => {
                let Ok(items) = msg.body().deserialize::<Vec<OwnedObjectPath>>() else {
                    return Ok(UpstreamAction::Drop);
                };
                let filtered = self.filter_and_sort_items(&owner, items).await;
                let rebuilt = rebuild_reply(msg, reply_serial, &filtered)?;
                Ok(UpstreamAction::Forward(rebuilt))
            }

            PendingReplyKind::CollectionItemsProp { owner } => {
                let Ok(raw_value) = msg.body().deserialize::<OwnedValue>() else {
                    return Ok(UpstreamAction::Drop);
                };
                let Ok(items) = Vec::<OwnedObjectPath>::try_from(raw_value) else {
                    return Ok(UpstreamAction::Drop);
                };
                let filtered = self.filter_and_sort_items(&owner, items).await;
                let value = Value::from(filtered);
                let rebuilt = rebuild_reply(msg, reply_serial, &value)?;
                Ok(UpstreamAction::Forward(rebuilt))
            }

            PendingReplyKind::CollectionGetAllProps { owner } => {
                let Ok(mut props) = msg.body().deserialize::<HashMap<String, OwnedValue>>() else {
                    return Ok(UpstreamAction::Drop);
                };
                if let Some(items_val) = props.remove("Items") {
                    let Ok(items) = Vec::<OwnedObjectPath>::try_from(items_val) else {
                        return Ok(UpstreamAction::Drop);
                    };
                    let filtered = self.filter_and_sort_items(&owner, items).await;
                    let Ok(encoded) = OwnedValue::try_from(Value::from(filtered)) else {
                        return Ok(UpstreamAction::Drop);
                    };
                    props.insert("Items".to_owned(), encoded);
                }
                let rebuilt = rebuild_reply(msg, reply_serial, &props)?;
                Ok(UpstreamAction::Forward(rebuilt))
            }
        }
    }

    async fn handle_upstream_signal(
        &mut self,
        msg: &Message,
        owner: &str,
    ) -> Result<UpstreamAction, RelayError> {
        let header = msg.header();
        let Some(interface) = header.interface().map(|iface| iface.as_str()) else {
            return Ok(UpstreamAction::Drop);
        };
        let Some(member) = header.member().map(|name| name.as_str()) else {
            return Ok(UpstreamAction::Drop);
        };
        let object_path = header.path().map_or_default(|path| path.as_str());

        match (interface, member) {
            (SECRET_PROMPT_IFACE, "Completed") => {
                if self.tracked_prompts.remove(object_path) {
                    Ok(UpstreamAction::Forward(msg.clone()))
                } else {
                    Ok(UpstreamAction::Drop)
                }
            }

            (SECRET_COLLECTION_IFACE, "ItemCreated" | "ItemChanged") => {
                let Ok(item_path) = msg.body().deserialize::<OwnedObjectPath>() else {
                    return Ok(UpstreamAction::Drop);
                };
                match self.lookup_item_ownership(owner, item_path.as_str()).await {
                    Ok(ItemOwnership::OwnPackage | ItemOwnership::Host) => {
                        self.record_visible_item(item_path.as_str());
                        Ok(UpstreamAction::Forward(msg.clone()))
                    }
                    Ok(ItemOwnership::OtherPackage) | Err(_) => Ok(UpstreamAction::Drop),
                }
            }

            (SECRET_COLLECTION_IFACE, "ItemDeleted") => {
                let Ok(item_path) = msg.body().deserialize::<OwnedObjectPath>() else {
                    return Ok(UpstreamAction::Drop);
                };
                if self.known_visible_items.remove(item_path.as_str()) {
                    return Ok(UpstreamAction::Forward(msg.clone()));
                }
                match self.lookup_item_ownership(owner, item_path.as_str()).await {
                    Ok(ItemOwnership::OwnPackage | ItemOwnership::Host) => {
                        Ok(UpstreamAction::Forward(msg.clone()))
                    }
                    Ok(ItemOwnership::OtherPackage) | Err(_) => Ok(UpstreamAction::Drop),
                }
            }

            (
                SECRET_SERVICE_IFACE,
                "CollectionCreated" | "CollectionChanged" | "CollectionDeleted",
            ) => Ok(UpstreamAction::Forward(msg.clone())),

            (DBUS_PROPERTIES_IFACE, "PropertiesChanged") => {
                if is_item_path(object_path) {
                    match self.lookup_item_ownership(owner, object_path).await {
                        Ok(ItemOwnership::OwnPackage | ItemOwnership::Host) => {
                            self.record_visible_item(object_path);
                            Ok(UpstreamAction::Forward(msg.clone()))
                        }
                        Ok(ItemOwnership::OtherPackage) | Err(_) => Ok(UpstreamAction::Drop),
                    }
                } else if is_collection_or_alias_path(object_path) {
                    let Ok(mut args) = msg.body().deserialize::<PropertiesChangedArgs>() else {
                        return Ok(UpstreamAction::Drop);
                    };
                    if let Some(items_val) = args.changed.remove("Items") {
                        let Ok(items) = Vec::<OwnedObjectPath>::try_from(items_val) else {
                            return Ok(UpstreamAction::Drop);
                        };
                        let filtered = self.filter_and_sort_items(owner, items).await;
                        let Ok(encoded) = OwnedValue::try_from(Value::from(filtered)) else {
                            return Ok(UpstreamAction::Drop);
                        };
                        args.changed.insert("Items".to_owned(), encoded);
                        let rebuilt = rebuild_signal(msg, &args)?;
                        return Ok(UpstreamAction::Forward(rebuilt));
                    }
                    Ok(UpstreamAction::Forward(msg.clone()))
                } else if object_path == "/org/freedesktop/secrets" {
                    Ok(UpstreamAction::Forward(msg.clone()))
                } else {
                    Ok(UpstreamAction::Drop)
                }
            }

            _ => Ok(UpstreamAction::Drop),
        }
    }

    async fn filter_and_sort_items(
        &mut self,
        owner: &str,
        items: Vec<OwnedObjectPath>,
    ) -> Vec<OwnedObjectPath> {
        let mut own_items = Vec::new();
        let mut host_items = Vec::new();

        for item in items.into_iter().take(MAX_DISCOVERY_ITEMS) {
            match self.lookup_item_ownership(owner, item.as_str()).await {
                Ok(ItemOwnership::OwnPackage) => {
                    self.record_visible_item(item.as_str());
                    own_items.push(item);
                }
                Ok(ItemOwnership::Host) => {
                    self.record_visible_item(item.as_str());
                    host_items.push(item);
                }
                Ok(ItemOwnership::OtherPackage) | Err(_) => {}
            }
        }

        own_items.extend(host_items);
        own_items
    }

    async fn lookup_item_ownership(
        &self,
        owner: &str,
        item_path: &str,
    ) -> Result<ItemOwnership, LookupError> {
        let attributes = self.fetch_item_attributes(owner, item_path).await?;
        Ok(classify_ownership(&attributes, self.package.as_deref()))
    }

    async fn fetch_item_attributes(
        &self,
        owner: &str,
        item_path: &str,
    ) -> Result<HashMap<String, String>, LookupError> {
        let args = PropertiesGetArgs {
            interface: SECRET_ITEM_IFACE.to_owned(),
            property: "Attributes".to_owned(),
        };
        let call = self.side_channel.call_method(
            Some(owner),
            item_path,
            Some(DBUS_PROPERTIES_IFACE),
            "Get",
            &args,
        );

        let reply = match tokio::time::timeout(LOOKUP_TIMEOUT, call).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(zbus::Error::MethodError(name, detail, _))) => {
                let err_name = name.as_str();
                if err_name == ERROR_IS_LOCKED {
                    return Err(LookupError::IsLocked);
                }
                if err_name == ERROR_NO_SUCH_OBJECT || err_name == ERROR_UNKNOWN_OBJECT {
                    return Err(LookupError::NoSuchObject);
                }
                return Err(LookupError::Other(format!(
                    "{err_name}: {}",
                    detail.unwrap_or_default()
                )));
            }
            Ok(Err(error)) => return Err(LookupError::Other(error.to_string())),
            Err(_) => return Err(LookupError::Other("side-channel lookup timed out".into())),
        };

        let raw_value: OwnedValue = reply
            .body()
            .deserialize()
            .map_err(|error| LookupError::Other(format!("invalid Attributes reply: {error}")))?;

        HashMap::<String, String>::try_from(raw_value).map_err(|error| {
            LookupError::Other(format!("Attributes property is not a{{ss}}: {error}"))
        })
    }

    fn record_visible_item(&mut self, path: &str) {
        if self.known_visible_items.len() >= MAX_TRACKED_ITEM_HINTS {
            self.known_visible_items.clear();
        }
        self.known_visible_items.insert(path.to_owned());
    }
}

fn classify_ownership(
    attributes: &HashMap<String, String>,
    caller_package: Option<&str>,
) -> ItemOwnership {
    match attributes.get(OWNERSHIP_ATTRIBUTE) {
        None => {
            // Also guard against any unexpected reserved attribute key.
            if attributes
                .keys()
                .any(|key| key.starts_with(RESERVED_SECRET_ATTRIBUTE_PREFIX))
            {
                ItemOwnership::OtherPackage
            } else {
                ItemOwnership::Host
            }
        }
        Some(tag) => {
            if caller_package == Some(tag.as_str()) {
                ItemOwnership::OwnPackage
            } else {
                ItemOwnership::OtherPackage
            }
        }
    }
}

fn is_item_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/org/freedesktop/secrets/collection/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let Some(collection) = segments.next() else {
        return false;
    };
    let Some(item) = segments.next() else {
        return false;
    };
    !collection.is_empty() && !item.is_empty() && segments.next().is_none()
}

fn is_collection_or_alias_path(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("/org/freedesktop/secrets/collection/") {
        return !rest.is_empty() && !rest.contains('/');
    }
    if let Some(rest) = path.strip_prefix("/org/freedesktop/secrets/aliases/") {
        return !rest.is_empty() && !rest.contains('/');
    }
    false
}

fn access_denied(detail: impl Into<String>) -> ClientAction {
    ClientAction::ReplyError {
        name: ERROR_ACCESS_DENIED,
        detail: detail.into(),
    }
}

fn rebuild_reply<B: Serialize + ZType>(
    original: &Message,
    reply_serial: NonZeroU32,
    body: &B,
) -> Result<Message, RelayError> {
    let header = original.header();
    let serial = header.primary().serial_num();
    let builder = MessageBuilder::from(header)
        .reply_serial(Some(reply_serial))
        .serial(serial);

    Ok(builder.build(body)?)
}

fn rebuild_signal<B: Serialize + ZType>(
    original: &Message,
    body: &B,
) -> Result<Message, RelayError> {
    let header = original.header();
    let path = header
        .path()
        .ok_or_else(|| RelayError::Message("upstream signal missing path".into()))?;
    let interface = header
        .interface()
        .ok_or_else(|| RelayError::Message("upstream signal missing interface".into()))?;
    let member = header
        .member()
        .ok_or_else(|| RelayError::Message("upstream signal missing member".into()))?;

    let mut builder = Message::signal(path.clone(), interface.clone(), member.clone())?
        .serial(header.primary().serial_num());
    if let Some(sender) = header.sender() {
        builder = builder.sender(sender.clone())?;
    }
    if let Some(destination) = header.destination() {
        builder = builder.destination(destination.clone())?;
    }

    Ok(builder.build(body)?)
}

async fn query_name_owner(connection: &Connection) -> Option<String> {
    let call = connection.call_method(
        Some(DBUS_SERVICE),
        DBUS_PATH,
        Some(DBUS_SERVICE),
        "GetNameOwner",
        &(SECRETS_WELL_KNOWN_NAME,),
    );

    match tokio::time::timeout(LOOKUP_TIMEOUT, call).await {
        Ok(Ok(reply)) => reply.body().deserialize::<String>().ok(),
        Ok(Err(_)) | Err(_) => None,
    }
}

fn spawn_owner_watcher(
    mut stream: MessageStream,
    owner_state: Arc<Mutex<OwnerState>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(item) = stream.next().await {
            let Ok(msg) = item else {
                break;
            };
            if msg.message_type() != Type::Signal {
                continue;
            }
            let header = msg.header();
            if header.interface().map(|i| i.as_str()) != Some(DBUS_SERVICE)
                || header.member().map(|m| m.as_str()) != Some("NameOwnerChanged")
            {
                continue;
            }
            let Ok(args) = msg.body().deserialize::<NameOwnerChangedArgs>() else {
                continue;
            };
            if args.name != SECRETS_WELL_KNOWN_NAME {
                continue;
            }
            let next_owner = (!args.new_owner.is_empty()).then_some(args.new_owner);
            let mut state = owner_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.owner != next_owner {
                state.owner = next_owner;
                state.generation = state.generation.wrapping_add(1);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use zbus::{message::Message, zvariant::OwnedObjectPath};

    use super::{
        ItemOwnership, ServiceSearchItemsReply, UnlockReply, classify_ownership,
        is_collection_or_alias_path, is_item_path,
    };

    #[test]
    fn ownership_classification_isolates_other_packages_and_unattributed_callers() {
        let host = HashMap::from([("service".to_owned(), "gh".to_owned())]);
        let codex = HashMap::from([
            ("service".to_owned(), "openai".to_owned()),
            ("agent-sandbox:package".to_owned(), "codex".to_owned()),
        ]);
        let omp = HashMap::from([
            ("service".to_owned(), "openai".to_owned()),
            ("agent-sandbox:package".to_owned(), "omp".to_owned()),
        ]);

        assert_eq!(classify_ownership(&host, Some("codex")), ItemOwnership::Host);
        assert_eq!(classify_ownership(&host, None), ItemOwnership::Host);
        assert_eq!(
            classify_ownership(&codex, Some("codex")),
            ItemOwnership::OwnPackage
        );
        assert_eq!(
            classify_ownership(&omp, Some("codex")),
            ItemOwnership::OtherPackage
        );
        assert_eq!(classify_ownership(&codex, None), ItemOwnership::OtherPackage);
    }

    #[test]
    fn item_and_collection_path_classifiers_match_spec_segments() {
        assert!(is_item_path("/org/freedesktop/secrets/collection/kdewallet/9"));
        assert!(!is_item_path("/org/freedesktop/secrets/collection/kdewallet"));
        assert!(!is_item_path("/org/freedesktop/secrets/collection/kdewallet/9/extra"));
        assert!(!is_item_path("/org/freedesktop/secrets/aliases/default"));

        assert!(is_collection_or_alias_path(
            "/org/freedesktop/secrets/collection/kdewallet"
        ));
        assert!(is_collection_or_alias_path(
            "/org/freedesktop/secrets/aliases/default"
        ));
        assert!(!is_collection_or_alias_path(
            "/org/freedesktop/secrets/collection/kdewallet/9"
        ));
    }

    #[test]
    fn struct_bodies_encode_multi_arg_dbus_signatures_without_tuples() {
        let path = OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/c/1")
            .expect("valid object path");
        let prompt = OwnedObjectPath::try_from("/org/freedesktop/secrets/prompt/p1")
            .expect("valid prompt path");

        let search_msg = Message::method_call("/org/freedesktop/secrets", "Dummy")
            .expect("builder")
            .build(&ServiceSearchItemsReply {
                unlocked: vec![path.clone()],
                locked: Vec::new(),
            })
            .expect("build ServiceSearchItemsReply");
        assert_eq!(search_msg.header().signature().to_string_no_parens(), "aoao");

        let unlock_msg = Message::method_call("/org/freedesktop/secrets", "Dummy")
            .expect("builder")
            .build(&UnlockReply {
                unlocked: vec![path],
                prompt,
            })
            .expect("build UnlockReply");
        assert_eq!(unlock_msg.header().signature().to_string_no_parens(), "aoo");
    }
}

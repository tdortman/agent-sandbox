//! Session-bus mediator for freedesktop Secret Service
//! (`org.freedesktop.secrets`).
//!
//! Traps all traffic addressed to `org.freedesktop.secrets` and its pinned
//! unique bus owner (`:1.x`) using a dedicated side-channel connection so
//! client serials and verbatim replies on the primary relay stream are never
//! disturbed.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::Duration,
};

use agent_sandbox_core::{
    policy::{
        DbusBus, RESERVED_SECRET_ATTRIBUTE_PREFIX, SecretAccess, SecretBatchInfo, SecretOperation,
        SecretPartition, SecretRequest,
    },
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

use crate::{POLICY_TIMEOUT, RelayError, rewrite_message_with_destination};

const SECRETS_WELL_KNOWN_NAME: &str = "org.freedesktop.secrets";
const SECRETS_SERVICE_PATH: &str = "/org/freedesktop/secrets";
const OWNERSHIP_ATTRIBUTE: &str = "agent-sandbox:package";
const ITEM_ATTRIBUTES_PROP_KEY: &str = "org.freedesktop.Secret.Item.Attributes";
const ITEM_LABEL_PROP_KEY: &str = "org.freedesktop.Secret.Item.Label";
const DAEMON_SYNTHESIZED_ATTRIBUTES: [&str; 4] = ["Uuid", "Path", "Totp", "xdg:content-type"];

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
const MAX_GET_SECRETS_BATCH: usize = 64;
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
    CreateItem { owner: String },
    Delete { owner: String },
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum CollectionTarget<'a> {
    Concrete(&'a str),
    Alias(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedCollection {
    segment: String,
    is_default_collection: bool,
}

#[derive(Debug)]
struct AccessibleItemMetadata {
    partition: SecretPartition,
    raw_attributes: HashMap<String, String>,
    label: String,
    collection: ResolvedCollection,
}

#[derive(Debug)]
enum AccessibleItem {
    Allowed(AccessibleItemMetadata),
    OtherPackage,
}

#[derive(Debug)]
struct BatchLookupItem {
    path: String,
    meta: AccessibleItemMetadata,
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
struct GetSecretsArgs {
    items: Vec<OwnedObjectPath>,
    session: OwnedObjectPath,
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

        let side_channel = Builder::address(upstream_address.as_str())?.build().await?;

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

        // Everything addressed to org.freedesktop.secrets or its unique owner
        // is strictly trapped and never falls through to CheckDbus.
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

        let object_path = header
            .path()
            .map_or_default(|path| path.as_str())
            .to_owned();

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

            // Service.Unlock: reject other packages' items, track returned
            // prompt.
            (SECRET_SERVICE_IFACE, "Unlock") => self.handle_unlock(msg, serial, &owner).await,

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
                self.handle_properties_set(msg, serial, &object_path, &owner, policy, ctx)
                    .await
            }

            // Gated secret reads, writes, and deletes.
            (SECRET_ITEM_IFACE, "GetSecret") => {
                self.handle_get_secret(msg, serial, &object_path, &owner, policy, ctx)
                    .await
            }

            (SECRET_SERVICE_IFACE, "GetSecrets") => {
                self.handle_get_secrets(msg, serial, &owner, policy, ctx)
                    .await
            }

            (SECRET_COLLECTION_IFACE, "CreateItem") => {
                self.handle_create_item(msg, serial, &object_path, &owner, policy, ctx)
                    .await
            }

            (SECRET_ITEM_IFACE, "SetSecret") => {
                self.handle_set_secret(msg, serial, &object_path, &owner, policy, ctx)
                    .await
            }

            (SECRET_ITEM_IFACE, "Delete") => {
                self.handle_delete_item(msg, serial, &object_path, &owner, policy, ctx)
                    .await
            }

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
                        // Some daemons (e.g. KeePassXC / oo7-daemon) return
                        // IsLocked on locked items; allow Unlock to proceed so
                        // subsequent operations enforce ownership once
                        // unlocked.
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
                if !self.owner_matches(owner) {
                    return Ok(access_denied("org.freedesktop.secrets owner changed"));
                }
                self.record_visible_item(object_path);
                let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
                Ok(ClientAction::Forward(forwarded))
            }
            Ok(ItemOwnership::OtherPackage) => Ok(access_denied(
                "secret item belongs to another package's partition",
            )),
            Err(error) => Ok(lookup_error_action(error, object_path, operation)),
        }
    }

    async fn handle_get_secret(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        object_path: &str,
        owner: &str,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Result<ClientAction, RelayError> {
        if msg.body().deserialize::<OwnedObjectPath>().is_err() {
            return Ok(access_denied("malformed Item.GetSecret body"));
        }

        self.authorize_single_item(
            msg,
            serial,
            object_path,
            owner,
            SecretAccess::Read,
            SecretOperation::GetSecret,
            "Item.GetSecret",
            policy,
            ctx,
        )
        .await
    }

    async fn authorize_single_item(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        object_path: &str,
        owner: &str,
        access: SecretAccess,
        operation: SecretOperation,
        op_name: &str,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Result<ClientAction, RelayError> {
        if !is_item_path(object_path) {
            return Ok(access_denied(format!(
                "{op_name} requires a concrete item path"
            )));
        }

        let meta = match self.lookup_accessible_item(owner, object_path).await {
            Ok(AccessibleItem::Allowed(meta)) => meta,
            Ok(AccessibleItem::OtherPackage) => {
                return Ok(access_denied(format!(
                    "{op_name} cannot access another package's secret"
                )));
            }
            Err(error) => return Ok(lookup_error_action(error, object_path, op_name)),
        };

        let request = meta.into_request(access, operation, None);
        if !check_secret(policy, request, ctx).await {
            return Ok(access_denied(format!("{op_name} denied by policy")));
        }
        if !self.owner_matches(owner) {
            return Ok(access_denied("org.freedesktop.secrets owner changed"));
        }

        self.record_visible_item(object_path);
        let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
        Ok(ClientAction::Forward(forwarded))
    }

    async fn handle_get_secrets(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        owner: &str,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Result<ClientAction, RelayError> {
        let Ok(args) = msg.body().deserialize::<GetSecretsArgs>() else {
            return Ok(access_denied("malformed Service.GetSecrets body"));
        };

        if args.items.len() > MAX_GET_SECRETS_BATCH {
            return Ok(access_denied(format!(
                "Service.GetSecrets batch size {} exceeds cap of {MAX_GET_SECRETS_BATCH}",
                args.items.len()
            )));
        }

        if args.items.is_empty() {
            if !self.owner_matches(owner) {
                return Ok(access_denied("org.freedesktop.secrets owner changed"));
            }
            let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
            return Ok(ClientAction::Forward(forwarded));
        }

        // Perform all fresh side-channel lookups first so foreign-package,
        // locked, or missing items fail immediately without spawning spurious
        // approval prompts for earlier items in the batch.
        let mut looked_up = Vec::with_capacity(args.items.len());
        for item in &args.items {
            let path = item.as_str();
            if !is_item_path(path) {
                return Ok(access_denied(format!(
                    "Service.GetSecrets rejected non-item path `{path}`"
                )));
            }
            match self.lookup_accessible_item(owner, path).await {
                Ok(AccessibleItem::Allowed(meta)) => looked_up.push(BatchLookupItem {
                    path: path.to_owned(),
                    meta,
                }),
                Ok(AccessibleItem::OtherPackage) => {
                    return Ok(access_denied(
                        "Service.GetSecrets cannot access another package's secret",
                    ));
                }
                Err(error) => return Ok(lookup_error_action(error, path, "Service.GetSecrets")),
            }
        }

        let Ok(total) = u32::try_from(looked_up.len()) else {
            return Ok(access_denied("Service.GetSecrets batch size overflow"));
        };

        let mut paths_to_record = Vec::with_capacity(looked_up.len());
        for (idx, item) in looked_up.into_iter().enumerate() {
            let Ok(index) = u32::try_from(idx + 1) else {
                return Ok(access_denied("Service.GetSecrets batch index overflow"));
            };
            let batch = (total > 1).then_some(SecretBatchInfo { index, total });
            let request =
                item.meta
                    .into_request(SecretAccess::Read, SecretOperation::GetSecrets, batch);
            if !check_secret(policy, request, ctx).await {
                return Ok(access_denied("Service.GetSecrets denied by policy"));
            }
            paths_to_record.push(item.path);
        }

        if !self.owner_matches(owner) {
            return Ok(access_denied("org.freedesktop.secrets owner changed"));
        }
        for path in paths_to_record {
            self.record_visible_item(&path);
        }
        let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
        Ok(ClientAction::Forward(forwarded))
    }

    async fn handle_create_item(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        object_path: &str,
        owner: &str,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Result<ClientAction, RelayError> {
        if !is_collection_or_alias_path(object_path) {
            return Ok(access_denied(
                "Collection.CreateItem requires a collection or alias path",
            ));
        }

        let Ok(mut args) = msg.body().deserialize::<CreateItemArgs>() else {
            return Ok(access_denied("malformed Collection.CreateItem body"));
        };

        let mut client_attrs = match args.properties.get(ITEM_ATTRIBUTES_PROP_KEY) {
            Some(value) => {
                let Ok(cloned) = value.try_clone() else {
                    return Ok(access_denied("malformed Item.Attributes in CreateItem"));
                };
                let Ok(map) = HashMap::<String, String>::try_from(cloned) else {
                    return Ok(access_denied("Item.Attributes in CreateItem must be a{ss}"));
                };
                map
            }
            None => HashMap::new(),
        };

        if has_reserved_attribute(&client_attrs) {
            return Ok(access_denied(
                "CreateItem attributes must not use reserved `agent-sandbox:` prefix",
            ));
        }

        let label = match args.properties.get(ITEM_LABEL_PROP_KEY) {
            Some(value) => {
                let Ok(cloned) = value.try_clone() else {
                    return Ok(access_denied("malformed Item.Label in CreateItem"));
                };
                let Ok(text) = String::try_from(cloned) else {
                    return Ok(access_denied("Item.Label in CreateItem must be a string"));
                };
                text
            }
            None => String::new(),
        };

        let resolved = match self.resolve_collection(owner, object_path).await {
            Ok(resolved) => resolved,
            Err(error) => {
                return Ok(lookup_error_action(
                    error,
                    object_path,
                    "Collection.CreateItem",
                ));
            }
        };

        let normalized_attrs = normalize_attributes(&client_attrs);
        let partition = if let Some(pkg) = self.package.clone() {
            client_attrs.insert(OWNERSHIP_ATTRIBUTE.to_owned(), pkg);
            let Ok(encoded) = OwnedValue::try_from(Value::from(client_attrs)) else {
                return Ok(access_denied("failed to encode CreateItem attributes"));
            };
            args.properties
                .insert(ITEM_ATTRIBUTES_PROP_KEY.to_owned(), encoded);
            SecretPartition::OwnPackage
        } else {
            SecretPartition::Host
        };

        let request = SecretRequest {
            partition,
            collection: resolved.segment,
            is_default_collection: resolved.is_default_collection,
            attributes: normalized_attrs,
            label,
            access: SecretAccess::Write,
            operation: SecretOperation::CreateItem,
            replace: args.replace,
            batch: None,
        };

        if !check_secret(policy, request, ctx).await {
            return Ok(access_denied("Collection.CreateItem denied by policy"));
        }
        if !self.owner_matches(owner) {
            return Ok(access_denied("org.freedesktop.secrets owner changed"));
        }

        let forwarded = rebuild_method_call(msg, serial, owner, &args)?;
        self.in_flight.insert(serial, PendingReplyKind::CreateItem {
            owner: owner.to_owned(),
        });
        Ok(ClientAction::Forward(forwarded))
    }

    async fn handle_set_secret(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        object_path: &str,
        owner: &str,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Result<ClientAction, RelayError> {
        if msg.body().deserialize::<SetSecretArgs>().is_err() {
            return Ok(access_denied("malformed Item.SetSecret body"));
        }

        self.authorize_single_item(
            msg,
            serial,
            object_path,
            owner,
            SecretAccess::Write,
            SecretOperation::SetSecret,
            "Item.SetSecret",
            policy,
            ctx,
        )
        .await
    }

    async fn handle_delete_item(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        object_path: &str,
        owner: &str,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Result<ClientAction, RelayError> {
        let action = self
            .authorize_single_item(
                msg,
                serial,
                object_path,
                owner,
                SecretAccess::Delete,
                SecretOperation::Delete,
                "Item.Delete",
                policy,
                ctx,
            )
            .await?;

        if matches!(action, ClientAction::Forward(_)) {
            self.in_flight.insert(serial, PendingReplyKind::Delete {
                owner: owner.to_owned(),
            });
        }
        Ok(action)
    }

    async fn authorize_dual_identity(
        &mut self,
        old_request: SecretRequest,
        new_request: SecretRequest,
        owner: &str,
        op_name: &str,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Option<ClientAction> {
        if !check_secret(policy, old_request.clone(), ctx).await {
            return Some(access_denied(format!("{op_name} denied by policy")));
        }
        if new_request != old_request && !check_secret(policy, new_request, ctx).await {
            return Some(access_denied(format!(
                "{op_name} denied for proposed identity"
            )));
        }
        if !self.owner_matches(owner) {
            return Some(access_denied("org.freedesktop.secrets owner changed"));
        }
        None
    }

    async fn handle_properties_set(
        &mut self,
        msg: &Message,
        serial: NonZeroU32,
        object_path: &str,
        owner: &str,
        policy: &mut PersistentRpcClient,
        ctx: &RequestContext,
    ) -> Result<ClientAction, RelayError> {
        let Ok(args) = msg.body().deserialize::<PropertiesSetArgs>() else {
            return Ok(access_denied("malformed Properties.Set body"));
        };

        if args.interface == SECRET_COLLECTION_IFACE && args.property == "Label" {
            return Ok(access_denied(
                "Collection.Label modification is not permitted from inside a sandbox",
            ));
        }

        if args.interface != SECRET_ITEM_IFACE {
            return Ok(access_denied(format!(
                "Properties.Set on {}.{} is denied",
                args.interface, args.property
            )));
        }

        if !is_item_path(object_path) {
            return Ok(access_denied(
                "Properties.Set for Item requires a concrete item path",
            ));
        }

        match args.property.as_str() {
            "Attributes" => {
                let Ok(mut proposed_attrs) = HashMap::<String, String>::try_from(args.value) else {
                    return Ok(access_denied("Item.Attributes update must be a{ss}"));
                };
                if has_reserved_attribute(&proposed_attrs) {
                    return Ok(access_denied(
                        "Item.Attributes update must not use reserved `agent-sandbox:` prefix",
                    ));
                }

                let meta = match self.lookup_accessible_item(owner, object_path).await {
                    Ok(AccessibleItem::Allowed(meta)) => meta,
                    Ok(AccessibleItem::OtherPackage) => {
                        return Ok(access_denied(
                            "Properties.Set cannot modify another package's secret",
                        ));
                    }
                    Err(error) => {
                        return Ok(lookup_error_action(
                            error,
                            object_path,
                            "Properties.Set(Item, Attributes)",
                        ));
                    }
                };

                let existing_tag = meta.raw_attributes.get(OWNERSHIP_ATTRIBUTE).cloned();
                let old_request =
                    meta.into_request(SecretAccess::Write, SecretOperation::SetAttributes, None);
                let mut new_request = old_request.clone();
                new_request.attributes = normalize_attributes(&proposed_attrs);

                if let Some(denial) = self
                    .authorize_dual_identity(
                        old_request,
                        new_request,
                        owner,
                        "Properties.Set(Item, Attributes)",
                        policy,
                        ctx,
                    )
                    .await
                {
                    return Ok(denial);
                }

                // Preserve any existing ownership tag unconditionally so a
                // sandbox can never move an item out of its secret partition.
                if let Some(tag) = existing_tag {
                    proposed_attrs.insert(OWNERSHIP_ATTRIBUTE.to_owned(), tag);
                }
                let Ok(encoded) = OwnedValue::try_from(Value::from(proposed_attrs)) else {
                    return Ok(access_denied("failed to encode Item.Attributes update"));
                };
                let rewritten = PropertiesSetArgs {
                    interface: SECRET_ITEM_IFACE.to_owned(),
                    property: "Attributes".to_owned(),
                    value: encoded,
                };
                let forwarded = rebuild_method_call(msg, serial, owner, &rewritten)?;
                self.record_visible_item(object_path);
                Ok(ClientAction::Forward(forwarded))
            }

            "Label" => {
                let Ok(proposed_label) = String::try_from(args.value) else {
                    return Ok(access_denied("Item.Label update must be a string"));
                };

                let meta = match self.lookup_accessible_item(owner, object_path).await {
                    Ok(AccessibleItem::Allowed(meta)) => meta,
                    Ok(AccessibleItem::OtherPackage) => {
                        return Ok(access_denied(
                            "Properties.Set cannot modify another package's secret",
                        ));
                    }
                    Err(error) => {
                        return Ok(lookup_error_action(
                            error,
                            object_path,
                            "Properties.Set(Item, Label)",
                        ));
                    }
                };

                let old_request =
                    meta.into_request(SecretAccess::Write, SecretOperation::SetLabel, None);
                let mut new_request = old_request.clone();
                new_request.label = proposed_label;

                if let Some(denial) = self
                    .authorize_dual_identity(
                        old_request,
                        new_request,
                        owner,
                        "Properties.Set(Item, Label)",
                        policy,
                        ctx,
                    )
                    .await
                {
                    return Ok(denial);
                }

                self.record_visible_item(object_path);
                let forwarded = rewrite_message_with_destination(msg, serial, None, owner)?;
                Ok(ClientAction::Forward(forwarded))
            }

            other => Ok(access_denied(format!(
                "Properties.Set on {SECRET_ITEM_IFACE}.{other} is denied"
            ))),
        }
    }

    async fn handle_upstream_message(
        &mut self,
        msg: &Message,
    ) -> Result<UpstreamAction, RelayError> {
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

            PendingReplyKind::CreateItem { owner } => {
                if current_owner == Some(owner.as_str())
                    && let Ok(reply) = msg.body().deserialize::<CreateItemReply>()
                {
                    if is_item_path(reply.item.as_str()) {
                        self.record_visible_item(reply.item.as_str());
                    }
                    let prompt_path = reply.prompt.as_str();
                    if prompt_path != "/" && !prompt_path.is_empty() {
                        self.tracked_prompts.insert(prompt_path.to_owned());
                    }
                }
                Ok(UpstreamAction::Forward(msg.clone()))
            }

            PendingReplyKind::Delete { owner } => {
                if current_owner == Some(owner.as_str())
                    && let Ok(prompt) = msg.body().deserialize::<OwnedObjectPath>()
                {
                    let prompt_path = prompt.as_str();
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

    fn owner_matches(&mut self, expected_owner: &str) -> bool {
        self.sync_owner_generation().as_deref() == Some(expected_owner)
    }

    async fn lookup_accessible_item(
        &self,
        owner: &str,
        item_path: &str,
    ) -> Result<AccessibleItem, LookupError> {
        let Some(segment) = parse_item_collection(item_path) else {
            return Err(LookupError::Other(format!(
                "invalid item path `{item_path}`"
            )));
        };

        let raw_attributes = self.fetch_item_attributes(owner, item_path).await?;
        let partition = match classify_ownership(&raw_attributes, self.package.as_deref()) {
            ItemOwnership::OwnPackage => SecretPartition::OwnPackage,
            ItemOwnership::Host => SecretPartition::Host,
            ItemOwnership::OtherPackage => return Ok(AccessibleItem::OtherPackage),
        };

        let label = self.fetch_item_label(owner, item_path).await?;
        let collection = self.resolve_concrete_collection(owner, segment).await?;

        Ok(AccessibleItem::Allowed(AccessibleItemMetadata {
            partition,
            raw_attributes,
            label,
            collection,
        }))
    }

    async fn resolve_collection(
        &self,
        owner: &str,
        collection_path: &str,
    ) -> Result<ResolvedCollection, LookupError> {
        let Some(target) = parse_collection_or_alias(collection_path) else {
            return Err(LookupError::Other(format!(
                "invalid collection path `{collection_path}`"
            )));
        };

        match target {
            CollectionTarget::Concrete(segment) => {
                self.resolve_concrete_collection(owner, segment).await
            }
            CollectionTarget::Alias("default") => {
                let Some(segment) = self.read_alias(owner, "default").await? else {
                    return Err(LookupError::NoSuchObject);
                };
                Ok(ResolvedCollection {
                    segment,
                    is_default_collection: true,
                })
            }
            CollectionTarget::Alias(alias) => {
                let Some(segment) = self.read_alias(owner, alias).await? else {
                    return Err(LookupError::NoSuchObject);
                };
                self.resolve_concrete_collection(owner, &segment).await
            }
        }
    }

    async fn resolve_concrete_collection(
        &self,
        owner: &str,
        segment: &str,
    ) -> Result<ResolvedCollection, LookupError> {
        let default_segment = self.read_alias(owner, "default").await?;
        Ok(ResolvedCollection {
            segment: segment.to_owned(),
            is_default_collection: default_segment.as_deref() == Some(segment),
        })
    }

    async fn read_alias(&self, owner: &str, alias: &str) -> Result<Option<String>, LookupError> {
        let reply = await_side_channel_call(self.side_channel.call_method(
            Some(owner),
            SECRETS_SERVICE_PATH,
            Some(SECRET_SERVICE_IFACE),
            "ReadAlias",
            &(alias,),
        ))
        .await?;
        let path: OwnedObjectPath = reply
            .body()
            .deserialize()
            .map_err(|error| LookupError::Other(format!("invalid ReadAlias reply: {error}")))?;

        let raw = path.as_str();
        if raw == "/" || raw.is_empty() {
            return Ok(None);
        }

        match parse_collection_or_alias(raw) {
            Some(CollectionTarget::Concrete(segment)) => Ok(Some(segment.to_owned())),
            _ => Err(LookupError::Other(format!(
                "ReadAlias(`{alias}`) returned unexpected collection path `{raw}`"
            ))),
        }
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
        let raw_value = self
            .side_channel_get_property(owner, item_path, SECRET_ITEM_IFACE, "Attributes")
            .await?;

        HashMap::<String, String>::try_from(raw_value).map_err(|error| {
            LookupError::Other(format!("Attributes property is not a{{ss}}: {error}"))
        })
    }

    async fn fetch_item_label(&self, owner: &str, item_path: &str) -> Result<String, LookupError> {
        let raw_value = self
            .side_channel_get_property(owner, item_path, SECRET_ITEM_IFACE, "Label")
            .await?;

        String::try_from(raw_value)
            .map_err(|error| LookupError::Other(format!("Label property is not a string: {error}")))
    }

    async fn side_channel_get_property(
        &self,
        owner: &str,
        item_path: &str,
        interface: &str,
        property: &str,
    ) -> Result<OwnedValue, LookupError> {
        let args = PropertiesGetArgs {
            interface: interface.to_owned(),
            property: property.to_owned(),
        };
        let call = self.side_channel.call_method(
            Some(owner),
            item_path,
            Some(DBUS_PROPERTIES_IFACE),
            "Get",
            &args,
        );
        let reply = await_side_channel_call(call).await?;
        reply.body().deserialize().map_err(|error| {
            LookupError::Other(format!("invalid {property} property reply: {error}"))
        })
    }

    fn record_visible_item(&mut self, path: &str) {
        if self.known_visible_items.len() >= MAX_TRACKED_ITEM_HINTS {
            self.known_visible_items.clear();
        }
        self.known_visible_items.insert(path.to_owned());
    }
}

impl AccessibleItemMetadata {
    fn into_request(
        self,
        access: SecretAccess,
        operation: SecretOperation,
        batch: Option<SecretBatchInfo>,
    ) -> SecretRequest {
        SecretRequest {
            partition: self.partition,
            collection: self.collection.segment,
            is_default_collection: self.collection.is_default_collection,
            attributes: normalize_attributes(&self.raw_attributes),
            label: self.label,
            access,
            operation,
            replace: false,
            batch,
        }
    }
}

async fn await_side_channel_call(
    call: impl std::future::Future<Output = zbus::Result<Message>>,
) -> Result<Message, LookupError> {
    match tokio::time::timeout(LOOKUP_TIMEOUT, call).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(zbus::Error::MethodError(name, detail, _))) => {
            let err_name = name.as_str();
            if err_name == ERROR_IS_LOCKED {
                return Err(LookupError::IsLocked);
            }
            if err_name == ERROR_NO_SUCH_OBJECT || err_name == ERROR_UNKNOWN_OBJECT {
                return Err(LookupError::NoSuchObject);
            }
            Err(LookupError::Other(format!(
                "{err_name}: {}",
                detail.unwrap_or_default()
            )))
        }
        Ok(Err(error)) => Err(LookupError::Other(error.to_string())),
        Err(_) => Err(LookupError::Other("side-channel lookup timed out".into())),
    }
}

async fn check_secret(
    policy: &mut PersistentRpcClient,
    request: SecretRequest,
    ctx: &RequestContext,
) -> bool {
    match policy
        .request(
            RpcRequest::CheckSecret {
                request,
                ctx: ctx.clone(),
            },
            POLICY_TIMEOUT,
        )
        .await
    {
        Ok(RpcReply::SecretCheck(reply)) => reply.ok && reply.verdict.allowed,
        Ok(other) => {
            warn!(reply = %other, "policyd returned unexpected reply for CheckSecret");
            false
        }
        Err(error) => {
            warn!(%error, "CheckSecret RPC failed; denying secret operation");
            false
        }
    }
}

fn lookup_error_action(error: LookupError, path: &str, operation: &str) -> ClientAction {
    match error {
        LookupError::IsLocked => ClientAction::ReplyError {
            name: ERROR_IS_LOCKED,
            detail: "secret item is locked".into(),
        },
        LookupError::NoSuchObject => ClientAction::ReplyError {
            name: ERROR_NO_SUCH_OBJECT,
            detail: format!("secret object `{path}` does not exist"),
        },
        LookupError::Other(detail) => {
            debug!(%path, %detail, %operation, "side-channel secret lookup failed");
            access_denied(format!("unable to inspect secret object for {operation}"))
        }
    }
}

fn has_reserved_attribute(attributes: &HashMap<String, String>) -> bool {
    attributes
        .keys()
        .any(|key| key.starts_with(RESERVED_SECRET_ATTRIBUTE_PREFIX))
}

fn normalize_attributes(attributes: &HashMap<String, String>) -> BTreeMap<String, String> {
    attributes
        .iter()
        .filter(|(key, _)| {
            !key.starts_with(RESERVED_SECRET_ATTRIBUTE_PREFIX)
                && !DAEMON_SYNTHESIZED_ATTRIBUTES.contains(&key.as_str())
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn classify_ownership(
    attributes: &HashMap<String, String>,
    caller_package: Option<&str>,
) -> ItemOwnership {
    match attributes.get(OWNERSHIP_ATTRIBUTE) {
        None => {
            // Also guard against any unexpected reserved attribute key.
            if has_reserved_attribute(attributes) {
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

fn parse_item_collection(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/org/freedesktop/secrets/collection/")?;
    let mut segments = rest.split('/');
    let collection = segments.next()?;
    let item = segments.next()?;
    if !collection.is_empty() && !item.is_empty() && segments.next().is_none() {
        Some(collection)
    } else {
        None
    }
}

fn is_item_path(path: &str) -> bool {
    parse_item_collection(path).is_some()
}

fn parse_collection_or_alias(path: &str) -> Option<CollectionTarget<'_>> {
    if let Some(rest) = path.strip_prefix("/org/freedesktop/secrets/collection/")
        && !rest.is_empty()
        && !rest.contains('/')
    {
        return Some(CollectionTarget::Concrete(rest));
    }
    if let Some(rest) = path.strip_prefix("/org/freedesktop/secrets/aliases/")
        && !rest.is_empty()
        && !rest.contains('/')
    {
        return Some(CollectionTarget::Alias(rest));
    }
    None
}

fn is_collection_or_alias_path(path: &str) -> bool {
    parse_collection_or_alias(path).is_some()
}

fn access_denied(detail: impl Into<String>) -> ClientAction {
    ClientAction::ReplyError {
        name: ERROR_ACCESS_DENIED,
        detail: detail.into(),
    }
}

fn rebuild_method_call<B: Serialize + ZType>(
    original: &Message,
    serial: NonZeroU32,
    destination: &str,
    body: &B,
) -> Result<Message, RelayError> {
    let header = original.header();
    let builder = MessageBuilder::from(header)
        .serial(serial)
        .destination(destination)?
        .endian(original.body().data().context().endian());

    Ok(builder.build(body)?)
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
    use std::collections::{BTreeMap, HashMap};

    use zbus::{
        message::Message,
        zvariant::{OwnedObjectPath, OwnedValue, Value},
    };

    use super::{
        CollectionTarget, CreateItemArgs, CreateItemReply, GetSecretsArgs, ItemOwnership,
        RawSecret, ServiceSearchItemsReply, SetSecretArgs, UnlockReply, classify_ownership,
        has_reserved_attribute, is_collection_or_alias_path, is_item_path, normalize_attributes,
        parse_collection_or_alias, parse_item_collection,
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

        assert_eq!(
            classify_ownership(&host, Some("codex")),
            ItemOwnership::Host
        );
        assert_eq!(classify_ownership(&host, None), ItemOwnership::Host);
        assert_eq!(
            classify_ownership(&codex, Some("codex")),
            ItemOwnership::OwnPackage
        );
        assert_eq!(
            classify_ownership(&omp, Some("codex")),
            ItemOwnership::OtherPackage
        );
        assert_eq!(
            classify_ownership(&codex, None),
            ItemOwnership::OtherPackage
        );
    }

    #[test]
    fn normalize_attributes_strips_reserved_and_daemon_synthesized_keys() {
        let raw = HashMap::from([
            ("service".to_owned(), "gh:github.com".to_owned()),
            ("username".to_owned(), "octocat".to_owned()),
            ("agent-sandbox:package".to_owned(), "codex".to_owned()),
            ("agent-sandbox:extra".to_owned(), "reserved".to_owned()),
            (
                "Uuid".to_owned(),
                "550e8400-e29b-41d4-a716-446655440000".to_owned(),
            ),
            ("Path".to_owned(), "/Group/Entry".to_owned()),
            ("Totp".to_owned(), "otpauth://totp/example".to_owned()),
            ("xdg:content-type".to_owned(), "text/plain".to_owned()),
        ]);

        assert!(has_reserved_attribute(&raw));
        assert_eq!(
            normalize_attributes(&raw),
            BTreeMap::from([
                ("service".to_owned(), "gh:github.com".to_owned()),
                ("username".to_owned(), "octocat".to_owned()),
            ])
        );
        assert!(!has_reserved_attribute(&HashMap::from([(
            "service".to_owned(),
            "gh".to_owned()
        )])));
    }

    #[test]
    fn item_and_collection_path_classifiers_match_spec_segments() {
        assert!(is_item_path(
            "/org/freedesktop/secrets/collection/kdewallet/9"
        ));
        assert_eq!(
            parse_item_collection("/org/freedesktop/secrets/collection/kdewallet/9"),
            Some("kdewallet")
        );
        assert!(!is_item_path(
            "/org/freedesktop/secrets/collection/kdewallet"
        ));
        assert!(!is_item_path(
            "/org/freedesktop/secrets/collection/kdewallet/9/extra"
        ));
        assert!(!is_item_path("/org/freedesktop/secrets/aliases/default"));

        assert_eq!(
            parse_collection_or_alias("/org/freedesktop/secrets/collection/kdewallet"),
            Some(CollectionTarget::Concrete("kdewallet"))
        );
        assert_eq!(
            parse_collection_or_alias("/org/freedesktop/secrets/aliases/default"),
            Some(CollectionTarget::Alias("default"))
        );
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
        let session = OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s1")
            .expect("valid session path");
        let prompt = OwnedObjectPath::try_from("/org/freedesktop/secrets/prompt/p1")
            .expect("valid prompt path");

        let search_msg = Message::method_call("/org/freedesktop/secrets", "Dummy")
            .expect("builder")
            .build(&ServiceSearchItemsReply {
                unlocked: vec![path.clone()],
                locked: Vec::new(),
            })
            .expect("build ServiceSearchItemsReply");
        assert_eq!(
            search_msg.header().signature().to_string_no_parens(),
            "aoao"
        );

        let unlock_msg = Message::method_call("/org/freedesktop/secrets", "Dummy")
            .expect("builder")
            .build(&UnlockReply {
                unlocked: vec![path.clone()],
                prompt: prompt.clone(),
            })
            .expect("build UnlockReply");
        assert_eq!(unlock_msg.header().signature().to_string_no_parens(), "aoo");

        let create_msg =
            Message::method_call("/org/freedesktop/secrets/collection/c", "CreateItem")
                .expect("builder")
                .build(&CreateItemArgs {
                    properties: HashMap::from([(
                        "org.freedesktop.Secret.Item.Label".to_owned(),
                        OwnedValue::try_from(Value::from("Token")).expect("label"),
                    )]),
                    secret: RawSecret {
                        session: session.clone(),
                        parameters: vec![1, 2, 3],
                        value: vec![0xDE, 0xAD, 0xBE, 0xEF],
                        content_type: "application/octet-stream".to_owned(),
                    },
                    replace: true,
                })
                .expect("build CreateItemArgs");
        assert_eq!(
            create_msg.header().signature().to_string_no_parens(),
            "a{sv}(oayays)b"
        );

        let create_reply = Message::method_call("/org/freedesktop/secrets", "Dummy")
            .expect("builder")
            .build(&CreateItemReply {
                item: path.clone(),
                prompt,
            })
            .expect("build CreateItemReply");
        assert_eq!(
            create_reply.header().signature().to_string_no_parens(),
            "oo"
        );

        let raw_secret = RawSecret {
            session: session.clone(),
            parameters: vec![4, 5],
            value: vec![6, 7],
            content_type: "text/plain".to_owned(),
        };
        let tuple_set_secret =
            Message::method_call("/org/freedesktop/secrets/collection/c/1", "SetSecret")
                .expect("builder")
                .build(&(&raw_secret,))
                .expect("build tuple SetSecret");
        let struct_set_secret =
            Message::method_call("/org/freedesktop/secrets/collection/c/1", "SetSecret")
                .expect("builder")
                .build(&SetSecretArgs {
                    secret: RawSecret {
                        session: session.clone(),
                        parameters: vec![4, 5],
                        value: vec![6, 7],
                        content_type: "text/plain".to_owned(),
                    },
                })
                .expect("build SetSecretArgs");
        assert_eq!(
            tuple_set_secret.header().signature().to_string(),
            "(oayays)",
            "wire signature of real D-Bus SetSecret((oayays))"
        );
        assert_eq!(
            struct_set_secret.header().signature().to_string(),
            "(oayays)",
            "SetSecretArgs must match real D-Bus (oayays) wire signature"
        );
        // Verify SetSecretArgs deserializes a real `(oayays)` message built
        // from a single-struct D-Bus argument, and vice versa!
        let decoded: SetSecretArgs = tuple_set_secret
            .body()
            .deserialize()
            .expect("SetSecretArgs must deserialize real (oayays) message");
        assert_eq!(decoded.secret.value, vec![6, 7]);
        let decoded_raw: RawSecret = struct_set_secret
            .body()
            .deserialize()
            .expect("RawSecret must also deserialize (oayays) message");
        assert_eq!(decoded_raw.value, vec![6, 7]);

        let get_secrets_msg = Message::method_call("/org/freedesktop/secrets", "GetSecrets")
            .expect("builder")
            .build(&GetSecretsArgs {
                items: vec![path],
                session,
            })
            .expect("build GetSecretsArgs");
        assert_eq!(
            get_secrets_msg.header().signature().to_string_no_parens(),
            "aoo"
        );
    }
}

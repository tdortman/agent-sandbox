//! Unix-socket D-Bus relay with policy checks.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::Duration;

use agent_sandbox_core::policy::{DbusBus, DbusFdMetadata, DbusMessageKind, DbusTarget};
use agent_sandbox_core::rpc::{RequestContext, RpcReply, RpcRequest};
use agent_sandbox_core::rpc_client::PersistentRpcClient;
use futures_util::StreamExt;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};
use zbus::connection::Builder;
use zbus::message::{Builder as MessageBuilder, Flags, Message, Type};
use zbus::{Connection, Guid, MessageStream};
use zvariant::Fd;

const DBUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_IFACE: &str = "org.freedesktop.DBus";
const HELLO: &str = "Hello";

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub listen: PathBuf,
    pub upstream_address: String,
    pub policy_socket: PathBuf,
    pub bus: DbusBus,
    pub context: RequestContext,
    pub policy_timeout: Duration,
}

impl RelayConfig {
    #[must_use]
    pub fn new(
        listen: impl Into<PathBuf>,
        upstream_address: impl Into<String>,
        policy_socket: impl Into<PathBuf>,
    ) -> Self {
        Self {
            listen: listen.into(),
            upstream_address: upstream_address.into(),
            policy_socket: policy_socket.into(),
            bus: DbusBus::Session,
            context: RequestContext::default(),
            policy_timeout: Duration::from_secs(305),
        }
    }
}

pub struct SerialMap {
    next: NonZeroU32,
    replies: HashMap<NonZeroU32, NonZeroU32>,
}

impl Default for SerialMap {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialMap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: NonZeroU32::MIN,
            replies: HashMap::new(),
        }
    }

    fn next_serial(&mut self) -> NonZeroU32 {
        let serial = self.next;
        self.next = NonZeroU32::new(serial.get().wrapping_add(1))
            .unwrap_or_else(|| NonZeroU32::new(1).expect("constant is non-zero"));
        serial
    }

    #[must_use]
    pub fn allocate(&mut self, client_serial: NonZeroU32) -> NonZeroU32 {
        let serial = self.next_serial();
        self.replies.insert(serial, client_serial);
        serial
    }

    #[must_use]
    pub fn allocate_untracked(&mut self) -> NonZeroU32 {
        self.next_serial()
    }
    pub fn take(&mut self, upstream_serial: NonZeroU32) -> Option<NonZeroU32> {
        self.replies.remove(&upstream_serial)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.replies.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.replies.is_empty()
    }
}

/// Extract the structured policy target from a message header.
#[must_use]
pub fn target_from_message(message: &Message, bus: DbusBus) -> DbusTarget {
    let header = message.header();
    let kind = match message.message_type() {
        Type::MethodCall => DbusMessageKind::MethodCall,
        Type::MethodReturn => DbusMessageKind::MethodReturn,
        Type::Error => DbusMessageKind::Error,
        Type::Signal => DbusMessageKind::Signal,
    };
    let destination = header
        .destination()
        .map(ToString::to_string)
        .unwrap_or_default();
    let object_path = header.path().map(ToString::to_string).unwrap_or_default();
    let interface = header
        .interface()
        .map(ToString::to_string)
        .unwrap_or_default();
    let member = header.member().map(ToString::to_string).unwrap_or_default();
    let signature = header.signature().to_string();
    let fd_count = header.unix_fds().unwrap_or(0);
    let fd_metadata = (0..fd_count)
        .map(|_| DbusFdMetadata {
            kind: "unknown".to_owned(),
            read_only: false,
        })
        .collect();
    DbusTarget {
        bus,
        destination,
        object_path,
        interface,
        member,
        message_kind: kind,
        signature,
        fd_metadata,
    }
}

/// Start accepting relay clients until the listener fails.
///
/// # Errors
/// Returns an I/O or D-Bus error if the listener cannot be created or a
/// connection cannot be established.
pub async fn run(config: RelayConfig) -> Result<(), RelayError> {
    if config.listen.exists() {
        tokio::fs::remove_file(&config.listen).await?;
    }
    let listener = UnixListener::bind(&config.listen)?;
    info!(path = %config.listen.display(), "D-Bus relay listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let client_config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_client(stream, client_config).await {
                debug!(%error, "D-Bus relay client closed");
            }
        });
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),
    #[error("policy RPC error: {0}")]
    Policy(#[from] agent_sandbox_core::rpc_client::RpcClientError),
    #[error("invalid D-Bus message: {0}")]
    Message(String),
}

struct RelayChannels {
    client_stream: MessageStream,
    upstream_stream: MessageStream,
    client_connection: Connection,
    upstream_connection: Connection,
}

async fn handle_client(client_socket: UnixStream, config: RelayConfig) -> Result<(), RelayError> {
    let client_stream = Builder::unix_stream(client_socket)
        .p2p()
        .server(Guid::generate())?
        .build_message_stream()
        .await?;
    let upstream_stream = Builder::address(config.upstream_address.as_str())?
        .build_message_stream()
        .await?;
    let client_connection = Connection::from(&client_stream);
    let upstream_connection = Connection::from(&upstream_stream);
    let upstream_name = upstream_connection
        .unique_name()
        .map(ToString::to_string)
        .ok_or_else(|| RelayError::Message("upstream has no unique name".into()))?;
    let mut policy = PersistentRpcClient::new(config.policy_socket.clone());
    let mut serials = SerialMap::new();
    relay_loop(
        RelayChannels {
            client_stream,
            upstream_stream,
            client_connection,
            upstream_connection,
        },
        upstream_name,
        &mut policy,
        &config,
        &mut serials,
    )
    .await
}

async fn relay_loop(
    channels: RelayChannels,
    upstream_name: String,
    policy: &mut PersistentRpcClient,
    config: &RelayConfig,
    serials: &mut SerialMap,
) -> Result<(), RelayError> {
    let RelayChannels {
        mut client_stream,
        mut upstream_stream,
        client_connection,
        upstream_connection,
    } = channels;
    loop {
        tokio::select! {
            client_message = client_stream.next() => {
                let Some(client_message) = client_message else { return Ok(()); };
                let client_message = client_message?;
                if is_hello(&client_message) {
                    let reply = Message::method_return(&client_message.header())?
                        .build(&(upstream_name.as_str(),))?;
                    client_connection.send(&reply).await?;
                    continue;
                }
                if matches!(
                    client_message.message_type(),
                    Type::MethodReturn | Type::Error
                ) {
                    continue;
                }
                if is_forbidden_bus_control(&client_message) {
                    send_access_denied(&client_connection, &client_message).await?;
                    continue;
                }
                let target = target_from_message(&client_message, config.bus);
                let allowed = policy_check(policy, target, config.context.clone(), config.policy_timeout).await;
                if !allowed {
                    send_access_denied(&client_connection, &client_message).await?;
                    continue;
                }
                let original_serial = client_message.header().primary().serial_num();
                let expects_reply = !client_message
                    .header()
                    .primary()
                    .flags()
                    .contains(Flags::NoReplyExpected);
                let upstream_serial = if client_message.message_type() == Type::MethodCall
                    && expects_reply
                {
                    serials.allocate(original_serial)
                } else {
                    serials.allocate_untracked()
                };
                let forwarded = rewrite_message(&client_message, upstream_serial, None)?;
                upstream_connection.send(&forwarded).await?;
            }
            upstream_message = upstream_stream.next() => {
                let Some(upstream_message) = upstream_message else { return Ok(()); };
                let upstream_message = upstream_message?;
                let reply_serial = upstream_message.header().reply_serial();
                let mapped_reply = reply_serial.and_then(|serial| serials.take(serial));
                if matches!(
                    upstream_message.message_type(),
                    Type::MethodReturn | Type::Error
                ) {
                    let Some(mapped_reply) = mapped_reply else {
                        continue;
                    };
                    let serial = serials.allocate_untracked();
                    let forwarded =
                        rewrite_message(&upstream_message, serial, Some(mapped_reply))?;
                    client_connection.send(&forwarded).await?;
                    continue;
                }
                if upstream_message.message_type() == Type::MethodCall {
                    continue;
                }
                if !policy_check(
                    policy,
                    target_from_message(&upstream_message, config.bus),
                    config.context.clone(),
                    config.policy_timeout,
                )
                .await
                {
                    continue;
                }
                let serial = serials.allocate_untracked();
                let forwarded = rewrite_message(&upstream_message, serial, None)?;
                client_connection.send(&forwarded).await?;
            }
        }
    }
}

async fn policy_check(
    policy: &mut PersistentRpcClient,
    target: DbusTarget,
    context: RequestContext,
    timeout: Duration,
) -> bool {
    let request = RpcRequest::CheckDbus {
        target,
        ctx: context,
    };
    match policy.request(request, timeout).await {
        Ok(RpcReply::DbusCheck(reply)) => reply.ok && reply.allowed,
        Ok(other) => {
            warn!(reply = %other, "policyd returned an unexpected reply for D-Bus check");
            false
        }
        Err(error) => {
            warn!(%error, "policyd check failed; denying D-Bus message");
            false
        }
    }
}

async fn send_access_denied(connection: &Connection, message: &Message) -> Result<(), zbus::Error> {
    let reply = Message::error(&message.header(), "org.freedesktop.DBus.Error.AccessDenied")?
        .build(&("blocked by agent-sandbox policy",))?;
    connection.send(&reply).await
}

fn is_forbidden_bus_control(message: &Message) -> bool {
    let header = message.header();
    message.message_type() == Type::MethodCall
        && header
            .destination()
            .is_some_and(|destination| destination.as_str() == DBUS_IFACE)
        && header.path().is_some_and(|path| path.as_str() == DBUS_PATH)
        && header
            .interface()
            .is_some_and(|interface| interface.as_str() == DBUS_IFACE)
        && header.member().is_some_and(|member| {
            matches!(
                member.as_str(),
                "RequestName" | "BecomeMonitor" | "AddMatch"
            )
        })
}

fn is_hello(message: &Message) -> bool {
    let header = message.header();
    message.message_type() == Type::MethodCall
        && header
            .destination()
            .is_some_and(|destination| destination.as_str() == DBUS_IFACE)
        && header.path().is_some_and(|path| path.as_str() == DBUS_PATH)
        && header
            .interface()
            .is_some_and(|interface| interface.as_str() == DBUS_IFACE)
        && header
            .member()
            .is_some_and(|member| member.as_str() == HELLO)
}

fn rewrite_message(
    message: &Message,
    serial: NonZeroU32,
    reply_serial: Option<NonZeroU32>,
) -> Result<Message, RelayError> {
    let body = message.body();
    let fds = body
        .data()
        .fds()
        .iter()
        .map(Fd::try_to_owned)
        .map(|fd| fd.map(Into::into))
        .collect::<Result<Vec<zvariant::OwnedFd>, _>>()
        .map_err(|error| RelayError::Message(format!("duplicating D-Bus fd: {error}")))?;

    let builder = MessageBuilder::from(message.header())
        .serial(serial)
        .reply_serial(reply_serial)
        .endian(body.data().context().endian());

    Ok(build_raw_body(
        builder,
        body.data().bytes(),
        body.signature(),
        fds,
    )?)
}

#[allow(unsafe_code)]
fn build_raw_body(
    builder: MessageBuilder<'_>,
    body: &[u8],
    signature: &zvariant::Signature,
    fds: Vec<zvariant::OwnedFd>,
) -> Result<Message, zbus::Error> {
    // The bytes and signature originate from a validated zbus message; cloned
    // FDs preserve the exact indices referenced by the body.
    Ok(unsafe { builder.build_raw_body(body, signature, fds)? })
}

#[cfg(test)]
mod tests {
    use super::{SerialMap, is_forbidden_bus_control, target_from_message};
    use std::num::NonZeroU32;
    use zbus::message::Message;
    use zbus::zvariant::Endian;

    #[test]
    fn serial_map_correlates_and_removes_replies() {
        let mut map = SerialMap::new();
        let client = NonZeroU32::new(41).expect("non-zero");
        let upstream = map.allocate(client);
        assert_eq!(upstream.get(), 1);
        assert_eq!(map.take(upstream), Some(client));
        assert!(map.is_empty());
    }

    #[test]
    fn target_extracts_header_fields_and_signature() {
        let message = Message::method_call("/org/example/Object", "Ping")
            .expect("builder")
            .destination("org.example.Service")
            .expect("destination")
            .interface("org.example.Interface")
            .expect("interface")
            .serial(NonZeroU32::new(7).expect("non-zero"))
            .endian(Endian::Little)
            .build(&("hello",))
            .expect("message");

        let target = target_from_message(&message, agent_sandbox_core::DbusBus::System);
        assert_eq!(target.destination, "org.example.Service");
        assert_eq!(target.object_path, "/org/example/Object");
        assert_eq!(target.interface, "org.example.Interface");
        assert_eq!(target.member, "Ping");
        assert_eq!(target.signature, "s");
        assert_eq!(target.bus, agent_sandbox_core::DbusBus::System);
    }

    #[test]
    fn bus_control_methods_are_denied_before_policy() {
        let message = Message::method_call("/org/freedesktop/DBus", "RequestName")
            .expect("builder")
            .destination("org.freedesktop.DBus")
            .expect("destination")
            .interface("org.freedesktop.DBus")
            .expect("interface")
            .build(&("org.example.Agent", 0_u32))
            .expect("message");

        assert!(is_forbidden_bus_control(&message));
    }
}

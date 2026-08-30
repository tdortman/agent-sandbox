//! Unix-socket D-Bus relay with policy checks.

use std::{num::NonZeroU32, path::PathBuf, time::Duration};

use agent_sandbox_core::{
    policy::{DbusBus, DbusFdMetadata, DbusMessageKind, DbusTarget},
    rpc::{RequestContext, RpcReply, RpcRequest},
    rpc_client::PersistentRpcClient,
};
use futures_util::StreamExt;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};
use zbus::{
    Connection, Guid, MessageStream,
    connection::Builder,
    message::{Builder as MessageBuilder, Message, Type},
};
use zvariant::Fd;

const DBUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_IFACE: &str = "org.freedesktop.DBus";
const HELLO: &str = "Hello";

const POLICY_TIMEOUT: Duration = Duration::from_secs(305);

/// Configuration for the D-Bus relay listener.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Unix socket path the relay listens on.
    pub listen: PathBuf,
    /// Upstream D-Bus address to relay to.
    pub upstream_address: String,
    /// Socket path of the policy daemon RPC endpoint.
    pub policy_socket: PathBuf,
    /// Which bus (session/system) the relay handles.
    pub bus: DbusBus,
    /// Request context attributed to the relay's own policy checks.
    pub context: RequestContext,
}

impl RelayConfig {
    /// Create a `RelayConfig`.
    ///
    /// Uses the session bus and a default [`RequestContext`]; override
    /// `bus` and `context` as needed.
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
        }
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
/// Errors returned by the relay.
pub enum RelayError {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A D-Bus error occurred.
    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),

    /// A D-Bus message was invalid.
    #[error("invalid D-Bus message: {0}")]
    Message(String),
}

struct RelayChannels {
    client_stream: MessageStream,
    upstream_stream: MessageStream,
    client_connection: Connection,
    upstream_connection: Connection,
}

async fn handle_client(
    client_socket: UnixStream,
    mut config: RelayConfig,
) -> Result<(), RelayError> {
    let credentials = getsockopt(&client_socket, PeerCredentials).map_err(|error| {
        RelayError::Message(format!("cannot read D-Bus peer credentials: {error}"))
    })?;

    config.context.pid = u32::try_from(credentials.pid()).ok();
    config.context.uid = Some(credentials.uid());

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

    let mut policy = PersistentRpcClient::new_trusted(config.policy_socket.clone());

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
    )
    .await
}

async fn relay_loop(
    channels: RelayChannels,
    upstream_name: String,
    policy: &mut PersistentRpcClient,
    config: &RelayConfig,
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
                let allowed = policy_check(policy, target, config.context.clone(), POLICY_TIMEOUT).await;
                if !allowed {
                    send_access_denied(&client_connection, &client_message).await?;
                    continue;
                }
                let serial = client_message.header().primary().serial_num();
                let forwarded = rewrite_message(&client_message, serial, None)?;
                upstream_connection.send(&forwarded).await?;
            }
            upstream_message = upstream_stream.next() => {
                let Some(upstream_message) = upstream_message else { return Ok(()); };
                let upstream_message = upstream_message?;
                if matches!(
                    upstream_message.message_type(),
                    Type::MethodReturn | Type::Error
                ) {
                    // Forward verbatim: rebuilding a reply parsed from the
                    // wire corrupted the token in GetSecret replies, and the
                    // client serial kept on the way upstream makes reply
                    // matching work without rewriting.
                    client_connection.send(&upstream_message).await?;
                    continue;
                }
                if upstream_message.message_type() == Type::MethodCall {
                    continue;
                }
                if !policy_check(
                    policy,
                    target_from_message(&upstream_message, config.bus),
                    config.context.clone(),
                    POLICY_TIMEOUT,
                )
                .await
                {
                    continue;
                }
                client_connection.send(&upstream_message).await?;
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
    is_bus_method(message, |member| {
        matches!(member, "RequestName" | "BecomeMonitor" | "AddMatch")
    })
}

fn is_hello(message: &Message) -> bool {
    is_bus_method(message, |member| member == HELLO)
}

fn is_bus_method(message: &Message, member_matches: impl FnOnce(&str) -> bool) -> bool {
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
            .is_some_and(|member| member_matches(member.as_str()))
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

#[allow(unsafe_code, reason = "zbus build_raw_body requires raw message bytes")]
fn build_raw_body(
    builder: MessageBuilder<'_>,
    body: &[u8],
    signature: &zvariant::Signature,
    fds: Vec<zvariant::OwnedFd>,
) -> Result<Message, zbus::Error> {
    // SAFETY: the bytes and signature originate from a validated zbus
    // message, and cloned FDs preserve the indices referenced by the body.
    Ok(unsafe { builder.build_raw_body(body, signature, fds)? })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use zbus::{
        message::Message,
        zvariant::{Endian, ObjectPath},
    };

    use super::{DbusBus, is_forbidden_bus_control, rewrite_message, target_from_message};

    #[test]
    fn rewrite_preserves_get_secret_reply_body() {
        let session: ObjectPath = "/org/freedesktop/secrets/session/1"
            .try_into()
            .expect("session path");

        let call = Message::method_call(
            "/org/freedesktop/secrets/collection/kdewallet/9",
            "GetSecret",
        )
        .expect("builder")
        .destination("org.freedesktop.secrets")
        .expect("destination")
        .interface("org.freedesktop.Secret.Item")
        .expect("interface")
        .serial(NonZeroU32::new(7).expect("non-zero"))
        .endian(Endian::Little)
        .build(&(session.clone(),))
        .expect("message");

        let token: Vec<u8> = b"gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_vec();
        assert_eq!(token.len(), 40);

        let reply = Message::method_return(&call.header())
            .expect("builder")
            .build(&(
                session.clone(),
                Vec::<u8>::new(),
                token.clone(),
                "text/plain; charset=utf8".to_string(),
            ))
            .expect("reply");

        let rewritten = rewrite_message(
            &reply,
            NonZeroU32::new(99).expect("non-zero"),
            Some(NonZeroU32::new(7).expect("non-zero")),
        )
        .expect("rewrite");

        let body = rewritten.body();
        let (r_session, _parameters, r_value, r_content_type): (
            ObjectPath,
            Vec<u8>,
            Vec<u8>,
            String,
        ) = body.deserialize().expect("deserialize reply body");

        assert_eq!(r_session, session);
        assert_eq!(r_value, token);
        assert_eq!(r_content_type, "text/plain; charset=utf8");
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

        let target = target_from_message(&message, DbusBus::System);
        assert_eq!(target.destination, "org.example.Service");
        assert_eq!(target.object_path, "/org/example/Object");
        assert_eq!(target.interface, "org.example.Interface");
        assert_eq!(target.member, "Ping");
        assert_eq!(target.signature, "s");
        assert_eq!(target.bus, DbusBus::System);
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

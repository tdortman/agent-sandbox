//! Unix-socket D-Bus relay with policy checks.

mod secrets;
#[cfg(test)]
mod secrets_tests;

use std::{
    collections::HashMap,
    ffi::OsStr,
    fs, io,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};

use agent_sandbox_core::{
    peer_cred_unix,
    policy::{DbusBus, DbusFdMetadata, DbusMessageKind, DbusTarget},
    rpc::{RequestContext, RpcReply, RpcRequest},
    rpc_client::PersistentRpcClient,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};
use url::{Host, Url};
use zbus::{
    Connection, Guid, MatchRule, MessageStream,
    connection::Builder,
    message::{Builder as MessageBuilder, Message, Type},
    zvariant::{Fd, OwnedValue},
};

const DBUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_IFACE: &str = "org.freedesktop.DBus";
const HELLO: &str = "Hello";
pub(crate) const POLICY_TIMEOUT: Duration = Duration::from_secs(305);
const BRIDGE_TIMEOUT: Duration = Duration::from_secs(5);
const PORTAL_DESTINATION: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const OPEN_URI_IFACE: &str = "org.freedesktop.portal.OpenURI";
const OPEN_URI: &str = "OpenURI";

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

    let destination = header.destination().map_or_default(ToString::to_string);

    let object_path = header.path().map_or_default(ToString::to_string);

    let interface = header.interface().map_or_default(ToString::to_string);

    let member = header.member().map_or_default(ToString::to_string);
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
        any_fd_metadata: false,
    }
}

/// Start accepting relay clients until the listener fails.
///
/// # Errors
/// Returns an I/O or D-Bus error if the listener cannot be created or a
/// connection cannot be established.
pub async fn run(config: RelayConfig) -> Result<(), RelayError> {
    run_inner(config, true).await
}

#[cfg(test)]
pub(crate) async fn run_for_test(config: RelayConfig) -> Result<(), RelayError> {
    run_inner(config, false).await
}

async fn run_inner(
    config: RelayConfig,
    require_trusted_policy_peer: bool,
) -> Result<(), RelayError> {
    if config.listen.exists() {
        tokio::fs::remove_file(&config.listen).await?;
    }

    let listener = UnixListener::bind(&config.listen)?;
    info!(path = %config.listen.display(), "D-Bus relay listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let client_config = config.clone();

        tokio::spawn(async move {
            if let Err(error) =
                handle_client(stream, client_config, require_trusted_policy_peer).await
            {
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

struct AcceptedClient {
    socket: UnixStream,
    config: RelayConfig,
}

struct AuthenticatedClient {
    client_stream: zbus::MessageStream,
    config: RelayConfig,
}

struct ReadyRelay {
    channels: RelayChannels,
    upstream_name: String,
    config: RelayConfig,
}

impl AcceptedClient {
    async fn authenticate(mut self) -> Result<AuthenticatedClient, RelayError> {
        let credentials = peer_cred_unix(&self.socket)
            .ok_or_else(|| RelayError::Message("cannot read D-Bus peer credentials".to_owned()))?;
        // A terminal opener runs outside the sandbox. Its own working directory
        // is not the project whose policy should govern the request.
        let pid = if self.config.context.uid == Some(credentials.uid)
            && std::env::current_exe().is_ok_and(|exe| is_relay_process(credentials.pid, &exe))
        {
            std::process::id()
        } else {
            credentials.pid
        };
        self.config.context.pid = Some(pid);
        self.config.context.uid = Some(credentials.uid);

        let client_stream = Builder::unix_stream(self.socket)
            .p2p()
            .server(Guid::generate())?
            .build_message_stream()
            .await?;

        Ok(AuthenticatedClient {
            client_stream,
            config: self.config,
        })
    }
}

impl AuthenticatedClient {
    async fn connect_upstream(self) -> Result<ReadyRelay, RelayError> {
        let upstream_stream = Builder::address(self.config.upstream_address.as_str())?
            .build_message_stream()
            .await?;

        let client_connection = Connection::from(&self.client_stream);
        let upstream_connection = Connection::from(&upstream_stream);

        let upstream_name = upstream_connection
            .unique_name()
            .map(ToString::to_string)
            .ok_or_else(|| RelayError::Message("upstream has no unique name".into()))?;

        Ok(ReadyRelay {
            channels: RelayChannels {
                client_stream: self.client_stream,
                upstream_stream,
                client_connection,
                upstream_connection,
            },
            upstream_name,
            config: self.config,
        })
    }
}

impl ReadyRelay {
    async fn run(self, require_trusted_policy_peer: bool) -> Result<(), RelayError> {
        let mut policy = if require_trusted_policy_peer {
            PersistentRpcClient::new_trusted(self.config.policy_socket.clone())
        } else {
            PersistentRpcClient::new(self.config.policy_socket.clone())
        };
        relay_loop(self.channels, self.upstream_name, &mut policy, &self.config).await
    }
}

async fn handle_client(
    client_socket: UnixStream,
    config: RelayConfig,
    require_trusted_policy_peer: bool,
) -> Result<(), RelayError> {
    AcceptedClient {
        socket: client_socket,
        config,
    }
    .authenticate()
    .await?
    .connect_upstream()
    .await?
    .run(require_trusted_policy_peer)
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

    let mut secrets =
        secrets::SecretsMediator::new(config.upstream_address.clone(), config.bus).await?;
    let mut hello_complete = false;

    loop {
        tokio::select! {
            client_message = client_stream.next() => {
                let Some(client_message) = client_message else { return Ok(()); };
                let client_message = client_message?;
                if is_hello(&client_message) {
                    let reply = Message::method_return(&client_message.header())?
                        .build(&(upstream_name.as_str(),))?;
                    client_connection.send(&reply).await?;
                    hello_complete = true;
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
                match secrets
                    .handle_client_message(&client_message, policy, &config.context)
                    .await?
                {
                    secrets::ClientAction::Forward(forwarded) => {
                        upstream_connection.send(&forwarded).await?;
                        continue;
                    }
                    secrets::ClientAction::ReplyError { name, detail } => {
                        send_dbus_error(&client_connection, &client_message, name, &detail).await?;
                        continue;
                    }
                    secrets::ClientAction::NotSecrets => {}
                }
                // Match rules only subscribe this relay's upstream connection;
                // every delivered signal still passes `policy_check` on the
                // upstream branch.
                let allowed = is_match_rule_control(&client_message)
                    || policy_check(
                        policy,
                        target_from_message(&client_message, config.bus),
                        config.context.clone(),
                        POLICY_TIMEOUT,
                    )
                    .await;
                if !allowed {
                    send_access_denied(&client_connection, &client_message).await?;
                    continue;
                }
                // Bridge before the browser opens: a signed-in user can be
                // redirected back immediately.
                if let Some(port) = oauth_redirect_port(&client_message) {
                    bridge_loopback(policy, port).await;
                }
                let serial = client_message.header().primary().serial_num();
                let forwarded = rewrite_message(&client_message, serial, None)?;
                upstream_connection.send(&forwarded).await?;
            }
            // Do not forward upstream messages (including the bus's initial
            // NameAcquired signal) until the client's Hello call has received
            // its MethodReturn.
            upstream_message = upstream_stream.next(), if hello_complete => {
                let Some(upstream_message) = upstream_message else { return Ok(()); };
                let upstream_message = upstream_message?;
                match secrets.handle_upstream_message(&upstream_message).await? {
                    secrets::UpstreamAction::Forward(forwarded) => {
                        client_connection.send(&forwarded).await?;
                        continue;
                    }
                    secrets::UpstreamAction::Drop => {
                        continue;
                    }
                    secrets::UpstreamAction::NotSecrets => {}
                }
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
        Ok(RpcReply::DbusCheck(reply)) => reply.ok && reply.verdict.allowed,

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

/// Body of `org.freedesktop.portal.OpenURI.OpenURI`.
#[derive(Debug, Serialize, Deserialize, zbus::zvariant::Type)]
struct OpenUriCall {
    parent_window: String,
    uri: String,
    options: HashMap<String, OwnedValue>,
}

/// Open a clicked OAuth link through the foreground sandbox launcher's session
/// relay.
///
/// Returns `false` for other links or when the launcher has no matching relay.
///
/// # Errors
///
/// Returns an error if the relay cannot forward the request or policy denies
/// it.
pub async fn open_terminal_oauth(launcher: u32, uri: String) -> Result<bool, RelayError> {
    if oauth_url_port(&uri).is_none_or(|port| port < 1024) {
        return Ok(false);
    }
    let Some(stream) = terminal_relay(launcher).await? else {
        return Ok(false);
    };
    let connection = Builder::unix_stream(stream).build().await?;
    connection
        .call_method(
            Some(PORTAL_DESTINATION),
            PORTAL_PATH,
            Some(OPEN_URI_IFACE),
            OPEN_URI,
            &OpenUriCall {
                parent_window: String::new(),
                uri,
                options: HashMap::new(),
            },
        )
        .await?;
    Ok(true)
}

async fn terminal_relay(launcher: u32) -> io::Result<Option<UnixStream>> {
    let uid = fs::metadata("/proc/self")?.uid();
    let parent = PathBuf::from(format!("/proc/{launcher}"));
    if !parent.metadata().is_ok_and(|meta| meta.uid() == uid) {
        return Ok(None);
    }
    let exe = std::env::current_exe()?;
    let children = match fs::read_to_string(parent.join(format!("task/{launcher}/children"))) {
        Ok(children) => children,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut relay = None;
    // The launcher starts its own session and system relays as direct children.
    for pid in children
        .split_whitespace()
        .filter_map(|pid| pid.parse::<u32>().ok())
    {
        if !is_relay_process(pid, &exe) {
            continue;
        }
        let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let Some(path) = session_relay_path(&cmdline) else {
            continue;
        };
        let stream = UnixStream::connect(path).await?;
        if !peer_cred_unix(&stream).is_some_and(|peer| peer.pid == pid && peer.uid == uid) {
            return Err(io::Error::other("session relay peer changed"));
        }
        if relay.replace(stream).is_some() {
            return Err(io::Error::other(
                "multiple session relays for the terminal job",
            ));
        }
    }
    Ok(relay)
}

fn is_relay_process(pid: u32, exe: &Path) -> bool {
    fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|path| path == exe)
}

fn session_relay_path(cmdline: &[u8]) -> Option<&Path> {
    let mut args = cmdline.strip_suffix(&[0])?.split(|byte| *byte == 0).skip(1);
    let mut listen = None;
    let mut session = false;
    while let Some(arg) = args.next() {
        let value = args.next()?;
        match arg {
            b"--listen" => listen = Some(Path::new(OsStr::from_bytes(value))),
            b"--bus" => session = value == b"session",
            _ => {}
        }
    }
    listen.filter(|path| session && path.is_absolute())
}

/// Loopback port of the OAuth `redirect_uri` in a URL sent to the portal's
/// `OpenURI`. The host browser delivers the authorization code to that port,
/// while the client listens on the sandbox's own loopback.
fn oauth_redirect_port(message: &Message) -> Option<u16> {
    let header = message.header();
    if header.interface()?.as_str() != OPEN_URI_IFACE || header.member()?.as_str() != OPEN_URI {
        return None;
    }

    let call: OpenUriCall = message.body().deserialize().ok()?;
    oauth_url_port(&call.uri)
}

fn oauth_url_port(uri: &str) -> Option<u16> {
    let url = Url::parse(uri).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let (_, redirect) = url.query_pairs().find(|(key, _)| key == "redirect_uri")?;
    let redirect = Url::parse(&redirect).ok()?;

    let loopback = match redirect.host()? {
        Host::Domain(domain) => domain == "localhost",
        Host::Ipv4(ip) => ip == Ipv4Addr::LOCALHOST,
        Host::Ipv6(ip) => ip == Ipv6Addr::LOCALHOST,
    };
    if redirect.scheme() != "http" || !loopback {
        return None;
    }

    redirect.port()
}

async fn bridge_loopback(policy: &mut PersistentRpcClient, port: u16) {
    match policy
        .request(RpcRequest::BridgeLoopback { port }, BRIDGE_TIMEOUT)
        .await
    {
        Ok(RpcReply::Simple(reply)) if reply.ok => {
            info!(port, "bridged OAuth redirect port from host loopback");
        }
        Ok(other) => warn!(port, reply = %other, "policyd refused OAuth redirect bridge"),
        Err(error) => warn!(port, %error, "OAuth redirect bridge request failed"),
    }
}

async fn send_access_denied(connection: &Connection, message: &Message) -> Result<(), zbus::Error> {
    send_dbus_error(
        connection,
        message,
        "org.freedesktop.DBus.Error.AccessDenied",
        "blocked by agent-sandbox policy",
    )
    .await
}

async fn send_dbus_error(
    connection: &Connection,
    message: &Message,
    error_name: &str,
    detail: &str,
) -> Result<(), zbus::Error> {
    let reply = Message::error(&message.header(), error_name)?.build(&(detail,))?;

    connection.send(&reply).await
}

fn is_forbidden_bus_control(message: &Message) -> bool {
    is_bus_method(message, |member| {
        matches!(member, "RequestName" | "BecomeMonitor")
    }) || (is_bus_method(message, |member| member == "AddMatch")
        && !is_scoped_signal_match(message))
}

fn is_match_rule_control(message: &Message) -> bool {
    is_bus_method(message, |member| {
        matches!(member, "AddMatch" | "RemoveMatch")
    })
}

/// Accept signal subscriptions narrowed to a sender or interface.
///
/// zbus's parser rejects keys it does not know, including `eavesdrop`, so an
/// accepted rule cannot observe messages addressed to other connections.
fn is_scoped_signal_match(message: &Message) -> bool {
    let body = message.body();
    let Ok(rule) = body.deserialize::<&str>() else {
        return false;
    };

    MatchRule::try_from(rule).is_ok_and(|rule| {
        rule.msg_type() == Some(Type::Signal)
            && (rule.sender().is_some() || rule.interface().is_some())
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
    rewrite_message_inner(message, serial, reply_serial, None)
}

pub(crate) fn rewrite_message_with_destination(
    message: &Message,
    serial: NonZeroU32,
    reply_serial: Option<NonZeroU32>,
    destination: &str,
) -> Result<Message, RelayError> {
    rewrite_message_inner(message, serial, reply_serial, Some(destination))
}

fn rewrite_message_inner(
    message: &Message,
    serial: NonZeroU32,
    reply_serial: Option<NonZeroU32>,
    destination: Option<&str>,
) -> Result<Message, RelayError> {
    let body = message.body();

    let fds = body
        .data()
        .fds()
        .iter()
        .map(Fd::try_to_owned)
        .map(|fd| fd.map(Into::into))
        .collect::<Result<Vec<zbus::zvariant::OwnedFd>, _>>()
        .map_err(|error| RelayError::Message(format!("duplicating D-Bus fd: {error}")))?;

    let mut builder = MessageBuilder::from(message.header())
        .serial(serial)
        .reply_serial(reply_serial)
        .endian(body.data().context().endian());

    if let Some(destination) = destination {
        builder = builder.destination(destination)?;
    }

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
    signature: &zbus::zvariant::Signature,
    fds: Vec<zbus::zvariant::OwnedFd>,
) -> Result<Message, zbus::Error> {
    // SAFETY: the bytes and signature originate from a validated zbus
    // message, and cloned FDs preserve the indices referenced by the body.
    Ok(unsafe { builder.build_raw_body(body, signature, fds)? })
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, num::NonZeroU32};

    use serde::{Deserialize, Serialize};
    use zbus::{
        message::Message,
        zvariant::{Endian, ObjectPath, Type},
    };

    use super::{
        DbusBus, OpenUriCall, is_forbidden_bus_control, oauth_redirect_port, rewrite_message,
        target_from_message,
    };

    fn open_uri(uri: &str) -> Message {
        Message::method_call("/org/freedesktop/portal/desktop", "OpenURI")
            .expect("builder")
            .destination("org.freedesktop.portal.Desktop")
            .expect("destination")
            .interface("org.freedesktop.portal.OpenURI")
            .expect("interface")
            .build(&OpenUriCall {
                parent_window: String::new(),
                uri: uri.to_owned(),
                options: HashMap::new(),
            })
            .expect("message")
    }

    struct RedirectCase {
        redirect: &'static str,
        port: Option<u16>,
    }

    #[test]
    fn open_uri_yields_loopback_oauth_redirect_port() {
        let authorize = |redirect: &str| {
            format!(
                "https://auth.example.com/authorize?client_id=abc&redirect_uri={}&state=s",
                url::form_urlencoded::byte_serialize(redirect.as_bytes()).collect::<String>()
            )
        };

        for case in [
            RedirectCase {
                redirect: "http://127.0.0.1:3000/callback",
                port: Some(3000),
            },
            RedirectCase {
                redirect: "http://localhost:54545/callback",
                port: Some(54545),
            },
            RedirectCase {
                redirect: "http://[::1]:8085/",
                port: Some(8085),
            },
            RedirectCase {
                redirect: "http://127.0.0.1/callback",
                port: None,
            },
            RedirectCase {
                redirect: "https://127.0.0.1:3000/callback",
                port: None,
            },
            RedirectCase {
                redirect: "http://evil.example.com:3000/callback",
                port: None,
            },
            RedirectCase {
                redirect: "http://127.0.0.2:3000/callback",
                port: None,
            },
        ] {
            assert_eq!(
                oauth_redirect_port(&open_uri(&authorize(case.redirect))),
                case.port,
                "{}",
                case.redirect
            );
        }
        assert_eq!(
            oauth_redirect_port(&open_uri("https://example.com/?next=http://127.0.0.1:3000")),
            None
        );
    }

    /// `org.freedesktop.Secret.Item.GetSecret` reply: session, parameters,
    /// value, and content type. The derived D-Bus struct signature matches
    /// the wire layout exactly.
    #[derive(Debug, Serialize, Deserialize, Type)]
    struct GetSecretReply<'a> {
        #[serde(borrow)]
        session: ObjectPath<'a>,
        parameters: Vec<u8>,
        value: Vec<u8>,
        content_type: String,
    }

    #[test]
    fn rewrite_preserves_get_secret_reply_body() {
        let session =
            ObjectPath::try_from("/org/freedesktop/secrets/session/1").expect("session path");

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
            .build(&GetSecretReply {
                session: session.clone(),
                parameters: Vec::new(),
                value: token.clone(),
                content_type: "text/plain; charset=utf8".to_string(),
            })
            .expect("reply");

        let rewritten = rewrite_message(
            &reply,
            NonZeroU32::new(99).expect("non-zero"),
            Some(NonZeroU32::new(7).expect("non-zero")),
        )
        .expect("rewrite");

        let body = rewritten.body();

        let decoded: GetSecretReply<'_> = body.deserialize().expect("deserialize reply body");

        assert_eq!(decoded.session, session);
        assert_eq!(decoded.value, token);
        assert_eq!(decoded.content_type, "text/plain; charset=utf8");
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

    #[test]
    fn add_match_requires_scoped_signal_rule_without_eavesdrop() {
        let add_match = |rule: &str| {
            Message::method_call("/org/freedesktop/DBus", "AddMatch")
                .expect("builder")
                .destination("org.freedesktop.DBus")
                .expect("destination")
                .interface("org.freedesktop.DBus")
                .expect("interface")
                .build(&(rule,))
                .expect("message")
        };

        let portal_response = "type='signal',sender='org.freedesktop.portal.Desktop',interface='\
                               org.freedesktop.portal.Request',member='Response',path='/org/\
                               freedesktop/portal/desktop/request/1_2/t'";
        assert!(!is_forbidden_bus_control(&add_match(portal_response)));
        assert!(!is_forbidden_bus_control(&add_match(
            "type='signal',interface='org.freedesktop.DBus.Properties'"
        )));

        for rule in [
            "type='signal'",
            "sender='org.freedesktop.portal.Desktop'",
            "type='method_call',interface='org.example.Interface'",
            "type='signal',sender='org.freedesktop.portal.Desktop',eavesdrop='true'",
            "eavesdrop='true',type='signal',interface='org.example.Interface'",
            "not a match rule",
        ] {
            assert!(is_forbidden_bus_control(&add_match(rule)), "{rule}");
        }
    }
}

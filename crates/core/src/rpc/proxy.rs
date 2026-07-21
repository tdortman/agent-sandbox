//! Typed capabilities and flow-registration wire values for the proxy socket.

use std::{
    fmt,
    net::IpAddr,
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    path::PathBuf,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use uuid::Uuid;

use super::request::RequestContext;
use crate::{
    HttpRequest, HttpRuleTarget, SandboxPaths,
    hosts::{normalize_dns_name, normalize_host},
};

/// A non-zero inode number identifying a local socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SocketInode(NonZeroU64);

impl SocketInode {
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is zero.
    pub fn new(value: u64) -> Result<Self, String> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| "socket inode must be non-zero".to_owned())
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for SocketInode {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A non-zero `/proc` process start-time tick count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProcessStartTimeTicks(NonZeroU64);

impl ProcessStartTimeTicks {
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is zero.
    pub fn new(value: u64) -> Result<Self, String> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| "process start time ticks must be non-zero".to_owned())
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for ProcessStartTimeTicks {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Process identity captured while resolving a socket owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pid: NonZeroU32,
    uid: u32,
    #[serde(rename = "process_start_time_ticks")]
    start_time: ProcessStartTimeTicks,
}

impl ProcessIdentity {
    ///
    /// # Errors
    ///
    /// Returns an error when `pid` or `start_time` is zero.
    pub fn new(pid: u32, uid: u32, start_time: u64) -> Result<Self, String> {
        let pid = NonZeroU32::new(pid).ok_or_else(|| "process pid must be non-zero".to_owned())?;
        let start_time = ProcessStartTimeTicks::new(start_time)?;
        Ok(Self {
            pid,
            uid,
            start_time,
        })
    }

    #[must_use]
    pub const fn from_parts(pid: NonZeroU32, uid: u32, start_time: ProcessStartTimeTicks) -> Self {
        Self {
            pid,
            uid,
            start_time,
        }
    }

    #[must_use]
    pub const fn pid(self) -> NonZeroU32 {
        self.pid
    }

    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    #[must_use]
    pub const fn process_start_time_ticks(self) -> ProcessStartTimeTicks {
        self.start_time
    }

    #[must_use]
    pub const fn pid_value(self) -> u32 {
        self.pid.get()
    }
}

/// Process and socket identity captured before a flow is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketIdentity {
    process: ProcessIdentity,
    inode: SocketInode,
}

impl SocketIdentity {
    #[must_use]
    pub const fn new(process: ProcessIdentity, inode: SocketInode) -> Self {
        Self { process, inode }
    }

    #[must_use]
    pub const fn pid(self) -> NonZeroU32 {
        self.process.pid()
    }

    #[must_use]
    pub const fn uid(self) -> u32 {
        self.process.uid()
    }

    #[must_use]
    pub const fn process_start_time_ticks(self) -> ProcessStartTimeTicks {
        self.process.process_start_time_ticks()
    }

    #[must_use]
    pub const fn socket_inode(self) -> SocketInode {
        self.inode
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireSocketIdentity {
    pid: NonZeroU32,
    uid: u32,
    #[serde(rename = "process_start_time_ticks")]
    start_time: ProcessStartTimeTicks,
    socket_inode: SocketInode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedWireSocketIdentity {
    pid: NonZeroU32,
    uid: u32,
    #[serde(rename = "process_start_time_ticks")]
    start_time: ProcessStartTimeTicks,
    socket_inode: SocketInode,
}

impl Serialize for SocketIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WireSocketIdentity {
            pid: self.process.pid,
            uid: self.process.uid,
            start_time: self.process.start_time,
            socket_inode: self.inode,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SocketIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = OwnedWireSocketIdentity::deserialize(deserializer)?;
        Ok(Self {
            process: ProcessIdentity::from_parts(wire.pid, wire.uid, wire.start_time),
            inode: wire.socket_inode,
        })
    }
}

/// `UUIDv4` identifying a proxy-side connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProxyConnectionId(Uuid);

impl ProxyConnectionId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when `value` is not the canonical lowercase hyphenated
    /// `UUIDv4` representation.
    pub fn parse(value: &str) -> Result<Self, String> {
        let uuid =
            Uuid::parse_str(value).map_err(|_| "invalid proxy connection UUID".to_owned())?;
        if value != uuid.hyphenated().to_string() {
            return Err(
                "proxy connection id must be canonical lowercase hyphenated `UUIDv4`".to_owned(),
            );
        }
        if uuid.get_version() != Some(uuid::Version::Random) {
            return Err("proxy connection id must be `UUIDv4`".to_owned());
        }
        Ok(Self(uuid))
    }

    #[must_use]
    pub const fn uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ProxyConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProxyConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(f)
    }
}

impl Serialize for ProxyConnectionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ProxyConnectionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

/// Canonical lowercase hyphenated `UUIDv7` request identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProxyRequestId(Uuid);

impl ProxyRequestId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when `value` is not the canonical lowercase hyphenated
    /// `UUIDv7` representation.
    pub fn parse(value: &str) -> Result<Self, String> {
        let uuid = Uuid::parse_str(value).map_err(|_| "invalid proxy request UUID".to_owned())?;
        if value != uuid.hyphenated().to_string() {
            return Err(
                "proxy request id must be canonical lowercase hyphenated `UUIDv7`".to_owned(),
            );
        }
        if uuid.get_version() != Some(uuid::Version::SortRand) {
            return Err("proxy request id must be `UUIDv7`".to_owned());
        }
        Ok(Self(uuid))
    }

    #[must_use]
    pub const fn uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ProxyRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProxyRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(f)
    }
}

impl Serialize for ProxyRequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ProxyRequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

fn encode_token(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0F) as usize] as char);
    }
    encoded
}

fn decode_token(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("capability token must be 64 lowercase hex characters".to_owned());
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(pair[0]);
        let low = hex_value(pair[1]);
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

const fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

macro_rules! capability_token {
    ($name:ident) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            ///
            /// # Errors
            ///
            /// Returns an error when operating-system randomness is unavailable.
            pub fn try_new() -> Result<Self, String> {
                let mut bytes = [0_u8; 32];
                getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
                Ok(Self(bytes))
            }

            ///
            /// # Panics
            ///
            /// Panics if operating-system randomness is unavailable.
            #[must_use]
            pub fn new() -> Self {
                Self::try_new().expect(
                    "operating system randomness must be available for proxy capability tokens",
                )
            }

            ///
            /// # Errors
            ///
            /// Returns an error when `value` is not a 64-character lowercase
            /// hexadecimal capability token.
            pub fn parse(value: &str) -> Result<Self, String> {
                decode_token(value).map(Self)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"<redacted>")
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&encode_token(&self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(&value).map_err(D::Error::custom)
            }
        }
    };
}

capability_token!(ProxySessionToken);
capability_token!(AttributionToken);

/// Transport protocol attached to a registered flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

/// Complete local/remote tuple used for owner revalidation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFlowKey {
    pub protocol: FlowProtocol,
    pub source_ip: IpAddr,
    pub source_port: NonZeroU16,
    pub destination_ip: IpAddr,
    pub destination_port: NonZeroU16,
}

impl NetworkFlowKey {
    #[must_use]
    pub const fn new(
        protocol: FlowProtocol,
        source_ip: IpAddr,
        source_port: NonZeroU16,
        destination_ip: IpAddr,
        destination_port: NonZeroU16,
    ) -> Self {
        Self {
            protocol,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an error when either endpoint port is zero.
    pub fn try_new(
        protocol: FlowProtocol,
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
    ) -> Result<Self, String> {
        let source_port = NonZeroU16::new(source_port)
            .ok_or_else(|| "source port must be non-zero".to_owned())?;
        let destination_port = NonZeroU16::new(destination_port)
            .ok_or_else(|| "destination port must be non-zero".to_owned())?;
        Ok(Self::new(
            protocol,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
        ))
    }

    #[must_use]
    pub const fn protocol(&self) -> FlowProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn source_ip(&self) -> IpAddr {
        self.source_ip
    }

    #[must_use]
    pub const fn source_port(&self) -> NonZeroU16 {
        self.source_port
    }

    #[must_use]
    pub const fn destination_ip(&self) -> IpAddr {
        self.destination_ip
    }

    #[must_use]
    pub const fn destination_port(&self) -> NonZeroU16 {
        self.destination_port
    }
}

/// Normalized policy host (DNS name or canonical IP literal).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalizedPolicyHost(NormalizedPolicyHostValue);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum NormalizedPolicyHostValue {
    Ip(IpAddr),
    Dns(Box<str>),
}

impl NormalizedPolicyHost {
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is not a valid normalized DNS name or IP
    /// literal.
    pub fn parse(value: &str) -> Result<Self, String> {
        let trimmed = value.trim();
        let bracketed = trimmed.starts_with('[') || trimmed.ends_with(']');
        if bracketed && trimmed.len() < 2 {
            return Err("policy host has malformed brackets".to_owned());
        }
        if bracketed
            && (!trimmed.starts_with('[')
                || !trimmed.ends_with(']')
                || trimmed[1..trimmed.len() - 1].contains(['[', ']']))
        {
            return Err("policy host has malformed brackets".to_owned());
        }
        let normalized = normalize_host(trimmed);
        if normalized.is_empty()
            || normalized.contains(['/', '?', '#', '@'])
            || normalized.starts_with('*')
        {
            return Err("policy host must be a hostname or IP literal".to_owned());
        }
        if let Ok(ip) = normalized.parse::<IpAddr>() {
            return Ok(Self(NormalizedPolicyHostValue::Ip(ip)));
        }
        if bracketed {
            return Err("brackets are only valid around an IP literal".to_owned());
        }
        let dns = normalize_dns_name(&normalized)
            .map_err(|error| format!("invalid policy host: {error}"))?;
        if dns.len() > 253 {
            return Err("policy host exceeds 253 bytes".to_owned());
        }
        for label in dns.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err("policy host contains an invalid DNS label".to_owned());
            }
        }
        Ok(Self(NormalizedPolicyHostValue::Dns(dns.into_boxed_str())))
    }

    #[must_use]
    pub fn dns_name(&self) -> Option<&str> {
        match &self.0 {
            NormalizedPolicyHostValue::Dns(name) => Some(name),
            NormalizedPolicyHostValue::Ip(_) => None,
        }
    }

    #[must_use]
    pub const fn ip(&self) -> Option<IpAddr> {
        match &self.0 {
            NormalizedPolicyHostValue::Ip(ip) => Some(*ip),
            NormalizedPolicyHostValue::Dns(_) => None,
        }
    }

    #[must_use]
    pub const fn is_ip(&self) -> bool {
        self.ip().is_some()
    }
}

impl fmt::Display for NormalizedPolicyHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            NormalizedPolicyHostValue::Ip(ip) => ip.fmt(formatter),
            NormalizedPolicyHostValue::Dns(name) => formatter.write_str(name),
        }
    }
}

impl Serialize for NormalizedPolicyHost {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NormalizedPolicyHost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

impl TryFrom<&str> for NormalizedPolicyHost {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFlowContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cwd: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    home: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sandbox_session_id: Option<String>,
}

/// Sandbox paths and session identity associated with a registered flow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowContext {
    paths: SandboxPaths,
    sandbox_session_id: Option<String>,
}

impl FlowContext {
    #[must_use]
    pub const fn new(paths: SandboxPaths, sandbox_session_id: Option<String>) -> Self {
        Self {
            paths,
            sandbox_session_id,
        }
    }

    #[must_use]
    pub const fn paths(&self) -> &SandboxPaths {
        &self.paths
    }

    #[must_use]
    pub fn sandbox_session_id(&self) -> Option<&str> {
        self.sandbox_session_id.as_deref()
    }

    #[must_use]
    pub fn sandbox_session_id_owned(&self) -> Option<String> {
        self.sandbox_session_id.clone()
    }

    #[must_use]
    pub fn into_parts(self) -> (SandboxPaths, Option<String>) {
        (self.paths, self.sandbox_session_id)
    }
}

impl Serialize for FlowContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WireFlowContext {
            cwd: self.paths.cwd_path(),
            home: self.paths.home_path(),
            project_root: self.paths.project_root_path(),
            sandbox_session_id: self.sandbox_session_id.clone(),
        }
        .serialize(serializer)
    }
}

impl From<RequestContext> for FlowContext {
    fn from(context: RequestContext) -> Self {
        Self::new(context.sandbox_paths(), context.sandbox_session_id)
    }
}

impl From<&RequestContext> for FlowContext {
    fn from(context: &RequestContext) -> Self {
        Self::new(context.sandbox_paths(), context.sandbox_session_id.clone())
    }
}

impl<'de> Deserialize<'de> for FlowContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireFlowContext::deserialize(deserializer)?;
        Ok(Self {
            paths: SandboxPaths::from_wire(wire.cwd, wire.home, wire.project_root),
            sandbox_session_id: wire.sandbox_session_id,
        })
    }
}

/// Trusted proxy registration payload. The server revalidates every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowRegistration {
    pub flow: NetworkFlowKey,
    pub owner: SocketIdentity,
    pub policy_host: NormalizedPolicyHost,
    pub ctx: FlowContext,
}

impl FlowRegistration {
    #[must_use]
    pub const fn new(
        flow: NetworkFlowKey,
        owner: SocketIdentity,
        policy_host: NormalizedPolicyHost,
        ctx: FlowContext,
    ) -> Self {
        Self {
            flow,
            owner,
            policy_host,
            ctx,
        }
    }

    #[must_use]
    pub const fn flow(&self) -> &NetworkFlowKey {
        &self.flow
    }

    #[must_use]
    pub const fn owner(&self) -> SocketIdentity {
        self.owner
    }

    #[must_use]
    pub const fn policy_host(&self) -> &NormalizedPolicyHost {
        &self.policy_host
    }

    #[must_use]
    pub const fn context(&self) -> &FlowContext {
        &self.ctx
    }
}

/// Proxy check operation payloads share one typed HTTP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCheckRequest {
    pub request: HttpRequest,
    pub attribution_token: AttributionToken,
}

/// Target used by host-side HTTP approval requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpApprovalRequest {
    pub target: HttpRuleTarget,
    pub scope: crate::ApprovalScope,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub ctx: RequestContext,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use serde_json::json;

    use super::*;

    #[test]
    fn proxy_ids_require_canonical_uuid_versions() {
        let connection = ProxyConnectionId::new();
        let connection_text = connection.to_string();
        assert_eq!(
            ProxyConnectionId::parse(&connection_text).expect("generated `UUIDv4` parses"),
            connection
        );
        assert!(
            ProxyConnectionId::parse(&connection_text.to_ascii_uppercase()).is_err(),
            "uppercase UUIDs are not canonical"
        );
        assert!(
            ProxyConnectionId::parse(&connection.uuid().as_simple().to_string()).is_err(),
            "simple UUIDs are not canonical"
        );

        let request = ProxyRequestId::new();
        let request_text = request.to_string();
        assert_eq!(
            ProxyRequestId::parse(&request_text).expect("generated `UUIDv7` parses"),
            request
        );
        assert!(
            ProxyRequestId::parse(&connection_text).is_err(),
            "`UUIDv4` is not a valid proxy request ID"
        );
    }

    #[test]
    fn capability_tokens_are_random_wire_hex_but_redacted_in_debug() {
        let token = ProxySessionToken::new();
        let wire = serde_json::to_value(&token).expect("token serializes");
        let wire_text = wire
            .as_str()
            .expect("token wire value is a string")
            .to_owned();
        assert_eq!(wire_text.len(), 64);
        assert!(wire_text.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            serde_json::from_value::<ProxySessionToken>(wire).expect("token deserializes"),
            token
        );
        let debug = format!("{token:?}");
        assert!(!debug.contains(&wire_text));
        assert!(debug.contains("redacted"));
        assert!(ProxySessionToken::parse(&wire_text.to_ascii_uppercase()).is_err());
    }

    #[test]
    fn registration_wire_is_flat_and_rejects_zero_or_unknown_values() {
        let flow = NetworkFlowKey::try_new(
            FlowProtocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            42,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
        )
        .expect("non-zero flow ports");
        let process = ProcessIdentity::new(123, 0, 456).expect("non-zero process identity");
        let registration = FlowRegistration::new(
            flow,
            SocketIdentity::new(process, SocketInode::new(789).expect("non-zero inode")),
            NormalizedPolicyHost::parse("EXAMPLE.COM.").expect("valid DNS host"),
            FlowContext::new(
                SandboxPaths::new("/tmp", "/home/user", "/tmp/project"),
                Some("sandbox".to_owned()),
            ),
        );
        let wire = serde_json::to_value(&registration).expect("registration serializes");
        assert_eq!(
            wire,
            json!({
                "flow": {
                    "protocol": "tcp",
                    "source_ip": "127.0.0.1",
                    "source_port": 42,
                    "destination_ip": "93.184.216.34",
                    "destination_port": 443
                },
                "owner": {
                    "pid": 123,
                    "uid": 0,
                    "process_start_time_ticks": 456,
                    "socket_inode": 789
                },
                "policy_host": "example.com",
                "ctx": {
                    "cwd": "/tmp",
                    "home": "/home/user",
                    "project_root": "/tmp/project",
                    "sandbox_session_id": "sandbox"
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<FlowRegistration>(wire).expect("registration deserializes"),
            registration
        );

        let unknown = json!({
            "flow": {
                "protocol": "tcp",
                "source_ip": "127.0.0.1",
                "source_port": 42,
                "destination_ip": "93.184.216.34",
                "destination_port": 443,
                "extra": true
            },
            "owner": {
                "pid": 123,
                "uid": 0,
                "process_start_time_ticks": 456,
                "socket_inode": 789
            },
            "policy_host": "example.com",
            "ctx": {}
        });
        assert!(serde_json::from_value::<FlowRegistration>(unknown).is_err());

        let zero_port = json!({
            "flow": {
                "protocol": "tcp",
                "source_ip": "127.0.0.1",
                "source_port": 0,
                "destination_ip": "93.184.216.34",
                "destination_port": 443
            },
            "owner": {
                "pid": 123,
                "uid": 0,
                "process_start_time_ticks": 456,
                "socket_inode": 789
            },
            "policy_host": "example.com",
            "ctx": {}
        });
        assert!(serde_json::from_value::<FlowRegistration>(zero_port).is_err());
    }

    #[test]
    fn policy_host_normalizes_dns_and_ip_literals_without_wildcards() {
        assert_eq!(
            NormalizedPolicyHost::parse("EXAMPLE.COM.")
                .expect("DNS host parses")
                .to_string(),
            "example.com"
        );
        assert_eq!(
            NormalizedPolicyHost::parse("[2001:0db8::1]")
                .expect("IPv6 host parses")
                .to_string(),
            "2001:db8::1"
        );
        for invalid in [
            "",
            "*.example.com",
            "example.com:443",
            "https://example.com",
            "[",
            "example.com]",
            "[example.com]",
        ] {
            assert!(
                NormalizedPolicyHost::parse(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }
}

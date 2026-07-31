//! Protocol-independent HTTP values shared by proxy backends.
//!
//! This module deliberately does not depend on Rama, quinn, or socket types.

use agent_sandbox_core::{
    HttpAuthority, HttpMethod, HttpParseError, HttpRequest as CoreHttpRequest, HttpScheme,
    HttpSessionMetadata as CoreHttpSessionMetadata,
};
use serde::{Deserialize, Serialize, Serializer};
use std::{collections::VecDeque, fmt};

/// Whether a header must not be forwarded end to end.
///
/// The header is either a hop-by-hop field or a field named by the
/// connection header tokens of the message.
#[must_use]
pub fn is_hop_by_hop_header(name: &str, connection_tokens: &[String]) -> bool {
    let name = name.to_ascii_lowercase();

    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || connection_tokens.iter().any(|token| token == &name)
}

/// HTTP versions supported by the semantic proxy contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HttpVersion {
    #[serde(rename = "HTTP/1.0")]
    Http10,

    #[serde(rename = "HTTP/1.1")]
    Http11,

    #[serde(rename = "HTTP/2")]
    Http2,

    #[serde(rename = "HTTP/3")]
    Http3,
}

impl HttpVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An end-to-end HTTP header with a validated name and value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SemanticHeaderWire")]
pub struct SemanticHeader {
    name: Box<str>,
    value: Box<[u8]>,
}

impl SemanticHeader {
    /// Construct a header without removing hop-by-hop fields.
    /// # Errors
    /// Returns [`HeaderError`] for an invalid field name or value.
    pub fn new<V>(name: &str, value: V) -> Result<Self, HeaderError>
    where
        V: AsRef<[u8]>,
    {
        let value = value.as_ref();

        if name.is_empty() || !name.bytes().all(is_header_name_byte) {
            return Err(HeaderError::InvalidName);
        }

        if value.iter().copied().any(is_invalid_header_value_byte) {
            return Err(HeaderError::InvalidValue);
        }

        Ok(Self {
            name: name.to_ascii_lowercase().into_boxed_str(),
            value: value.into(),
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Deserialize)]
struct SemanticHeaderWire {
    name: String,
    value: SemanticHeaderValue,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SemanticHeaderValue {
    Text(String),
    Bytes(Vec<u8>),
}

impl TryFrom<SemanticHeaderWire> for SemanticHeader {
    type Error = HeaderError;

    fn try_from(wire: SemanticHeaderWire) -> Result<Self, Self::Error> {
        match wire.value {
            SemanticHeaderValue::Text(value) => Self::new(&wire.name, value),
            SemanticHeaderValue::Bytes(value) => Self::new(&wire.name, value),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticHeaders(Vec<SemanticHeader>);

impl SemanticHeaders {
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, header: SemanticHeader) {
        self.0.push(header);
    }

    /// # Errors
    /// Returns [`HeaderError`] for an invalid field name or value.
    pub fn try_push<V>(&mut self, name: &str, value: V) -> Result<(), HeaderError>
    where
        V: AsRef<[u8]>,
    {
        self.push(SemanticHeader::new(name, value)?);
        Ok(())
    }

    #[must_use]
    pub fn as_slice(&self) -> &[SemanticHeader] {
        &self.0
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[SemanticHeader]> for SemanticHeaders {
    fn as_ref(&self) -> &[SemanticHeader] {
        self.as_slice()
    }
}

impl IntoIterator for SemanticHeaders {
    type IntoIter = std::vec::IntoIter<SemanticHeader>;
    type Item = SemanticHeader;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// A raw query without its leading `?`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RawQuery(Box<str>);

impl RawQuery {
    /// # Errors
    /// Returns [`ValueError::InvalidQuery`] for a fragment or control byte.
    pub fn parse(value: &str) -> Result<Self, ValueError> {
        if value
            .bytes()
            .any(|byte| byte == b'#' || byte < 0x20 || byte == 0x7F)
        {
            return Err(ValueError::InvalidQuery);
        }

        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RawQuery {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl TryFrom<&str> for RawQuery {
    type Error = ValueError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl std::str::FromStr for RawQuery {
    type Err = ValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Optional session attribution for extended HTTP sessions.
///
/// The core type owns the wire shape and validation; the semantic request
/// carries it unchanged into policy requests.
pub type SessionMetadata = CoreHttpSessionMetadata;

/// Terminal state for a streamed request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestTerminal {
    Complete,
    Cancellation,
    Reset(u64),
    Error(TerminalError),
}

/// A bounded queue of request body chunks.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BoundedRequestBodyWire")]
pub struct BoundedRequestBody {
    chunks: VecDeque<Vec<u8>>,
    buffered_bytes: usize,
    max_chunk_bytes: usize,
    max_buffered_bytes: usize,
    trailers: Option<SemanticHeaders>,
    terminal: Option<RequestTerminal>,
}

impl BoundedRequestBody {
    /// # Errors
    /// Returns [`BodyError::InvalidLimit`] when either limit is zero or
    /// inconsistent.
    pub const fn new(max_chunk_bytes: usize, max_buffered_bytes: usize) -> Result<Self, BodyError> {
        if max_chunk_bytes == 0 || max_buffered_bytes < max_chunk_bytes {
            return Err(BodyError::InvalidLimit);
        }

        Ok(Self {
            chunks: VecDeque::new(),
            buffered_bytes: 0,
            max_chunk_bytes,
            max_buffered_bytes,
            trailers: None,
            terminal: None,
        })
    }

    #[must_use]
    /// # Panics
    /// This function uses fixed nonzero limits.
    pub fn empty() -> Self {
        Self::new(16 * 1024, 1024 * 1024).expect("constant body limits are valid")
    }

    /// # Errors
    /// Returns [`BodyError`] when the body is terminal or exceeds a configured
    /// limit.
    pub fn push_chunk(&mut self, chunk: Vec<u8>) -> Result<(), BodyError> {
        if self.terminal.is_some() || self.trailers.is_some() {
            return Err(BodyError::AfterTerminal);
        }

        if chunk.len() > self.max_chunk_bytes {
            return Err(BodyError::ChunkTooLarge);
        }

        if chunk.len() > self.max_buffered_bytes.saturating_sub(self.buffered_bytes) {
            return Err(BodyError::BufferFull);
        }

        self.buffered_bytes += chunk.len();
        self.chunks.push_back(chunk);
        Ok(())
    }

    pub fn pop_chunk(&mut self) -> Option<Vec<u8>> {
        let chunk = self.chunks.pop_front()?;
        self.buffered_bytes -= chunk.len();
        Some(chunk)
    }

    /// # Errors
    /// Returns [`BodyError`] when the body is terminal or already has trailers.
    pub fn set_trailers(&mut self, trailers: SemanticHeaders) -> Result<(), BodyError> {
        if self.terminal.is_some() {
            return Err(BodyError::AfterTerminal);
        }

        if self.trailers.is_some() {
            return Err(BodyError::TrailersAlreadySet);
        }

        self.trailers = Some(trailers);
        Ok(())
    }

    /// # Errors
    /// Returns [`BodyError::AfterTerminal`] when the body is already terminal.
    pub fn finish(&mut self) -> Result<(), BodyError> {
        self.terminate(RequestTerminal::Complete)
    }

    /// # Errors
    /// Returns [`BodyError::AfterTerminal`] when the body is already terminal.
    pub fn terminate(&mut self, terminal: RequestTerminal) -> Result<(), BodyError> {
        if self.terminal.is_some() {
            return Err(BodyError::AfterTerminal);
        }

        self.terminal = Some(terminal);
        Ok(())
    }

    #[must_use]
    pub const fn terminal(&self) -> Option<&RequestTerminal> {
        self.terminal.as_ref()
    }

    #[must_use]
    pub const fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    #[must_use]
    pub const fn trailers(&self) -> Option<&SemanticHeaders> {
        self.trailers.as_ref()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

#[derive(Deserialize)]
struct BoundedRequestBodyWire {
    chunks: VecDeque<Vec<u8>>,
    buffered_bytes: usize,
    max_chunk_bytes: usize,
    max_buffered_bytes: usize,
    trailers: Option<SemanticHeaders>,
    terminal: Option<RequestTerminal>,
}

impl TryFrom<BoundedRequestBodyWire> for BoundedRequestBody {
    type Error = BodyError;

    fn try_from(wire: BoundedRequestBodyWire) -> Result<Self, Self::Error> {
        let mut body = Self::new(wire.max_chunk_bytes, wire.max_buffered_bytes)?;

        for chunk in wire.chunks {
            body.push_chunk(chunk)?;
        }

        if body.buffered_bytes != wire.buffered_bytes {
            return Err(BodyError::InvalidBufferedBytes);
        }

        if let Some(trailers) = wire.trailers {
            body.set_trailers(trailers)?;
        }

        if let Some(terminal) = wire.terminal {
            body.terminate(terminal)?;
        }

        Ok(body)
    }
}

/// A validated semantic HTTP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SemanticRequestWire")]
pub struct SemanticRequest {
    method: HttpMethod,
    scheme: HttpScheme,
    authority: Box<str>,
    path: SemanticPath,
    raw_path: Box<str>,
    raw_query: Option<RawQuery>,
    headers: SemanticHeaders,
    source_version: HttpVersion,
    target_version: HttpVersion,
    session: Option<SessionMetadata>,
    body: BoundedRequestBody,
}

impl SemanticRequest {
    /// # Errors
    /// Returns [`SemanticRequestError`] when any request value is invalid.
    #[expect(
        clippy::too_many_arguments,
        reason = "semantic request fields map directly to the wire contract"
    )]
    pub fn from_parts(
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        raw_query: Option<&str>,
        headers: SemanticHeaders,
        source_version: HttpVersion,
        target_version: HttpVersion,
        session: Option<SessionMetadata>,
        body: BoundedRequestBody,
    ) -> Result<Self, SemanticRequestError> {
        let method = HttpMethod::parse(method)?;
        let scheme = HttpScheme::parse(scheme)?;
        let authority_value = HttpAuthority::parse(scheme, authority)?;
        let authority = canonical_authority(scheme, &authority_value).into_boxed_str();
        let semantic_path = SemanticPath::parse(path, method.as_str())?;
        let raw_query = raw_query.map(RawQuery::parse).transpose()?;

        Ok(Self {
            method,
            scheme,
            authority,
            path: semantic_path,
            raw_path: path.into(),
            raw_query,
            headers,
            source_version,
            target_version,
            session,
            body,
        })
    }

    /// Build the query-insensitive policy value used by the existing policy
    /// RPC.
    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError`] when the normalized policy target is invalid.
    pub fn policy_request(&self) -> Result<CoreHttpRequest, HttpParseError> {
        let request = CoreHttpRequest::from_parts(
            self.method.as_str(),
            self.scheme.as_str(),
            &self.authority,
            self.path.as_str(),
        )?;

        if let Some(session) = &self.session {
            return Ok(request.with_session(Some(session.clone())));
        }

        Ok(request)
    }

    #[must_use]
    pub fn forwarding_target(&self) -> String {
        self.raw_query.as_ref().map_or_else(
            || self.raw_path.to_string(),
            |query| format!("{}?{}", self.raw_path, query.as_str()),
        )
    }

    #[must_use]
    pub const fn method(&self) -> &HttpMethod {
        &self.method
    }

    #[must_use]
    pub const fn scheme(&self) -> HttpScheme {
        self.scheme
    }

    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    #[must_use]
    pub const fn path(&self) -> &SemanticPath {
        &self.path
    }

    #[must_use]
    pub fn raw_path(&self) -> &str {
        &self.raw_path
    }

    #[must_use]
    pub const fn raw_query(&self) -> Option<&RawQuery> {
        self.raw_query.as_ref()
    }

    #[must_use]
    pub const fn headers(&self) -> &SemanticHeaders {
        &self.headers
    }

    #[must_use]
    pub const fn source_version(&self) -> HttpVersion {
        self.source_version
    }

    #[must_use]
    pub const fn target_version(&self) -> HttpVersion {
        self.target_version
    }

    #[must_use]
    pub const fn session(&self) -> Option<&SessionMetadata> {
        self.session.as_ref()
    }

    #[must_use]
    pub const fn body(&self) -> &BoundedRequestBody {
        &self.body
    }

    pub const fn body_mut(&mut self) -> &mut BoundedRequestBody {
        &mut self.body
    }

    #[must_use]
    pub fn into_body(self) -> BoundedRequestBody {
        self.body
    }
}

#[derive(Deserialize)]
struct SemanticRequestWire {
    method: HttpMethod,
    scheme: HttpScheme,
    authority: String,
    path: SemanticPath,
    raw_path: Option<String>,
    raw_query: Option<RawQuery>,
    headers: SemanticHeaders,
    source_version: HttpVersion,
    target_version: HttpVersion,
    session: Option<SessionMetadata>,
    body: BoundedRequestBody,
}

impl TryFrom<SemanticRequestWire> for SemanticRequest {
    type Error = SemanticRequestError;

    fn try_from(wire: SemanticRequestWire) -> Result<Self, Self::Error> {
        let expected_path = wire.path;

        let request = Self::from_parts(
            wire.method.as_str(),
            wire.scheme.as_str(),
            &wire.authority,
            wire.raw_path
                .as_deref()
                .unwrap_or_else(|| expected_path.as_str()),
            wire.raw_query.as_ref().map(RawQuery::as_str),
            wire.headers,
            wire.source_version,
            wire.target_version,
            wire.session,
            wire.body,
        )?;

        if request.path != expected_path {
            return Err(SemanticRequestError::PathMismatch);
        }

        Ok(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "SemanticPathWire")]
pub struct SemanticPath(SemanticPathValue);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SemanticPathValue {
    Path(Box<str>),
    Asterisk,
}

impl SemanticPath {
    fn parse(value: &str, method: &str) -> Result<Self, SemanticRequestError> {
        if value == "*" {
            if method != "OPTIONS" {
                return Err(SemanticRequestError::AsteriskRequiresOptions);
            }

            return Ok(Self(SemanticPathValue::Asterisk));
        }

        let normalized = agent_sandbox_core::NormalizedHttpPath::parse(value)?;
        Ok(Self(SemanticPathValue::Path(normalized.as_str().into())))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            SemanticPathValue::Path(value) => value,
            SemanticPathValue::Asterisk => "*",
        }
    }
}

impl Serialize for SemanticPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.0 {
            SemanticPathValue::Path(value) => {
                serializer.serialize_newtype_variant("SemanticPath", 0, "Path", value)
            }

            SemanticPathValue::Asterisk => {
                serializer.serialize_unit_variant("SemanticPath", 1, "Asterisk")
            }
        }
    }
}

#[derive(Deserialize)]
enum SemanticPathWire {
    Path(String),
    Asterisk,
}

impl TryFrom<SemanticPathWire> for SemanticPath {
    type Error = SemanticRequestError;

    fn try_from(wire: SemanticPathWire) -> Result<Self, Self::Error> {
        match wire {
            SemanticPathWire::Path(path) => Self::parse(&path, "GET"),
            SemanticPathWire::Asterisk => Ok(Self(SemanticPathValue::Asterisk)),
        }
    }
}

/// Ordered response events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseEvent {
    Informational(ResponseHead),
    Final(ResponseHead),
    BodyChunk(Vec<u8>),
    Trailers(SemanticHeaders),
    Complete,
    Cancelled,
    Reset(u64),
    Error(TerminalError),
}

/// A response status and its headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ResponseHeadWire")]
pub struct ResponseHead {
    status: u16,
    headers: SemanticHeaders,
}

impl ResponseHead {
    /// # Errors
    /// Returns [`EventError`] when the status is outside the informational
    /// range.
    pub fn informational(status: u16, headers: SemanticHeaders) -> Result<Self, EventError> {
        if !(100..200).contains(&status) {
            return Err(EventError::InvalidInformationalStatus);
        }

        Ok(Self { status, headers })
    }

    /// # Errors
    /// Returns [`EventError`] when the status is not a valid final status.
    pub fn final_head(status: u16, headers: SemanticHeaders) -> Result<Self, EventError> {
        if !(200..1000).contains(&status) {
            return Err(EventError::InvalidFinalStatus);
        }

        Ok(Self { status, headers })
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub const fn headers(&self) -> &SemanticHeaders {
        &self.headers
    }
}

#[derive(Deserialize)]
struct ResponseHeadWire {
    status: u16,
    headers: SemanticHeaders,
}

impl TryFrom<ResponseHeadWire> for ResponseHead {
    type Error = EventError;

    fn try_from(wire: ResponseHeadWire) -> Result<Self, Self::Error> {
        if (100..200).contains(&wire.status) {
            Self::informational(wire.status, wire.headers)
        } else {
            Self::final_head(wire.status, wire.headers)
        }
    }
}

/// Typed terminal failures shared by all protocol backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum TerminalError {
    #[error("policy denied request: {0}")]
    PolicyDenied(Box<str>),

    #[error("request cancelled")]
    Cancellation,

    #[error("stream reset with code {0}")]
    StreamReset(u64),

    #[error("transport failure: {0}")]
    Transport(Box<str>),

    #[error("protocol violation: {0}")]
    ProtocolViolation(Box<str>),

    #[error("upstream refused request: {0}")]
    UpstreamRefused(Box<str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ResponsePhase {
    Initial,
    Final,
    Trailers,
    TerminalBeforeFinal,
    TerminalAfterFinal,
    TerminalAfterTrailers,
}

/// Response event sequence validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ResponseSequenceWire")]
pub struct ResponseSequence {
    events: VecDeque<ResponseEvent>,
    final_seen: bool,
    trailers_seen: bool,
    terminal_seen: bool,
    body_bytes: usize,
    consumed_phase: ResponsePhase,
    max_events: usize,
    max_body_bytes: usize,
}

impl ResponseSequence {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: VecDeque::new(),
            final_seen: false,
            trailers_seen: false,
            terminal_seen: false,
            consumed_phase: ResponsePhase::Initial,
            body_bytes: 0,
            max_events: 1024,
            max_body_bytes: 1024 * 1024,
        }
    }

    /// # Errors
    /// Returns [`EventError::InvalidLimit`] when `max_events` is zero.
    pub const fn with_limits(max_events: usize, max_body_bytes: usize) -> Result<Self, EventError> {
        if max_events == 0 {
            return Err(EventError::InvalidLimit);
        }

        let mut sequence = Self::new();
        sequence.max_events = max_events;
        sequence.max_body_bytes = max_body_bytes;
        Ok(sequence)
    }

    /// # Errors
    /// Returns [`EventError`] when the event is out of order or exceeds a
    /// limit.
    pub fn push(&mut self, event: ResponseEvent) -> Result<(), EventError> {
        if self.terminal_seen {
            return Err(EventError::AfterTerminal);
        }

        if self.events.len() >= self.max_events {
            return Err(EventError::BufferFull);
        }

        match &event {
            ResponseEvent::Informational(head) => {
                if self.final_seen || !(100..200).contains(&head.status()) {
                    return Err(EventError::InvalidOrdering);
                }
            }

            ResponseEvent::Final(head) => {
                if self.final_seen || !(200..1000).contains(&head.status()) {
                    return Err(EventError::InvalidOrdering);
                }
                self.final_seen = true;
            }

            ResponseEvent::BodyChunk(chunk) => {
                if !self.final_seen || self.trailers_seen {
                    return Err(EventError::InvalidOrdering);
                }
                if chunk.len() > self.max_body_bytes.saturating_sub(self.body_bytes) {
                    return Err(EventError::BufferFull);
                }
                self.body_bytes += chunk.len();
            }

            ResponseEvent::Trailers(_) => {
                if !self.final_seen || self.trailers_seen {
                    return Err(EventError::InvalidOrdering);
                }
                self.trailers_seen = true;
            }

            ResponseEvent::Complete => {
                if !self.final_seen {
                    return Err(EventError::InvalidOrdering);
                }
                self.terminal_seen = true;
            }

            ResponseEvent::Cancelled | ResponseEvent::Reset(_) | ResponseEvent::Error(_) => {
                self.terminal_seen = true;
            }
        }

        self.events.push_back(event);
        Ok(())
    }

    pub fn pop_event(&mut self) -> Option<ResponseEvent> {
        let event = self.events.pop_front()?;

        match &event {
            ResponseEvent::Final(_) => self.consumed_phase = ResponsePhase::Final,
            ResponseEvent::Trailers(_) => self.consumed_phase = ResponsePhase::Trailers,

            ResponseEvent::Complete
            | ResponseEvent::Cancelled
            | ResponseEvent::Reset(_)
            | ResponseEvent::Error(_) => {
                self.consumed_phase = match self.consumed_phase {
                    ResponsePhase::Initial => ResponsePhase::TerminalBeforeFinal,
                    ResponsePhase::Final => ResponsePhase::TerminalAfterFinal,
                    ResponsePhase::Trailers => ResponsePhase::TerminalAfterTrailers,
                    phase => phase,
                };
            }

            ResponseEvent::Informational(_) | ResponseEvent::BodyChunk(_) => {}
        }

        if let ResponseEvent::BodyChunk(chunk) = &event {
            self.body_bytes -= chunk.len();
        }

        Some(event)
    }

    #[must_use]
    pub const fn events(&self) -> &VecDeque<ResponseEvent> {
        &self.events
    }
}

impl Default for ResponseSequence {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
struct ResponseSequenceWire {
    events: VecDeque<ResponseEvent>,
    final_seen: Option<bool>,
    trailers_seen: Option<bool>,
    terminal_seen: Option<bool>,
    consumed_phase: Option<ResponsePhase>,
    body_bytes: Option<usize>,
    max_events: Option<usize>,
    max_body_bytes: Option<usize>,
}

impl TryFrom<ResponseSequenceWire> for ResponseSequence {
    type Error = EventError;

    fn try_from(wire: ResponseSequenceWire) -> Result<Self, Self::Error> {
        let mut sequence = Self::with_limits(
            wire.max_events.unwrap_or(1024),
            wire.max_body_bytes.unwrap_or(1024 * 1024),
        )?;

        let consumed_phase = wire.consumed_phase.unwrap_or(ResponsePhase::Initial);
        sequence.consumed_phase = consumed_phase;

        sequence.final_seen = matches!(
            consumed_phase,
            ResponsePhase::Final
                | ResponsePhase::Trailers
                | ResponsePhase::TerminalAfterFinal
                | ResponsePhase::TerminalAfterTrailers
        );

        sequence.trailers_seen = matches!(
            consumed_phase,
            ResponsePhase::Trailers | ResponsePhase::TerminalAfterTrailers
        );

        sequence.terminal_seen = matches!(
            consumed_phase,
            ResponsePhase::TerminalBeforeFinal
                | ResponsePhase::TerminalAfterFinal
                | ResponsePhase::TerminalAfterTrailers
        );

        for event in wire.events {
            sequence.push(event)?;
        }

        if wire
            .final_seen
            .is_some_and(|value| value != sequence.final_seen)
            || wire
                .trailers_seen
                .is_some_and(|value| value != sequence.trailers_seen)
            || wire
                .terminal_seen
                .is_some_and(|value| value != sequence.terminal_seen)
            || wire
                .body_bytes
                .is_some_and(|bytes| bytes != sequence.body_bytes)
        {
            return Err(EventError::InvalidState);
        }

        Ok(sequence)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("invalid header name")]
    InvalidName,

    #[error("invalid header value")]
    InvalidValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValueError {
    #[error("invalid raw query")]
    InvalidQuery,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BodyError {
    #[error("body limit is invalid")]
    InvalidLimit,

    #[error("body chunk exceeds the configured limit")]
    ChunkTooLarge,

    #[error("body buffer is full")]
    BufferFull,

    #[error("body is already terminal")]
    AfterTerminal,

    #[error("request trailers are already set")]
    TrailersAlreadySet,

    #[error("body buffered byte count is inconsistent")]
    InvalidBufferedBytes,
}

#[derive(Debug, thiserror::Error)]
pub enum SemanticRequestError {
    #[error(transparent)]
    Parse(#[from] HttpParseError),

    #[error(transparent)]
    Query(#[from] ValueError),

    #[error("serialized path does not match raw path normalization")]
    PathMismatch,

    #[error("OPTIONS is required for the asterisk request target")]
    AsteriskRequiresOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    #[error("response event occurs after a terminal event")]
    AfterTerminal,

    #[error("response event is out of order")]
    InvalidOrdering,

    #[error("informational status is not in the 1xx range")]
    InvalidInformationalStatus,

    #[error("final status is in the 1xx range")]
    InvalidFinalStatus,

    #[error("response event limit is invalid")]
    InvalidLimit,

    #[error("response event buffer is full")]
    BufferFull,

    #[error("response sequence state does not match its events")]
    InvalidState,
}

fn canonical_authority(scheme: HttpScheme, authority: &HttpAuthority) -> String {
    let host = if authority.host().is_ipv6() {
        format!("[{}]", authority.host())
    } else {
        authority.host().to_string()
    };

    if authority.is_default_port(scheme) {
        host
    } else {
        format!("{host}:{}", authority.port_number())
    }
}

const fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

const fn is_invalid_header_value_byte(byte: u8) -> bool {
    (byte < 0x20 && byte != b'\t') || byte == 0x7F
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_preserves_raw_query_and_policy_ignores_it() {
        let request = SemanticRequest::from_parts(
            "GET",
            "https",
            "Example.COM:443",
            "/a/../b",
            Some("x=1&x=2"),
            SemanticHeaders::new(),
            HttpVersion::Http11,
            HttpVersion::Http11,
            None,
            BoundedRequestBody::empty(),
        )
        .expect("valid request");

        assert_eq!(
            request.raw_query.as_ref().expect("query").as_str(),
            "x=1&x=2"
        );

        assert_eq!(request.path.as_str(), "/b");

        assert_eq!(
            request
                .policy_request()
                .expect("policy request")
                .url
                .to_string(),
            "https://example.com/b"
        );

        assert_eq!(request.forwarding_target(), "/a/../b?x=1&x=2");
    }

    #[test]
    fn body_is_bounded() {
        let mut body = BoundedRequestBody::new(2, 3).expect("valid limits");
        body.push_chunk(vec![1, 2]).expect("first chunk");
        assert_eq!(body.push_chunk(vec![3, 4]), Err(BodyError::BufferFull));
        assert_eq!(body.pop_chunk(), Some(vec![1, 2]));
    }

    #[test]
    fn response_events_are_ordered_and_terminal() {
        let mut sequence = ResponseSequence::new();

        sequence
            .push(ResponseEvent::Informational(
                ResponseHead::informational(103, SemanticHeaders::new()).expect("1xx"),
            ))
            .expect("info");

        sequence
            .push(ResponseEvent::Final(
                ResponseHead::final_head(200, SemanticHeaders::new()).expect("final"),
            ))
            .expect("final");

        sequence
            .push(ResponseEvent::BodyChunk(vec![1]))
            .expect("body");

        sequence.push(ResponseEvent::Complete).expect("complete");

        assert_eq!(
            sequence.push(ResponseEvent::BodyChunk(vec![2])),
            Err(EventError::AfterTerminal)
        );
    }

    #[test]
    fn response_sequence_round_trips_and_drains() {
        let mut sequence = ResponseSequence::new();

        sequence
            .push(ResponseEvent::Final(
                ResponseHead::final_head(200, SemanticHeaders::new()).expect("final"),
            ))
            .expect("final");

        sequence
            .push(ResponseEvent::BodyChunk(vec![1]))
            .expect("body");

        sequence.push(ResponseEvent::Complete).expect("complete");
        let encoded = serde_json::to_string(&sequence).expect("wire");
        let mut decoded: ResponseSequence = serde_json::from_str(&encoded).expect("decode");
        assert!(decoded.pop_event().is_some());
        assert!(decoded.pop_event().is_some());
        assert!(decoded.pop_event().is_some());
        assert!(decoded.pop_event().is_none());
        let drained = serde_json::to_string(&decoded).expect("drained wire");

        let mut restored: ResponseSequence =
            serde_json::from_str(&drained).expect("drained decode");

        assert!(restored.pop_event().is_none());
    }

    #[test]
    fn invalid_values_are_rejected() {
        assert!(SemanticHeader::new("bad name", "value").is_err());
        assert!(RawQuery::parse("x=1#fragment").is_err());

        assert!(
            SemanticRequest::from_parts(
                "GET",
                "https",
                "example.com",
                "*",
                None,
                SemanticHeaders::new(),
                HttpVersion::Http11,
                HttpVersion::Http11,
                None,
                BoundedRequestBody::empty()
            )
            .is_err()
        );

        assert!(SemanticHeader::new("x-opaque", [0x80, b'a']).is_ok());
    }

    #[test]
    fn response_order_rejects_body_before_final_and_second_final() {
        let mut sequence = ResponseSequence::new();

        assert_eq!(
            sequence.push(ResponseEvent::BodyChunk(vec![1])),
            Err(EventError::InvalidOrdering)
        );

        sequence
            .push(ResponseEvent::Final(
                ResponseHead::final_head(204, SemanticHeaders::new()).expect("final"),
            ))
            .expect("final");

        assert_eq!(
            sequence.push(ResponseEvent::Final(
                ResponseHead::final_head(205, SemanticHeaders::new()).expect("final")
            )),
            Err(EventError::InvalidOrdering)
        );
    }

    #[test]
    fn terminal_errors_are_typed_and_serializable() {
        let error = TerminalError::PolicyDenied("approval required".into());
        let event = ResponseEvent::Error(error.clone());

        assert_eq!(
            error.to_string(),
            "policy denied request: approval required"
        );

        assert!(
            serde_json::to_string(&event)
                .expect("wire")
                .contains("PolicyDenied")
        );
    }

    #[test]
    fn terminal_failures_can_end_before_response_head() {
        let events = [
            ResponseEvent::Cancelled,
            ResponseEvent::Reset(7),
            ResponseEvent::Error(TerminalError::PolicyDenied("denied".into())),
            ResponseEvent::Error(TerminalError::Transport("closed".into())),
            ResponseEvent::Error(TerminalError::ProtocolViolation("bad frame".into())),
            ResponseEvent::Error(TerminalError::UpstreamRefused("refused".into())),
        ];

        for event in events {
            let mut sequence = ResponseSequence::new();
            sequence.push(event).expect("pre-head terminal");

            assert_eq!(
                sequence.push(ResponseEvent::BodyChunk(vec![1])),
                Err(EventError::AfterTerminal)
            );
        }
    }

    #[test]
    fn request_trailers_and_response_buffers_are_bounded() {
        let mut body = BoundedRequestBody::empty();
        body.set_trailers(SemanticHeaders::new()).expect("trailers");

        assert_eq!(
            body.set_trailers(SemanticHeaders::new()),
            Err(BodyError::TrailersAlreadySet)
        );

        body.finish().expect("finish");
        assert_eq!(body.push_chunk(vec![1]), Err(BodyError::AfterTerminal));
        let mut sequence = ResponseSequence::with_limits(3, 1).expect("limits");

        sequence
            .push(ResponseEvent::Final(
                ResponseHead::final_head(200, SemanticHeaders::new()).expect("final"),
            ))
            .expect("final");

        sequence
            .push(ResponseEvent::BodyChunk(vec![1]))
            .expect("body");

        assert_eq!(
            sequence.push(ResponseEvent::BodyChunk(vec![2])),
            Err(EventError::BufferFull)
        );
    }

    #[test]
    fn invalid_json_values_are_rejected() {
        assert!(
            serde_json::from_str::<SemanticHeader>(r#"{"name":"bad name","value":"x"}"#).is_err()
        );

        assert!(serde_json::from_str::<RawQuery>(r#""x=1#bad""#).is_err());
        assert!(serde_json::from_str::<ResponseHead>(r#"{"status":99,"headers":[]}"#).is_err());

        assert!(
            serde_json::from_str::<ResponseSequence>(r#"{"events":[{"BodyChunk":[1]}]}"#).is_err()
        );

        assert!(serde_json::from_str::<BoundedRequestBody>(
            r#"{"chunks":[[1,2,3]],"buffered_bytes":3,"max_chunk_bytes":2,"max_buffered_bytes":3}"#
        ).is_err());
    }

    #[test]
    fn wire_order_is_deterministic() {
        let mut headers = SemanticHeaders::new();
        headers.try_push("X-Test", "one").expect("header");
        headers.try_push("x-test", "two").expect("header");

        let request = SemanticRequest::from_parts(
            "GET",
            "http",
            "example.com",
            "/",
            Some("a=1&b=2"),
            headers,
            HttpVersion::Http11,
            HttpVersion::Http11,
            None,
            BoundedRequestBody::empty(),
        )
        .expect("request");

        let wire = serde_json::to_string(&request).expect("wire");

        assert_eq!(
            wire,
            r#"{"method":"GET","scheme":"http","authority":"example.com","path":{"Path":"/"},"raw_path":"/","raw_query":"a=1&b=2","headers":[{"name":"x-test","value":[111,110,101]},{"name":"x-test","value":[116,119,111]}],"source_version":"HTTP/1.1","target_version":"HTTP/1.1","session":null,"body":{"chunks":[],"buffered_bytes":0,"max_chunk_bytes":16384,"max_buffered_bytes":1048576,"trailers":null,"terminal":null}}"#
        );

        assert!(wire.contains("\"raw_query\":\"a=1&b=2\""));

        let malformed = wire.replace(
            "\"path\":{\"Path\":\"/\"}",
            "\"path\":{\"Path\":\"/wrong\"}",
        );

        assert!(serde_json::from_str::<SemanticRequest>(&malformed).is_err());
        assert!(wire.contains("\"path\":{\"Path\":\"/\"}"));
    }
}

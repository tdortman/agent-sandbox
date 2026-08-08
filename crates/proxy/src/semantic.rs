//! Protocol-independent HTTP values shared by proxy backends.
//!
//! This module deliberately does not depend on Rama, quinn, or socket types.

use agent_sandbox_core::{
    HttpAuthority, HttpMethod, HttpParseError, HttpRequest as CoreHttpRequest, HttpScheme,
    HttpSessionMetadata as CoreHttpSessionMetadata,
};
use http::HeaderMap;
use std::fmt;

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

/// Build the end-to-end headers of one request, filtering hop-by-hop
/// fields and connection-header tokens.
///
/// # Errors
/// Returns [`HeaderError`] for an invalid field name or value.
pub fn semantic_request_headers(headers: &HeaderMap) -> Result<SemanticHeaders, HeaderError> {
    let connection_tokens = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();

    let mut semantic = SemanticHeaders::new();

    for (name, value) in headers {
        if is_hop_by_hop_header(name.as_str(), &connection_tokens) {
            continue;
        }

        semantic.try_push(name.as_str(), value.as_bytes())?;
    }

    Ok(semantic)
}

/// HTTP versions supported by the semantic proxy contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestTerminal {
    Complete,
    Cancellation,
    Error(TerminalError),
}

/// Validates request body chunks without buffering them.
///
/// Production pushes each chunk and forwards it immediately, so the queue
/// never holds more than one element and the buffer limits are unreachable.
/// What survives is single-chunk validation: the chunk bound, trailers, and
/// terminal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedRequestBody {
    max_chunk_bytes: usize,
    trailers: Option<SemanticHeaders>,
    terminal: Option<RequestTerminal>,
}

impl BoundedRequestBody {
    /// # Errors
    /// Returns [`BodyError::InvalidLimit`] when the chunk bound is zero.
    pub const fn new(max_chunk_bytes: usize) -> Result<Self, BodyError> {
        if max_chunk_bytes == 0 {
            return Err(BodyError::InvalidLimit);
        }

        Ok(Self {
            max_chunk_bytes,
            trailers: None,
            terminal: None,
        })
    }

    #[must_use]
    /// # Panics
    /// This function uses fixed nonzero limits.
    pub fn empty() -> Self {
        Self::new(16 * 1024).expect("constant body limits are valid")
    }

    /// # Errors
    /// Returns [`BodyError`] when the body is terminal or the chunk exceeds
    /// the configured chunk bound.
    pub const fn push_chunk(&mut self, chunk: &[u8]) -> Result<(), BodyError> {
        if self.terminal.is_some() || self.trailers.is_some() {
            return Err(BodyError::AfterTerminal);
        }

        if chunk.len() > self.max_chunk_bytes {
            return Err(BodyError::ChunkTooLarge);
        }

        Ok(())
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
}

/// A validated semantic HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Input values for one semantic HTTP request.
pub struct SemanticRequestParts<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub raw_query: Option<&'a str>,
    pub headers: SemanticHeaders,
    pub source_version: HttpVersion,
    pub target_version: HttpVersion,
    pub session: Option<SessionMetadata>,
    pub body: BoundedRequestBody,
}

impl SemanticRequest {
    /// # Errors
    /// Returns [`SemanticRequestError`] when any request value is invalid.
    pub fn from_parts(parts: SemanticRequestParts<'_>) -> Result<Self, SemanticRequestError> {
        let method = HttpMethod::parse(parts.method)?;
        let scheme = HttpScheme::parse(parts.scheme)?;
        let authority_value = HttpAuthority::parse(scheme, parts.authority)?;
        let authority = canonical_authority(scheme, &authority_value).into_boxed_str();
        let semantic_path = SemanticPath::parse(parts.path, method.as_str())?;
        let raw_query = parts.raw_query.map(RawQuery::parse).transpose()?;

        Ok(Self {
            method,
            scheme,
            authority,
            path: semantic_path,
            raw_path: parts.path.into(),
            raw_query,
            headers: parts.headers,
            source_version: parts.source_version,
            target_version: parts.target_version,
            session: parts.session,
            body: parts.body,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Ordered response events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseEvent {
    Final(ResponseHead),
    BodyChunk(Vec<u8>),
    Trailers(SemanticHeaders),
    Complete,
    Cancelled,
    Error(TerminalError),
}

/// A response status and its headers.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Typed terminal failures shared by all protocol backends.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TerminalError {
    #[error("request cancelled")]
    Cancellation,

    #[error("transport failure: {0}")]
    Transport(Box<str>),

    #[error("protocol violation: {0}")]
    ProtocolViolation(Box<str>),
}

/// Response event sequence validator.
///
/// Production validates each event as it arrives and forwards it immediately,
/// so events are never queued and the event-count limit is unreachable. What
/// survives is phase validation: final head ordering, trailers, terminal
/// state, and the single-chunk bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseSequence {
    final_seen: bool,
    trailers_seen: bool,
    terminal_seen: bool,
    max_body_bytes: usize,
}

impl ResponseSequence {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            final_seen: false,
            trailers_seen: false,
            terminal_seen: false,
            max_body_bytes: 1024 * 1024,
        }
    }

    /// Construct a sequence with a custom body bound.
    #[must_use]
    pub const fn with_limits(max_body_bytes: usize) -> Self {
        let mut sequence = Self::new();
        sequence.max_body_bytes = max_body_bytes;
        sequence
    }

    /// # Errors
    /// Returns [`EventError`] when the event is out of order or exceeds the
    /// chunk bound.
    pub fn push(&mut self, event: ResponseEvent) -> Result<(), EventError> {
        if self.terminal_seen {
            return Err(EventError::AfterTerminal);
        }

        match event {
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
                if chunk.len() > self.max_body_bytes {
                    return Err(EventError::BufferFull);
                }
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

            ResponseEvent::Cancelled | ResponseEvent::Error(_) => {
                self.terminal_seen = true;
            }
        }

        Ok(())
    }
}

impl Default for ResponseSequence {
    fn default() -> Self {
        Self::new()
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
        let request = SemanticRequest::from_parts(SemanticRequestParts {
            method: "GET",
            scheme: "https",
            authority: "Example.COM:443",
            path: "/a/../b",
            raw_query: Some("x=1&x=2"),
            headers: SemanticHeaders::new(),
            source_version: HttpVersion::Http11,
            target_version: HttpVersion::Http11,
            session: None,
            body: BoundedRequestBody::empty(),
        })
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
    fn body_chunk_bound_and_limits_are_validated() {
        let mut body = BoundedRequestBody::new(2).expect("valid limits");
        body.push_chunk(&[1, 2]).expect("chunk at the bound");
        assert_eq!(body.push_chunk(&[1, 2, 3]), Err(BodyError::ChunkTooLarge));

        assert_eq!(BoundedRequestBody::new(0), Err(BodyError::InvalidLimit));
    }

    #[test]
    fn response_events_are_ordered_and_terminal() {
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

        assert_eq!(
            sequence.push(ResponseEvent::BodyChunk(vec![2])),
            Err(EventError::AfterTerminal)
        );
    }

    #[test]
    fn invalid_values_are_rejected() {
        assert!(SemanticHeader::new("bad name", "value").is_err());
        assert!(RawQuery::parse("x=1#fragment").is_err());

        assert!(
            SemanticRequest::from_parts(SemanticRequestParts {
                method: "GET",
                scheme: "https",
                authority: "example.com",
                path: "*",
                raw_query: None,
                headers: SemanticHeaders::new(),
                source_version: HttpVersion::Http11,
                target_version: HttpVersion::Http11,
                session: None,
                body: BoundedRequestBody::empty(),
            })
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
    fn response_sequence_rejects_late_headers_and_tracks_terminal_after_trailers() {
        let mut sequence = ResponseSequence::new();

        sequence
            .push(ResponseEvent::Final(
                ResponseHead::final_head(200, SemanticHeaders::new()).expect("final"),
            ))
            .expect("final");

        sequence
            .push(ResponseEvent::BodyChunk(vec![1]))
            .expect("body");

        sequence
            .push(ResponseEvent::Trailers(SemanticHeaders::new()))
            .expect("trailers");

        assert_eq!(
            sequence.push(ResponseEvent::BodyChunk(vec![2])),
            Err(EventError::InvalidOrdering)
        );

        sequence.push(ResponseEvent::Cancelled).expect("cancelled");

        assert_eq!(
            sequence.push(ResponseEvent::Complete),
            Err(EventError::AfterTerminal)
        );
    }

    #[test]
    fn terminal_errors_are_typed() {
        let error = TerminalError::Transport("closed".into());
        let event = ResponseEvent::Error(error.clone());

        assert_eq!(error.to_string(), "transport failure: closed");
        assert_eq!(
            event,
            ResponseEvent::Error(TerminalError::Transport("closed".into()))
        );
    }

    #[test]
    fn terminal_failures_can_end_before_response_head() {
        let events = [
            ResponseEvent::Cancelled,
            ResponseEvent::Error(TerminalError::Transport("closed".into())),
            ResponseEvent::Error(TerminalError::ProtocolViolation("bad frame".into())),
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
    fn request_trailers_and_response_chunk_bound_apply() {
        let mut body = BoundedRequestBody::empty();
        body.set_trailers(SemanticHeaders::new()).expect("trailers");

        assert_eq!(
            body.set_trailers(SemanticHeaders::new()),
            Err(BodyError::TrailersAlreadySet)
        );

        body.finish().expect("finish");
        assert_eq!(body.push_chunk(&[1]), Err(BodyError::AfterTerminal));
        let mut sequence = ResponseSequence::with_limits(1);

        sequence
            .push(ResponseEvent::Final(
                ResponseHead::final_head(200, SemanticHeaders::new()).expect("final"),
            ))
            .expect("final");

        sequence
            .push(ResponseEvent::BodyChunk(vec![1]))
            .expect("body");

        assert_eq!(
            sequence.push(ResponseEvent::BodyChunk(vec![2; 2])),
            Err(EventError::BufferFull)
        );
    }
}

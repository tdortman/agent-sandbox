//! Protocol-independent HTTP values shared by proxy backends.
//!
//! This module deliberately does not depend on Rama, quinn, or socket types.

use std::fmt;

use agent_sandbox_core::{
    HttpAuthority, HttpMethod, HttpParseError, HttpRequest as CoreHttpRequest, HttpScheme,
    HttpSessionMetadata as CoreHttpSessionMetadata,
};
use http::{HeaderMap, HeaderName, HeaderValue};

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
/// Returns an error for an invalid field name or value.
pub fn semantic_request_headers(
    headers: &HeaderMap,
) -> Result<SemanticHeaders, Box<dyn std::error::Error + Send + Sync>> {
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
    /// HTTP/1.0.
    Http10,
    /// HTTP/1.1.
    Http11,
    /// HTTP/2.
    Http2,
    /// HTTP/3.
    Http3,
}

impl HttpVersion {
    /// The wire-format version string.
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

/// An ordered collection of validated end-to-end headers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SemanticHeaders(Vec<(HeaderName, HeaderValue)>);

impl SemanticHeaders {
    /// Create an empty header collection.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// # Errors
    /// Returns an error for an invalid field name or value.
    pub fn try_push<V>(
        &mut self,
        name: &str,
        value: V,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        V: AsRef<[u8]>,
    {
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_ref())?;
        self.0.push((name, value));
        Ok(())
    }

    /// The headers as a slice, in insertion order.
    #[must_use]
    pub fn as_slice(&self) -> &[(HeaderName, HeaderValue)] {
        &self.0
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

    /// The query string without its leading `?`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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
    /// The request body stream completed normally.
    Complete,
    /// The request was cancelled.
    Cancellation,
    /// The request body failed terminally.
    Error(TerminalError),
}

/// Validates request body chunks without buffering them.
///
/// Production pushes each chunk and forwards it immediately, so the queue
/// never holds more than one element and the buffer limit is unreachable.
/// What survives is single-chunk validation: the chunk bound, trailers, and
/// terminal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedRequestBody {
    max_chunk_bytes: usize,
    trailers: bool,
    terminal: bool,
}

impl BoundedRequestBody {
    /// Create an empty request body validator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_chunk_bytes: 16 * 1024,
            trailers: false,
            terminal: false,
        }
    }

    /// Create an empty request body validator.
    #[must_use]
    pub const fn empty() -> Self {
        Self::new()
    }
}

impl Default for BoundedRequestBody {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedRequestBody {
    /// # Errors
    /// Returns [`BodyError`] when the body is terminal or the chunk exceeds
    /// the configured chunk bound.
    pub const fn push_chunk(&mut self, chunk: &[u8]) -> Result<(), BodyError> {
        if self.terminal || self.trailers {
            return Err(BodyError::AfterTerminal);
        }

        if chunk.len() > self.max_chunk_bytes {
            return Err(BodyError::ChunkTooLarge);
        }

        Ok(())
    }

    /// # Errors
    /// Returns [`BodyError`] when the body is terminal or already has trailers.
    pub const fn set_trailers(&mut self) -> Result<(), BodyError> {
        if self.terminal {
            return Err(BodyError::AfterTerminal);
        }

        if self.trailers {
            return Err(BodyError::TrailersAlreadySet);
        }

        self.trailers = true;
        Ok(())
    }

    /// # Errors
    /// Returns [`BodyError::AfterTerminal`] when the body is already terminal.
    pub const fn finish(&mut self) -> Result<(), BodyError> {
        self.terminate()
    }

    /// # Errors
    /// Returns [`BodyError::AfterTerminal`] when the body is already terminal.
    pub const fn terminate(&mut self) -> Result<(), BodyError> {
        if self.terminal {
            return Err(BodyError::AfterTerminal);
        }

        self.terminal = true;
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
    session: Option<SessionMetadata>,
    body: BoundedRequestBody,
}

/// Input values for one semantic HTTP request.
pub struct SemanticRequestParts<'a> {
    /// The request method.
    pub method: &'a str,
    /// The URI scheme.
    pub scheme: &'a str,
    /// The request authority.
    pub authority: &'a str,
    /// The request path.
    pub path: &'a str,
    /// The raw (unparsed) query, without a leading `?`.
    pub raw_query: Option<&'a str>,
    /// The validated end-to-end request headers.
    pub headers: SemanticHeaders,
    /// Optional session attribution.
    pub session: Option<SessionMetadata>,
    /// The request body state.
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

    /// The raw path and query as forwarded to the upstream, preserving the
    /// original un-normalized path.
    #[must_use]
    pub fn forwarding_target(&self) -> String {
        self.raw_query.as_ref().map_or_else(
            || self.raw_path.to_string(),
            |query| format!("{}?{}", self.raw_path, query.as_str()),
        )
    }

    /// The request method.
    #[must_use]
    pub const fn method(&self) -> &HttpMethod {
        &self.method
    }

    /// The canonical request authority.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The validated end-to-end request headers.
    #[must_use]
    pub const fn headers(&self) -> &SemanticHeaders {
        &self.headers
    }

    /// The optional session attribution.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionMetadata> {
        self.session.as_ref()
    }

    /// Consume the request and return its body state.
    #[must_use]
    pub fn into_body(self) -> BoundedRequestBody {
        self.body
    }
}

/// The normalized request path, or the asterisk-form OPTIONS target.
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

    /// The path as a string: normalized, or `*` for asterisk-form.
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
    /// The final response head.
    Final(ResponseHead),
    /// One body chunk.
    BodyChunk(Vec<u8>),
    /// Trailing response headers.
    Trailers(SemanticHeaders),
    /// The body stream ended cleanly.
    Complete,
    /// The response was cancelled before completion.
    Cancelled,
    /// A typed terminal failure.
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
    /// Returns [`EventError`] when the status is not a valid final status.
    pub fn final_head(status: u16, headers: SemanticHeaders) -> Result<Self, EventError> {
        if !(200..1000).contains(&status) {
            return Err(EventError::InvalidFinalStatus);
        }

        Ok(Self { status, headers })
    }

    /// The final HTTP status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    /// The response headers.
    pub const fn headers(&self) -> &SemanticHeaders {
        &self.headers
    }
}

/// Typed terminal failures shared by all protocol backends.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TerminalError {
    /// The request was cancelled.
    #[error("request cancelled")]
    Cancellation,

    /// A transport-level failure.
    #[error("transport failure: {0}")]
    Transport(Box<str>),

    /// A protocol violation.
    #[error("protocol violation: {0}")]
    ProtocolViolation(Box<str>),
}

/// Response event sequence validator.
///
/// Production validates each event as it arrives and forwards it immediately,
/// so events are never queued and the event-count limit is unreachable. What
/// survives is phase validation: final head ordering, trailers, and terminal
/// state.
/// Upper bound on a single body chunk the proxy accepts from an upstream.
/// A chunk above this size is rejected as [`EventError::BufferFull`] to stop
/// a peer from forcing a single oversized allocation.
const MAX_BODY_CHUNK_BYTES: usize = 1024 * 1024;

/// Tracks the validation state of a streamed response event sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseSequence {
    final_seen: bool,
    trailers_seen: bool,
    terminal_seen: bool,
}

impl ResponseSequence {
    /// Create an empty response sequence validator.
    /// A response may only start with a final head or a terminal event.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            final_seen: false,
            trailers_seen: false,
            terminal_seen: false,
        }
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
                if chunk.len() > MAX_BODY_CHUNK_BYTES {
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

/// Validation failure for a semantic value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValueError {
    /// The raw query contains a fragment or control byte.
    #[error("invalid raw query")]
    InvalidQuery,
}

/// Body stream validation failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BodyError {
    /// The body chunk exceeds the configured limit.
    #[error("body chunk exceeds the configured limit")]
    ChunkTooLarge,

    /// The body is already terminal.
    #[error("body is already terminal")]
    AfterTerminal,

    /// Request trailers are already set.
    #[error("request trailers are already set")]
    TrailersAlreadySet,
}

/// Failure constructing a semantic HTTP request.
#[derive(Debug, thiserror::Error)]
pub enum SemanticRequestError {
    /// A request value failed to parse.
    #[error(transparent)]
    Parse(#[from] HttpParseError),

    /// The raw query is invalid.
    #[error(transparent)]
    Query(#[from] ValueError),

    /// The asterisk request target is only valid for `OPTIONS`.
    #[error("OPTIONS is required for the asterisk request target")]
    AsteriskRequiresOptions,
}

/// Response event sequence validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    /// A response event occurs after a terminal event.
    #[error("response event occurs after a terminal event")]
    AfterTerminal,

    /// A response event is out of order.
    #[error("response event is out of order")]
    InvalidOrdering,

    /// A response body chunk exceeds the configured limit.
    #[error("response body chunk exceeds the configured limit")]
    BufferFull,

    /// The final status is in the 1xx range.
    #[error("final status is in the 1xx range")]
    InvalidFinalStatus,
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

#[cfg(test)]
mod tests {
    use super::*;

    impl BoundedRequestBody {
        fn with_chunk_bound(max_chunk_bytes: usize) -> Self {
            Self {
                max_chunk_bytes,
                trailers: false,
                terminal: false,
            }
        }
    }

    #[test]
    fn request_wire_preserves_raw_query_and_policy_ignores_it() {
        let request = SemanticRequest::from_parts(SemanticRequestParts {
            method: "GET",
            scheme: "https",
            authority: "Example.COM:443",
            path: "/a/../b",
            raw_query: Some("x=1&x=2"),
            headers: SemanticHeaders::new(),
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
    fn body_chunk_bound_is_validated() {
        let mut body = BoundedRequestBody::with_chunk_bound(2);
        body.push_chunk(&[1, 2]).expect("chunk at the bound");
        assert_eq!(body.push_chunk(&[1, 2, 3]), Err(BodyError::ChunkTooLarge));
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
        let mut headers = SemanticHeaders::new();
        assert!(headers.try_push("bad name", "value").is_err());
        assert!(RawQuery::parse("x=1#fragment").is_err());

        assert!(
            SemanticRequest::from_parts(SemanticRequestParts {
                method: "GET",
                scheme: "https",
                authority: "example.com",
                path: "*",
                raw_query: None,
                headers: SemanticHeaders::new(),
                session: None,
                body: BoundedRequestBody::empty(),
            })
            .is_err()
        );

        assert!(headers.try_push("x-opaque", [0x80, b'a']).is_ok());
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
    fn sequence_rejects_single_body_chunk_over_the_bound() {
        let mut sequence = ResponseSequence::new();
        sequence
            .push(ResponseEvent::Final(
                ResponseHead::final_head(200, SemanticHeaders::new()).expect("final"),
            ))
            .expect("final");

        assert_eq!(
            sequence.push(ResponseEvent::BodyChunk(vec![0; MAX_BODY_CHUNK_BYTES + 1])),
            Err(EventError::BufferFull)
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
    fn request_trailers_and_termination_apply() {
        let mut body = BoundedRequestBody::empty();
        body.set_trailers().expect("trailers");

        assert_eq!(body.set_trailers(), Err(BodyError::TrailersAlreadySet));

        body.finish().expect("finish");
        assert_eq!(body.push_chunk(&[1]), Err(BodyError::AfterTerminal));
    }
}

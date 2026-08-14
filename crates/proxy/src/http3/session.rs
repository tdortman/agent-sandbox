//! HTTP/3 extended-session validation and wire helpers.

use std::fmt;

use agent_sandbox_core::{AttributionToken, HttpSessionMetadata};
use bytes::Bytes;
use h3::{ext::Protocol, quic::StreamId};

const MAX_CAPSULE_BYTES: usize = 1024 * 1024;
const MAX_CONNECT_UDP_PAYLOAD_BYTES: usize = 65_527;
pub(super) const DATAGRAM_CAPSULE_TYPE: u64 = 0;

/// One protocol supported by the approved HTTP/3 session path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionProtocol {
    /// RFC 9220 WebSocket extended CONNECT.
    WebSocket,

    /// WebTransport over HTTP/3.
    WebTransport,

    /// RFC 9298 CONNECT-UDP.
    ConnectUdp,
}

impl SessionProtocol {
    /// Parse the HTTP/3 `:protocol` extension.
    ///
    /// # Errors
    ///
    /// Returns an error for a protocol outside this ticket's session set.
    pub fn from_extension(protocol: Protocol) -> Result<Self, SessionError> {
        match protocol.as_str() {
            "websocket" => Ok(Self::WebSocket),
            "webtransport" => Ok(Self::WebTransport),
            "connect-udp" => Ok(Self::ConnectUdp),
            _ => Err(SessionError::UnsupportedProtocol),
        }
    }

    /// Return the HTTP/3 protocol extension value.
    #[must_use]
    pub const fn extension(self) -> Protocol {
        match self {
            Self::WebSocket => Protocol::WEBSOCKET,
            Self::WebTransport => Protocol::WEB_TRANSPORT,
            Self::ConnectUdp => Protocol::CONNECT_UDP,
        }
    }

    /// Return the policy metadata kind and protocol value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::WebSocket => "websocket",
            Self::WebTransport => "webtransport",
            Self::ConnectUdp => "connect-udp",
        }
    }

    /// Whether this protocol uses HTTP Datagrams or Capsules.
    #[must_use]
    pub const fn needs_datagrams(self) -> bool {
        matches!(self, Self::WebTransport | Self::ConnectUdp)
    }
}

/// Build the policy metadata for one extended CONNECT request.
///
/// # Errors
///
/// Returns an error when the target is not valid metadata.
pub fn metadata(
    protocol: SessionProtocol,
    target: &str,
) -> Result<HttpSessionMetadata, SessionError> {
    HttpSessionMetadata::new(Some(protocol.name()), Some(protocol.name()), Some(target))
        .map_err(|_| SessionError::InvalidMetadata)
}

/// One approved session identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// The policy-approved origin authority.
    pub origin: String,

    /// The policy-approved session target.
    pub target: String,

    /// The policy-approved protocol.
    pub protocol: SessionProtocol,

    /// The policy attribution that approved the session.
    pub attribution: AttributionToken,
}

/// A validated capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    /// Capsule type.
    pub kind: u64,

    /// Capsule payload without the type and length fields.
    pub payload: Bytes,
}

/// Incremental Capsule Protocol decoder.
#[derive(Debug, Default)]
pub struct CapsuleDecoder {
    buffered: Vec<u8>,
}

impl CapsuleDecoder {
    /// Add one body chunk and return every complete capsule.
    ///
    /// # Errors
    ///
    /// Returns an error when a varint or capsule length is invalid.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Capsule>, SessionError> {
        if self.buffered.len().saturating_add(chunk.len()) > MAX_CAPSULE_BYTES {
            return Err(SessionError::CapsuleTooLarge);
        }

        self.buffered.extend_from_slice(chunk);
        let mut offset = 0;
        let mut capsules = Vec::new();

        while offset < self.buffered.len() {
            let Some((kind, kind_len)) = decode_varint(&self.buffered[offset..])? else {
                break;
            };

            let Some((length, length_len)) = decode_varint(&self.buffered[offset + kind_len..])?
            else {
                break;
            };

            if length > MAX_CAPSULE_BYTES as u64 {
                return Err(SessionError::CapsuleTooLarge);
            }

            let start = offset + kind_len + length_len;

            let end = start
                .checked_add(usize::try_from(length).map_err(|_| SessionError::InvalidCapsule)?)
                .ok_or(SessionError::InvalidCapsule)?;

            if end > self.buffered.len() {
                break;
            }

            capsules.push(Capsule {
                kind,
                payload: Bytes::copy_from_slice(&self.buffered[start..end]),
            });

            offset = end;
        }

        if offset != 0 {
            self.buffered.drain(..offset);
        }

        Ok(capsules)
    }

    /// Reject a truncated final capsule.
    ///
    /// # Errors
    ///
    /// Returns an error when incomplete bytes remain.
    pub fn finish(self) -> Result<(), SessionError> {
        if self.buffered.is_empty() {
            Ok(())
        } else {
            Err(SessionError::InvalidCapsule)
        }
    }
}

/// Encode one Capsule Protocol message.
#[must_use]
pub fn encode_capsule(kind: u64, payload: &[u8]) -> Bytes {
    let mut encoded =
        Vec::with_capacity(varint_len(kind) + varint_len(payload.len() as u64) + payload.len());

    encode_varint(kind, &mut encoded);
    encode_varint(payload.len() as u64, &mut encoded);
    encoded.extend_from_slice(payload);
    Bytes::from(encoded)
}

/// Encode a CONNECT-UDP DATAGRAM capsule for context zero.
#[cfg(test)]
#[must_use]
pub fn encode_connect_udp_datagram(payload: &[u8]) -> Bytes {
    encode_capsule(
        DATAGRAM_CAPSULE_TYPE,
        &encode_connect_udp_datagram_payload(payload),
    )
}

/// Encode one CONNECT-UDP HTTP Datagram payload with context zero.
#[must_use]
pub fn encode_connect_udp_datagram_payload(payload: &[u8]) -> Bytes {
    let mut value = Vec::with_capacity(varint_len(0) + payload.len());
    encode_varint(0, &mut value);
    value.extend_from_slice(payload);
    Bytes::from(value)
}

/// Decode the payload of a CONNECT-UDP DATAGRAM capsule.
///
/// # Errors
///
/// Returns an error when the context identifier is not zero or the payload
/// exceeds the maximum CONNECT-UDP datagram size.
pub fn decode_connect_udp_datagram(payload: &[u8]) -> Result<Bytes, SessionError> {
    let Some((context, context_len)) = decode_varint(payload)? else {
        return Err(SessionError::InvalidCapsule);
    };

    if context != 0 {
        return Err(SessionError::InvalidDatagramContext);
    }

    let payload = &payload[context_len..];

    if payload.len() > MAX_CONNECT_UDP_PAYLOAD_BYTES {
        return Err(SessionError::DatagramTooLarge);
    }

    Ok(Bytes::copy_from_slice(payload))
}

/// Encode one HTTP Datagram with a quarter stream ID prefix.
///
/// # Errors
///
/// Returns an error when the stream is not a client-initiated bidirectional
/// stream.
pub fn encode_http_datagram(stream_id: StreamId, payload: &[u8]) -> Result<Bytes, SessionError> {
    let id = stream_id.into_inner();

    if !id.is_multiple_of(4) {
        return Err(SessionError::InvalidDatagramContext);
    }

    let quarter_id = id / 4;
    let mut encoded = Vec::with_capacity(varint_len(quarter_id) + payload.len());
    encode_varint(quarter_id, &mut encoded);
    encoded.extend_from_slice(payload);
    Ok(Bytes::from(encoded))
}

/// Decode one HTTP Datagram and validate its quarter stream ID.
///
/// # Errors
///
/// Returns an error for malformed, oversized, or misdirected datagrams.
pub fn decode_http_datagram(datagram: &[u8], expected: StreamId) -> Result<Bytes, SessionError> {
    let Some((quarter_id, prefix_len)) = decode_varint(datagram)? else {
        return Err(SessionError::InvalidDatagramContext);
    };

    let stream_id = quarter_id
        .checked_mul(4)
        .and_then(|id| StreamId::try_from(id).ok())
        .ok_or(SessionError::InvalidDatagramContext)?;

    if stream_id != expected {
        return Err(SessionError::InvalidDatagramContext);
    }

    let payload = &datagram[prefix_len..];

    if payload.len() > MAX_CONNECT_UDP_PAYLOAD_BYTES {
        return Err(SessionError::DatagramTooLarge);
    }

    Ok(Bytes::copy_from_slice(payload))
}

/// Errors raised before an approved session reaches an upstream peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// The peer does not support the requested session protocol.
    UnsupportedProtocol,

    /// The policy metadata is malformed.
    InvalidMetadata,

    /// A capsule is malformed or truncated.
    InvalidCapsule,

    /// A capsule exceeds the bounded relay buffer.
    CapsuleTooLarge,

    /// A datagram uses a context for another session.
    InvalidDatagramContext,

    /// A datagram exceeds the maximum payload size.
    DatagramTooLarge,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedProtocol => "unsupported HTTP/3 session protocol",
            Self::InvalidMetadata => "invalid HTTP/3 session metadata",
            Self::InvalidCapsule => "invalid Capsule Protocol message",
            Self::CapsuleTooLarge => "Capsule Protocol buffer exceeds limit",
            Self::InvalidDatagramContext => "invalid HTTP Datagram context",
            Self::DatagramTooLarge => "HTTP Datagram payload exceeds limit",
        };

        formatter.write_str(message)
    }
}

impl std::error::Error for SessionError {}

fn decode_varint(bytes: &[u8]) -> Result<Option<(u64, usize)>, SessionError> {
    let Some(first) = bytes.first().copied() else {
        return Ok(None);
    };

    let length = 1usize << (first >> 6);

    if bytes.len() < length {
        return Ok(None);
    }

    let mut value = u64::from(first & 0x3F);

    for byte in &bytes[1..length] {
        value = value
            .checked_shl(8)
            .and_then(|value| value.checked_add(u64::from(*byte)))
            .ok_or(SessionError::InvalidCapsule)?;
    }

    Ok(Some((value, length)))
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=63 => output.push(u8::try_from(value).expect("bounded QUIC varint")),

        64..=16_383 => {
            let value = u16::try_from(value | 0x4000).expect("bounded QUIC varint");
            output.extend_from_slice(&value.to_be_bytes());
        }

        16_384..=1_073_741_823 => {
            let value = u32::try_from(value | 0x8000_0000).expect("bounded QUIC varint");
            output.extend_from_slice(&value.to_be_bytes());
        }

        _ => {
            let value = value | 0xC000_0000_0000_0000;
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

const fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_decoder_handles_split_messages() {
        let encoded = encode_capsule(7, b"payload");
        let mut decoder = CapsuleDecoder::default();
        assert!(decoder.push(&encoded[..2]).expect("first chunk").is_empty());

        assert_eq!(decoder.push(&encoded[2..]).expect("second chunk"), [
            Capsule {
                kind: 7,
                payload: Bytes::from_static(b"payload"),
            }
        ]);

        decoder.finish().expect("complete capsule");
    }

    #[test]
    fn capsule_decoder_rejects_oversized_declared_length() {
        let mut encoded = Vec::new();
        encode_varint(0, &mut encoded);
        encode_varint((MAX_CAPSULE_BYTES + 1) as u64, &mut encoded);

        assert_eq!(
            CapsuleDecoder::default().push(&encoded),
            Err(SessionError::CapsuleTooLarge)
        );
    }

    #[test]
    fn datagram_context_and_stream_id_are_pinned() {
        let capsule = encode_connect_udp_datagram(b"hello");
        let mut decoder = CapsuleDecoder::default();
        let capsule = decoder.push(&capsule).expect("decode capsule").remove(0);

        assert_eq!(
            decode_connect_udp_datagram(&capsule.payload).expect("context zero"),
            Bytes::from_static(b"hello")
        );

        assert_eq!(
            decode_http_datagram(
                &encode_http_datagram(StreamId::try_from(16).expect("stream id"), b"hello")
                    .expect("encode datagram"),
                StreamId::try_from(16).expect("stream id")
            )
            .expect("stream context"),
            Bytes::from_static(b"hello")
        );
    }

    #[test]
    fn connect_udp_capsule_round_trip_preserves_payload() {
        let inbound = encode_connect_udp_datagram(b"capsule");

        let capsule = CapsuleDecoder::default()
            .push(&inbound)
            .expect("decode inbound capsule")
            .remove(0);

        let payload =
            decode_connect_udp_datagram(&capsule.payload).expect("decode CONNECT-UDP payload");

        let outbound = encode_capsule(
            DATAGRAM_CAPSULE_TYPE,
            &encode_connect_udp_datagram_payload(&payload),
        );

        let capsule = CapsuleDecoder::default()
            .push(&outbound)
            .expect("decode outbound capsule")
            .remove(0);

        assert_eq!(
            decode_connect_udp_datagram(&capsule.payload).expect("decode outbound payload"),
            Bytes::from_static(b"capsule")
        );
    }

    #[test]
    fn webtransport_datagram_capsule_payload_is_implicit() {
        let payload = Bytes::from_static(b"webtransport-capsule");
        let encoded = encode_capsule(DATAGRAM_CAPSULE_TYPE, &payload);

        let capsule = CapsuleDecoder::default()
            .push(&encoded)
            .expect("decode capsule")
            .remove(0);

        assert_eq!(capsule.payload, payload);
    }

    #[test]
    fn invalid_context_is_rejected() {
        let mut value = Vec::new();
        encode_varint(1, &mut value);
        value.extend_from_slice(b"payload");

        assert_eq!(
            decode_connect_udp_datagram(&value),
            Err(SessionError::InvalidDatagramContext)
        );
    }

    #[test]
    fn oversized_connect_udp_datagram_is_rejected() {
        let payload = vec![0; MAX_CONNECT_UDP_PAYLOAD_BYTES + 1];
        let encoded = encode_connect_udp_datagram(&payload);

        let capsule = CapsuleDecoder::default()
            .push(&encoded)
            .expect("decode capsule")
            .remove(0);

        assert_eq!(
            decode_connect_udp_datagram(&capsule.payload),
            Err(SessionError::DatagramTooLarge)
        );
    }

    #[test]
    fn protocol_extensions_require_their_session_settings() {
        assert_eq!(
            SessionProtocol::from_extension(Protocol::WEB_TRANSPORT).expect("WebTransport"),
            SessionProtocol::WebTransport
        );

        assert!(SessionProtocol::WebTransport.needs_datagrams());
        assert!(!SessionProtocol::WebSocket.needs_datagrams());

        assert_eq!(
            SessionProtocol::from_extension(Protocol::CONNECT_UDP).expect("CONNECT-UDP"),
            SessionProtocol::ConnectUdp
        );
    }
}

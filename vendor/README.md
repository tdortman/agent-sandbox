# Vendored crates

This directory contains crates vendored from crates.io, some with
project-local patches. Each directory name includes the upstream version.
This file summarises the high-level changes in each crate compared to its
original upstream release; unchanged crates are listed as-is.

## h3 0.0.8

Client response handling:

- `recv_response()` now consumes and discards informational (1xx)
  responses, matching the behaviour callers previously expected.
- Added `recv_response_with_informational()`, which returns all
  informational responses in order together with the final response.
- Added `recv_response_head()`, which receives a single response head for
  callers that want to process each head themselves.
- More than 16 informational responses abort the stream with
  `H3_EXCESSIVE_LOAD`.

No other changes.

## h3-datagram 0.0.2

Vendored unmodified.

## h3-webtransport 0.1.2

- Added `accept_with_response()` and `accept_request_with_response()`, so
  callers can supply their own response to a WebTransport CONNECT request
  instead of the built-in 200/400 reply.
- The existing `accept()` and `accept_request()` now delegate to those
  methods with the default response.
- A successful caller-provided response still gets the
  `sec-webtransport-http3-draft: draft02` header if it is missing.

## quinn 0.11.11 and quinn-proto 0.11.16

- `quinn-proto` now emits authenticated `ConnectionIdEvent` values for
  locally-issued connection IDs, and `quinn::Connection` exposes them
  through `poll_connection_id_event()` alongside `stable_id()`.
- The transparent HTTP/3 backend uses these events to bind active and
  retired connection IDs to policy ownership without parsing encrypted
  QUIC packets.

## rustls 0.23.43

- Added RFC 9849 shared-mode server ECH, which upstream rustls does not
  implement. The patch is modelled on the open upstream PR
  `rustls/rustls#2993`.
- New `ServerConfig::with_ech_keys` API, HPKE decryption of the outer
  ClientHello, and byte-exact reconstruction of the inner hello (session
  ID restore and `ech_outer_extensions` decompression) feeding SNI, ALPN,
  key share and the handshake transcript.
- `ServerHello.random` carries the section 7.2 accept confirmation;
  `HelloRetryRequest` carries the section 7.2.1 confirmation; rejected
  offers advertise `retry_configs` in `EncryptedExtensions` only when the
  client offered ECH.
- Upstream server ECH has no release target, so this crate stays pinned
  at 0.23.43 (matching the workspace version requirement, so quinn and
  rama keep resolving to it unchanged) until upstream offers an
  equivalent API.

## rama-http-core 0.3.0

The high-level HTTP services previously exposed only the final response. This
patch lets the TCP proxy relay informational responses while the origin is still
processing the request.

- Added the `InformationalSender` request extension for HTTP/1 and HTTP/2
  servers. A service can queue interim heads before returning its final response.
- HTTP/1 writes interim heads without completing the response or changing body
  framing. HTTP/1.0 clients receive no interim heads.
- HTTP/2 forwards interim heads through the existing `send_informational` API.
- The HTTP/2 client now invokes the existing `OnInformational` callback, matching
  the HTTP/1 client. It consumes interim heads before polling the final response.
- Forwarding is limited to 16 upstream interim heads per request. Overflow fails the
  connection or stream. `101 Switching Protocols` uses the existing upgrade
  path, and the interim API rejects it and body-framing headers.
- The proxy filters hop-by-hop headers. HTTP/1's existing local `100 Continue`
  behavior remains; the proxy suppresses a duplicate upstream `100` when the
  downstream requested `100-continue`.

The proxy's `transparent_suite/compatibility.rs` tests exercise the wire behavior,
including early hints before a gated final response, uploads, and h2c streaming.
Remove this patch once upstream Rama exposes equivalent interim response
forwarding on both server protocols and its HTTP/2 client, then rerun those tests.

HTTP/2 recovery also preserves whether a stream was above a remote GOAWAY's
last-stream ID. The public `h2::Error::is_unprocessed()` reports this case and
remote `REFUSED_STREAM` resets. Ordinary connection errors remain ineligible.
The proxy retries once only while its request body is unconsumed and available,
preserving the destination, attribution, and HTTP version. The raw-peer
`h2_recovery_retries_only_unprocessed_recoverable_requests_once` test covers
GOAWAY boundaries, reset reasons, uploads, and the retry limit.

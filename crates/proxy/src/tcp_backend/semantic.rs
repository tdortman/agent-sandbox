use std::{
    pin::Pin,
    task::{Context, Poll},
};

use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt},
};
use rama_http::{
    Body, HeaderMap, Response, Version,
    body::{Frame, StreamingBody},
};

use crate::{
    policy::{normalize_authority, reconcile_authorities},
    semantic::{
        BoundedRequestBody, HttpVersion as SemanticHttpVersion, ResponseEvent, ResponseHead,
        ResponseSequence, SemanticHeaders, TerminalError, is_hop_by_hop_header,
    },
    tcp_backend::is_websocket_upgrade_response,
};

/// Resolve the single policy authority for one downstream request from its
/// authority candidates: the `Host` header wins, then the URI authority, then
/// the TLS server name; an HTTP/1.0 request without any of them falls back to
/// the original destination. Every pair of present candidates must agree on
/// the fallback port.
///
/// # Errors
///
/// Returns an error when candidates conflict or no candidate exists.
pub fn resolve_request_authority(
    header_host: Option<String>,
    uri_host: Option<String>,
    tls_host: Option<String>,
    ip_fallback: Option<String>,
    fallback_port: u16,
) -> Result<String, BoxError> {
    if let (Some(header), Some(uri)) = (&header_host, &uri_host) {
        reconcile_authorities(&[header, uri], fallback_port)
            .map_err(|error| error.into_boxed("HTTP request has conflicting origin authorities"))?;
    }

    if let Some(tls) = tls_host.as_deref()
        && let Some(request_host) = header_host.as_deref().or(uri_host.as_deref())
    {
        reconcile_authorities(&[tls, request_host], fallback_port)
            .map_err(|error| error.into_boxed("HTTP request conflicts with TLS server identity"))?;
    }

    let host = header_host
        .or(uri_host)
        .or(tls_host)
        .or(ip_fallback)
        .ok_or_else(|| BoxError::from_static_str("HTTP request has no authority"))?;

    normalize_authority(&host, fallback_port).map_err(BoxError::from)
}

const SEMANTIC_BODY_CHUNK_BYTES: usize = 16 * 1024;

pub struct SemanticRequestBody {
    inner: Body,
    semantic: BoundedRequestBody,
    terminal: bool,
}

impl SemanticRequestBody {
    pub(crate) fn new(inner: Body, mut semantic: BoundedRequestBody) -> Self {
        let terminal = inner.is_end_stream();

        if terminal {
            let _ = semantic.finish();
        }

        Self {
            inner,
            semantic,
            terminal,
        }
    }

    const fn finish(&mut self) {
        if !self.terminal {
            let _ = self.semantic.terminate();
            self.terminal = true;
        }
    }
}

impl StreamingBody for SemanticRequestBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,

            Poll::Ready(None) => {
                self.finish();
                Poll::Ready(None)
            }

            Poll::Ready(Some(Err(error))) => {
                self.finish();
                Poll::Ready(Some(Err(error)))
            }

            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    for chunk in data.chunks(SEMANTIC_BODY_CHUNK_BYTES) {
                        if let Err(error) = self.semantic.push_chunk(chunk) {
                            self.finish();
                            return Poll::Ready(Some(Err(Box::new(error))));
                        }
                    }
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        if let Err(error) = semantic_headers_from_map(&trailers) {
                            self.finish();
                            return Poll::Ready(Some(Err(error)));
                        }

                        if let Err(error) = self.semantic.set_trailers() {
                            self.finish();
                            return Poll::Ready(Some(Err(Box::new(error))));
                        }

                        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                    } else {
                        let error = BoxError::from_static_str("HTTP body frame has unknown type");
                        self.finish();
                        Poll::Ready(Some(Err(error)))
                    }
                }
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> rama_http::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for SemanticRequestBody {
    fn drop(&mut self) {
        self.finish();
    }
}

struct SemanticResponseBody {
    inner: Body,
    sequence: ResponseSequence,
    terminal: bool,
}

impl SemanticResponseBody {
    fn new(inner: Body, head: ResponseHead) -> Result<Self, BoxError> {
        let terminal = inner.is_end_stream();
        let mut sequence = ResponseSequence::new();
        sequence.push(ResponseEvent::Final(head))?;

        if terminal {
            sequence.push(ResponseEvent::Complete)?;
        }

        Ok(Self {
            inner,
            sequence,
            terminal,
        })
    }

    fn finish(&mut self, event: ResponseEvent) {
        if !self.terminal {
            let _ = self.sequence.push(event);
            self.terminal = true;
        }
    }
}

impl StreamingBody for SemanticResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,

            Poll::Ready(None) => {
                self.finish(ResponseEvent::Complete);
                Poll::Ready(None)
            }

            Poll::Ready(Some(Err(error))) => {
                self.finish(ResponseEvent::Error(TerminalError::Transport(
                    error.to_string().into_boxed_str(),
                )));
                Poll::Ready(Some(Err(error)))
            }

            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    if let Err(error) = self.sequence.push(ResponseEvent::BodyChunk(data.to_vec()))
                    {
                        self.finish(ResponseEvent::Error(TerminalError::ProtocolViolation(
                            error.to_string().into_boxed_str(),
                        )));
                        return Poll::Ready(Some(Err(Box::new(error))));
                    }

                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        let semantic = match semantic_headers_from_map(&trailers) {
                            Ok(semantic) => semantic,
                            Err(error) => {
                                self.finish(ResponseEvent::Error(
                                    TerminalError::ProtocolViolation(
                                        error.to_string().into_boxed_str(),
                                    ),
                                ));
                                return Poll::Ready(Some(Err(error)));
                            }
                        };

                        if let Err(error) = self.sequence.push(ResponseEvent::Trailers(semantic)) {
                            self.finish(ResponseEvent::Error(TerminalError::ProtocolViolation(
                                error.to_string().into_boxed_str(),
                            )));
                            return Poll::Ready(Some(Err(Box::new(error))));
                        }

                        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                    } else {
                        let error = BoxError::from_static_str("HTTP body frame has unknown type");
                        self.finish(ResponseEvent::Error(TerminalError::ProtocolViolation(
                            error.to_string().into_boxed_str(),
                        )));
                        Poll::Ready(Some(Err(error)))
                    }
                }
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> rama_http::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for SemanticResponseBody {
    fn drop(&mut self) {
        self.finish(ResponseEvent::Cancelled);
    }
}

fn semantic_headers_from_map(headers: &HeaderMap) -> Result<SemanticHeaders, BoxError> {
    let mut semantic = SemanticHeaders::new();

    for (name, value) in headers {
        semantic.try_push(name.as_str(), value.as_bytes())?;
    }

    Ok(semantic)
}

fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect()
}

fn semantic_response_headers(headers: &HeaderMap) -> Result<SemanticHeaders, BoxError> {
    let connection_tokens = connection_tokens(headers);
    let mut semantic = SemanticHeaders::new();

    for (name, value) in headers {
        if is_hop_by_hop_header(name.as_str(), &connection_tokens) {
            continue;
        }

        semantic.try_push(name.as_str(), value.as_bytes())?;
    }

    Ok(semantic)
}

pub fn bridge_response_body(mut response: Response) -> Result<Response, BoxError> {
    if response.status().as_u16() < 200 || is_websocket_upgrade_response(&response) {
        return Ok(response);
    }

    let headers = semantic_response_headers(response.headers())?;
    let head = ResponseHead::final_head(response.status().as_u16(), headers)?;
    let body = std::mem::replace(response.body_mut(), Body::empty());
    *response.body_mut() = Body::new(SemanticResponseBody::new(body, head)?);
    Ok(response)
}

pub fn semantic_http_version(version: Version) -> Result<SemanticHttpVersion, BoxError> {
    match version {
        Version::HTTP_10 => Ok(SemanticHttpVersion::Http10),
        Version::HTTP_11 => Ok(SemanticHttpVersion::Http11),
        Version::HTTP_2 => Ok(SemanticHttpVersion::Http2),
        Version::HTTP_3 => Ok(SemanticHttpVersion::Http3),
        Version::HTTP_09 => Err(BoxError::from_static_str("HTTP/0.9 is not supported")),
    }
}

#[cfg(test)]
mod tests {
    use rama_http::{
        Body, HeaderMap, HeaderValue, Request, Response, StatusCode, body::util::BodyExt,
    };

    use super::{SemanticRequestBody, bridge_response_body, semantic_response_headers};
    use crate::semantic::{BoundedRequestBody, semantic_request_headers};

    #[test]
    fn semantic_headers_preserve_opaque_values() {
        let mut request = Request::builder()
            .uri("http://localhost/")
            .body(Body::empty())
            .expect("request");

        request.headers_mut().insert(
            "x-opaque",
            HeaderValue::from_bytes(&[0x80, b'a']).expect("opaque header"),
        );

        let headers = semantic_request_headers(&http::HeaderMap::from_iter(
            request.headers().iter().map(|(name, value)| {
                (
                    http::HeaderName::from_bytes(name.as_str().as_bytes())
                        .expect("rama header names are valid"),
                    http::HeaderValue::from_bytes(value.as_bytes())
                        .expect("rama header values are valid"),
                )
            }),
        ))
        .expect("semantic headers");

        assert_eq!(headers.as_slice()[0].1.as_bytes(), &[0x80, b'a']);
    }

    #[test]
    fn semantic_headers_filter_hop_by_hop_fields_and_connection_tokens() {
        let request = Request::builder()
            .header("connection", "x-remove")
            .header("x-remove", "one")
            .header("keep-alive", "timeout=5")
            .header("x-end-to-end", "yes")
            .body(Body::empty())
            .expect("request");

        let headers = semantic_request_headers(&http::HeaderMap::from_iter(
            request.headers().iter().map(|(name, value)| {
                (
                    http::HeaderName::from_bytes(name.as_str().as_bytes())
                        .expect("rama header names are valid"),
                    http::HeaderValue::from_bytes(value.as_bytes())
                        .expect("rama header values are valid"),
                )
            }),
        ))
        .expect("semantic headers");

        assert!(headers.as_slice().iter().all(|header| {
            !["connection", "x-remove", "keep-alive"].contains(&header.0.as_str())
        }));

        assert!(
            headers
                .as_slice()
                .iter()
                .any(|header| header.0.as_str() == "x-end-to-end")
        );
    }

    #[test]
    fn filters_hop_by_hop_response_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("x-private"));
        headers.insert("x-private", HeaderValue::from_static("hidden"));
        headers.insert("keep-alive", HeaderValue::from_static("hidden"));
        headers.insert("x-visible", HeaderValue::from_static("visible"));
        let semantic = semantic_response_headers(&headers).expect("response headers");

        assert!(semantic.as_slice().iter().any(|header| {
            header.0.as_str() == "x-visible" && header.1.as_bytes() == b"visible"
        }));

        assert!(
            !semantic
                .as_slice()
                .iter()
                .any(|header| header.0.as_str() == "x-private")
        );
    }

    #[tokio::test]
    async fn empty_semantic_body_finishes_without_frames() {
        let mut body = Body::new(SemanticRequestBody::new(
            Body::empty(),
            BoundedRequestBody::empty(),
        ));

        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn semantic_body_bridges_data_and_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-request-trailer", HeaderValue::from_static("present"));
        let source = Body::from("request-body").with_trailer_headers(trailers);

        let mut body = Body::new(SemanticRequestBody::new(
            source,
            BoundedRequestBody::empty(),
        ));

        let data = body
            .frame()
            .await
            .expect("data frame")
            .expect("data frame result")
            .into_data()
            .expect("data");

        assert_eq!(data, "request-body");

        let trailers = body
            .frame()
            .await
            .expect("trailer frame")
            .expect("trailer frame result")
            .into_trailers()
            .expect("trailers");

        assert_eq!(
            trailers
                .get("x-request-trailer")
                .expect("request trailer")
                .to_str()
                .expect("trailer value"),
            "present"
        );

        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn semantic_response_bridge_preserves_data_and_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-response-trailer", HeaderValue::from_static("present"));

        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("response-body").with_trailer_headers(trailers))
            .expect("response");

        let mut response = bridge_response_body(response).expect("bridge response");

        let data = response
            .body_mut()
            .frame()
            .await
            .expect("data frame")
            .expect("data frame result")
            .into_data()
            .expect("data");

        assert_eq!(data, "response-body");

        let trailers = response
            .body_mut()
            .frame()
            .await
            .expect("trailer frame")
            .expect("trailer frame result")
            .into_trailers()
            .expect("trailers");

        assert_eq!(
            trailers
                .get("x-response-trailer")
                .expect("response trailer")
                .to_str()
                .expect("trailer value"),
            "present"
        );

        assert!(response.body_mut().frame().await.is_none());
    }

    mod authority {
        use rama_core::error::BoxError;

        use super::super::resolve_request_authority;

        fn resolved(
            header: Option<&str>,
            uri: Option<&str>,
            tls: Option<&str>,
            ip_fallback: Option<&str>,
        ) -> Result<String, BoxError> {
            resolve_request_authority(
                header.map(str::to_owned),
                uri.map(str::to_owned),
                tls.map(str::to_owned),
                ip_fallback.map(str::to_owned),
                8443,
            )
        }

        #[test]
        fn earlier_candidates_win_when_candidates_agree() -> Result<(), BoxError> {
            assert_eq!(
                resolved(
                    Some("a.test:8080"),
                    Some("a.test:8080"),
                    Some("a.test:8080"),
                    None
                )?,
                "a.test:8080"
            );
            assert_eq!(
                resolved(None, Some("a.test:8080"), Some("a.test:8080"), None)?,
                "a.test:8080"
            );
            assert_eq!(
                resolved(None, None, Some("a.test:8080"), None)?,
                "a.test:8080"
            );
            Ok(())
        }

        #[test]
        fn conflicting_candidates_are_rejected() {
            assert!(resolved(Some("a.test:80"), Some("b.test:80"), None, None).is_err());
            assert!(resolved(Some("a.test:80"), None, Some("b.test"), None).is_err());
        }

        #[test]
        fn http_1_0_falls_back_to_the_original_destination() -> Result<(), BoxError> {
            assert_eq!(
                resolved(None, None, None, Some("93.184.216.34:443"))?,
                "93.184.216.34:443"
            );
            assert!(resolved(None, None, None, None).is_err());
            Ok(())
        }

        #[test]
        fn portless_authorities_take_the_fallback_port() -> Result<(), BoxError> {
            assert_eq!(resolved(Some("a.test"), None, None, None)?, "a.test:8443");
            Ok(())
        }
    }
}

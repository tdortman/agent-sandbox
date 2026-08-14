use agent_sandbox_core::{EchRewrite, rewrite_ech_config};
use rama_core::error::{BoxError, BoxErrorExt};
use rama_http::{Body, HeaderValue, Request, Response, body::util::BodyExt};

use crate::tcp_backend::PolicyDenied;

pub fn is_doh_request(request: &Request) -> bool {
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/dns-message"))
        });

    let dns_query = request.uri().query().is_some_and(|query| {
        query
            .to_string()
            .split('&')
            .any(|part| part.starts_with("dns="))
    });

    (request.method().as_str().eq_ignore_ascii_case("POST") && content_type)
        || (request.method().as_str().eq_ignore_ascii_case("GET") && dns_query)
}

fn is_doh_response(response: &Response) -> bool {
    response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/dns-message"))
        })
}

/// Rewrite a successful `DoH` DNS response before returning it to the client.
///
/// Only `application/dns-message` responses are inspected. Unsupported content
/// encodings and DNSSEC-protected ECH answers fail closed.
pub async fn rewrite_doh_response(
    mut response: Response,
    ech_config_list: Option<&[u8]>,
) -> Result<Response, BoxError> {
    let Some(replacement) = ech_config_list else {
        return Ok(response);
    };

    if !is_doh_response(&response) {
        return Err(Box::new(PolicyDenied));
    }

    if response
        .headers()
        .get("content-encoding")
        .is_some_and(|value| value != "identity")
    {
        return Err(BoxError::from_static_str(
            "cannot inspect encoded DoH response",
        ));
    }

    let body = std::mem::replace(response.body_mut(), Body::empty());
    let body = body.limited(65_535).collect().await?.to_bytes();

    let body = match rewrite_ech_config(&body, replacement)? {
        EchRewrite::Rewritten(body) => body,
        EchRewrite::Unchanged => body.to_vec(),
        EchRewrite::DnssecProtected => {
            return Err(Box::new(PolicyDenied));
        }
    };

    response.headers_mut().remove("transfer-encoding");

    response.headers_mut().insert(
        "content-length",
        HeaderValue::from_str(&body.len().to_string())?,
    );

    *response.body_mut() = Body::from(body);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use rama_http::{Body, Request};

    use super::is_doh_request;

    #[test]
    fn detects_doh_post_and_get_requests() {
        let post = Request::builder()
            .method("POST")
            .header("content-type", "application/dns-message")
            .body(Body::empty())
            .expect("test request");

        assert!(is_doh_request(&post));

        let get = Request::builder()
            .method("GET")
            .uri("/dns-query?dns=abc")
            .body(Body::empty())
            .expect("test request");

        assert!(is_doh_request(&get));
    }
}

pub mod cert;
pub mod policy;
pub mod semantic;
use rama_http::{HeaderName, Response};

pub const ALT_SVC: HeaderName = HeaderName::from_static("alt-svc");

pub fn strip_alt_svc<B>(response: &mut Response<B>) {
    response.headers_mut().remove(ALT_SVC);
}

#[cfg(test)]
mod tests {
    use super::strip_alt_svc;
    use rama_http::{HeaderName, HeaderValue, Response};

    #[test]
    fn strips_alt_svc_from_responses() -> Result<(), Box<dyn std::error::Error>> {
        let mut response = Response::builder()
            .header(
                HeaderName::from_static("alt-svc"),
                HeaderValue::from_static("h3=\":443\""),
            )
            .body(())?;

        strip_alt_svc(&mut response);
        assert!(!response.headers().contains_key("alt-svc"));
        Ok(())
    }
}

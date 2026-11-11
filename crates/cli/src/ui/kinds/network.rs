use std::sync::Arc;

use agent_sandbox_core::{
    ApprovalTarget, FlowProtocol, host_pattern_matches, is_ip_literal, normalize_dns_name,
    scheme_for, split_check_aliases,
};

use crate::ui::{
    options::{ApprovalFormPresentation, ApprovalFormResult},
    prompt::{
        Fallback, FallbackTarget, Origin, Prompt, TextTarget, TextTitle, comment_field, prompt_tag,
        review_form, text_field,
    },
};

/// The fields of a network push that shape its prompt.
pub struct NetworkRequest {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub scheme: Option<String>,
    pub url: Option<String>,
}

pub fn prompt(session_id: Option<&str>, origin: Origin, request: NetworkRequest) -> Prompt {
    let host = request.host.unwrap_or_default();
    let port = request.port.unwrap_or(0);
    let transport = request.scheme.unwrap_or_else(|| "https".into());
    let scheme = network_prompt_scheme(&transport, port);
    let aliased = split_check_aliases(request.url);

    let url = network_prompt_with_transport_hint(
        network_prompt_with_aliases(
            &host,
            port,
            scheme,
            aliased.url,
            (!aliased.aliases.is_empty()).then_some(aliased.aliases),
        ),
        &transport,
        port,
    );

    let url = url.split(['?', '#']).next().unwrap_or_default().to_owned();
    let tag = prompt_tag(origin.package.as_deref());

    let review = review_form(&origin, session_id, network_presentation(&url), vec![
        text_field("target", "Host rule", host.clone()),
        comment_field(),
    ]);

    let fallback = Fallback {
        action_title: format!("{tag}: {url}"),
        scope_phrase: url.clone(),
        target: FallbackTarget::Text(TextTarget {
            title: TextTitle::ForAction {
                tag,
                noun: format!("{url} target"),
            },
            default: host.clone(),
            parse: Arc::new(|host| {
                Some(ApprovalTarget::NetworkHost {
                    host: host.to_owned(),
                })
            }),
        }),
    };

    Prompt {
        origin,
        review,
        parse_target: Arc::new(move |result| parse_network_target(result, &host)),
        fallback,
    }
}

fn network_presentation(url: &str) -> ApprovalFormPresentation {
    ApprovalFormPresentation {
        heading: "Allow this network connection?".into(),
        subject: url.into(),
    }
}

fn valid_network_host(value: &str) -> Option<String> {
    let value = value.trim();

    if is_ip_literal(value) {
        return Some(value.to_owned());
    }

    normalize_dns_name(value).ok()
}

/// Parse and validate an editable network host against the request.
fn parse_network_target(
    result: &ApprovalFormResult,
    requested_host: &str,
) -> Option<ApprovalTarget> {
    let host = valid_network_host(result.values.get("target")?)?;

    if !host_pattern_matches(&host, requested_host) {
        return None;
    }

    Some(ApprovalTarget::NetworkHost { host })
}

fn network_prompt_scheme(transport: &str, port: u16) -> &str {
    // A bare "udp" transport is never claimed to be QUIC: proxied QUIC
    // never prompts at the transport layer, so a UDP prompt is always a
    // direct flow. Only an explicit "http3" transport keeps the https
    // rendering with its QUIC hint.
    if transport == "udp" {
        return "udp";
    }

    let protocol = match transport {
        "tcp" => FlowProtocol::Tcp,
        "http3" => FlowProtocol::Udp,
        // "http"/"https" inputs are already schemes, not transport hints.
        _ => return transport,
    };

    match scheme_for(protocol, port) {
        // The wire classification for UDP 443 is "http3"; display URLs
        // render it as https with a QUIC hint.
        "http3" => "https",

        scheme => scheme,
    }
}

fn network_prompt_with_transport_hint(base: String, transport: &str, port: u16) -> String {
    if transport == "http3" && port == 443 {
        format!("{base} (HTTP/3 over QUIC)")
    } else {
        base
    }
}

fn network_prompt_url(host: &str, port: u16, scheme: &str, fallback_url: Option<String>) -> String {
    if host.trim().is_empty() {
        fallback_url.unwrap_or_else(|| format!("{scheme}://{host}:{port}"))
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

fn network_prompt_with_aliases(
    host: &str,
    port: u16,
    scheme: &str,
    fallback_url: Option<String>,
    aliases: Option<Vec<String>>, // parsed from URL fragment when present
) -> String {
    let base = network_prompt_url(host, port, scheme, fallback_url);

    if !is_ip_literal(host) {
        return base;
    }

    let Some(aliases) = aliases else {
        return base;
    };

    let hints: Vec<&str> = aliases
        .iter()
        .map(String::as_str)
        .filter(|alias| !alias.is_empty() && !is_ip_literal(alias))
        .collect();

    if hints.is_empty() {
        return base;
    }

    format!("{base} (previously seen as: {})", hints.join(", "))
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::{ApprovalTarget, attach_check_aliases};

    use super::{
        NetworkRequest, network_presentation, network_prompt_scheme, network_prompt_url,
        network_prompt_with_aliases, network_prompt_with_transport_hint, parse_network_target,
        prompt, valid_network_host,
    };
    use crate::ui::{
        kinds::test_support::{form_result, origin},
        prompt::FallbackTarget,
    };

    #[test]
    fn network_presentation_uses_connection_copy_and_destination() {
        let presentation = network_presentation("https://example.com:443");
        assert_eq!(presentation.heading, "Allow this network connection?");
        assert_eq!(presentation.subject, "https://example.com:443");
    }

    #[test]
    fn network_prompt_scheme_does_not_infer_protocol_from_tcp_ports() {
        // Ports do not identify protocols: TCP prompts render as tcp://
        // until the proxy decodes the stream and prompts per request.
        for port in [80, 443, 8008, 8080, 8443, 853, 9443] {
            assert_eq!(network_prompt_scheme("tcp", port), "tcp");
        }

        // A bare UDP transport is never claimed to be QUIC either.
        assert_eq!(network_prompt_scheme("udp", 443), "udp");
        assert_eq!(network_prompt_scheme("udp", 853), "udp");
    }

    #[test]
    fn network_prompt_marks_udp_443_as_http3_without_inventing_uri_scheme() {
        let base = network_prompt_url(
            "example.com",
            443,
            network_prompt_scheme("http3", 443),
            None,
        );

        assert_eq!(
            network_prompt_with_transport_hint(base, "http3", 443),
            "https://example.com:443 (HTTP/3 over QUIC)"
        );
    }

    #[test]
    fn network_prompt_url_prefers_policy_host_over_raw_ip_url() {
        let url = network_prompt_url(
            "example.com",
            443,
            "tcp",
            Some("tcp://104.18.32.47:443".to_string()),
        );

        assert_eq!(url, "tcp://example.com:443");
    }

    #[test]
    fn network_prompt_url_falls_back_when_host_missing() {
        let url = network_prompt_url("", 443, "tcp", Some("tcp://104.18.32.47:443".to_string()));
        assert_eq!(url, "tcp://104.18.32.47:443");
    }

    #[test]
    fn network_prompt_with_aliases_appends_hint_for_ip_literal() {
        let url = network_prompt_with_aliases(
            "104.18.32.47",
            443,
            "tcp",
            Some("tcp://104.18.32.47:443".to_string()),
            Some(vec!["chatgpt.com".to_string()]),
        );

        assert_eq!(
            url,
            "tcp://104.18.32.47:443 (previously seen as: chatgpt.com)"
        );
    }

    #[test]
    fn network_prompt_with_aliases_skips_hint_for_hostname() {
        let url = network_prompt_with_aliases(
            "chatgpt.com",
            443,
            "tcp",
            None,
            Some(vec!["example.com".to_string()]),
        );

        assert_eq!(url, "tcp://chatgpt.com:443");
    }

    #[test]
    fn network_prompt_with_aliases_joins_multiple_hints() {
        let url = network_prompt_with_aliases(
            "104.18.32.47",
            443,
            "tcp",
            None,
            Some(vec![
                "chatgpt.com".to_string(),
                "www.chatgpt.com".to_string(),
            ]),
        );

        assert_eq!(
            url,
            "tcp://104.18.32.47:443 (previously seen as: chatgpt.com, www.chatgpt.com)"
        );
    }

    #[test]
    fn host_text_is_normalised_and_revalidated() {
        assert_eq!(
            valid_network_host(" Example.COM. "),
            Some("example.com".into())
        );

        assert_eq!(
            valid_network_host("104.18.32.47"),
            Some("104.18.32.47".into())
        );

        assert!(valid_network_host("bad host").is_none());
    }

    #[test]
    fn network_target_matches_requested_host() {
        assert_eq!(
            parse_network_target(&form_result("example.com"), "example.com"),
            Some(ApprovalTarget::NetworkHost {
                host: "example.com".into(),
            })
        );
    }

    #[test]
    fn network_target_wildcard_matches_requested_host() {
        let result = form_result("*.example.com");
        assert!(parse_network_target(&result, "api.example.com").is_some());
    }

    #[test]
    fn network_target_rejects_nonmatching_host() {
        let result = form_result("other.com");
        assert!(parse_network_target(&result, "example.com").is_none());
    }

    #[test]
    fn prompt_describes_the_flow_and_strips_url_decorations() {
        let url = attach_check_aliases(Some("tcp://104.18.32.47:443".into()), &[
            "chatgpt.com".to_string()
        ]);

        let prompt = prompt(Some("session"), origin(Some("omp")), NetworkRequest {
            host: Some("104.18.32.47".into()),
            port: Some(443),
            scheme: Some("tcp".into()),
            url,
        });

        let presentation = prompt.review.presentation.as_ref().expect("presentation");

        assert_eq!(
            presentation.subject,
            "tcp://104.18.32.47:443 (previously seen as: chatgpt.com)"
        );

        assert_eq!(prompt.review.summary, "agent-sandbox (omp)");
        assert_eq!(
            prompt.fallback.action_title,
            format!("agent-sandbox (omp): {}", presentation.subject)
        );
        assert!(matches!(prompt.fallback.target, FallbackTarget::Text(_)));
    }

    #[test]
    fn prompt_parses_only_targets_covering_the_requested_host() {
        let prompt = prompt(None, origin(None), NetworkRequest {
            host: Some("api.example.com".into()),
            port: Some(443),
            scheme: None,
            url: None,
        });

        assert!((prompt.parse_target)(&form_result("*.example.com")).is_some());
        assert!((prompt.parse_target)(&form_result("other.com")).is_none());
    }
}

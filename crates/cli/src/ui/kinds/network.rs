use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use agent_sandbox_core::{
    ApprovalTarget, FlowProtocol, host_pattern_matches,
    hosts::{is_displayable_hostname, sanitize_aliases},
    is_ip_literal, normalize_dns_name, scheme_for, split_check_aliases,
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

    // Names come from DNS answers a sandbox controls: only plain hostnames
    // are rendered, so none can reshape the prompt text or hide what follows
    // it. A host that is neither a hostname nor an IP literal is not shown;
    // the destination address is.
    let aliases = sanitize_aliases(aliased.aliases);
    let shown_host = if is_ip_literal(&host) || is_displayable_hostname(&host) {
        host.as_str()
    } else {
        ""
    };

    let url = network_prompt_with_transport_hint(
        network_prompt_with_aliases(shown_host, port, scheme, aliased.url, &aliases),
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
    ApprovalFormPresentation::new("Allow this network connection?", url)
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

/// The destination IP a prompt URL names, when its authority is an IP
/// socket address.
fn url_destination_ip(url: &str) -> Option<IpAddr> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    authority.parse::<SocketAddr>().ok().map(|addr| addr.ip())
}

/// Render the destination for a raw transport flow.
///
/// A raw flow carries no hostname of its own: the host comes from the DNS
/// cache and is a guess when several names share the IP. The prompt names
/// the destination IP and the other names mapped to it so the user can judge.
fn network_prompt_with_aliases(
    host: &str,
    port: u16,
    scheme: &str,
    fallback_url: Option<String>,
    aliases: &[String],
) -> String {
    let destination_ip = fallback_url.as_deref().and_then(url_destination_ip);
    let base = network_prompt_url(host, port, scheme, fallback_url);

    let names: Vec<&str> = aliases
        .iter()
        .map(String::as_str)
        .filter(|alias| !alias.is_empty() && !is_ip_literal(alias) && *alias != host)
        .collect();

    let others = if names.is_empty() {
        String::new()
    } else {
        format!("other names for this IP: {}", names.join(", "))
    };

    if host.is_empty() || is_ip_literal(host) {
        return if names.is_empty() {
            base
        } else {
            format!(
                "{base} (other names seen for this IP: {})",
                names.join(", ")
            )
        };
    }

    let Some(ip) = destination_ip else {
        return base;
    };

    if others.is_empty() {
        format!("{base} (name guessed from DNS; destination IP {ip})")
    } else {
        format!("{base} (name guessed from DNS; destination IP {ip}; {others})")
    }
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
            &["chatgpt.com".to_string()],
        );

        assert_eq!(
            url,
            "tcp://104.18.32.47:443 (other names seen for this IP: chatgpt.com)"
        );
    }

    #[test]
    fn network_prompt_with_aliases_skips_hint_for_hostname() {
        let url = network_prompt_with_aliases("chatgpt.com", 443, "tcp", None, &[
            "example.com".to_string()
        ]);

        assert_eq!(url, "tcp://chatgpt.com:443");
    }

    #[test]
    fn network_prompt_with_aliases_joins_multiple_hints() {
        let url = network_prompt_with_aliases("104.18.32.47", 443, "tcp", None, &[
            "chatgpt.com".to_string(),
            "www.chatgpt.com".to_string(),
        ]);

        assert_eq!(
            url,
            "tcp://104.18.32.47:443 (other names seen for this IP: chatgpt.com, www.chatgpt.com)"
        );
    }

    #[test]
    fn network_prompt_shows_destination_ip_and_other_names_for_a_guessed_host() {
        let url = network_prompt_with_aliases(
            "b.example",
            443,
            "tcp",
            Some("tcp://93.184.216.34:443".to_string()),
            &["a.example".to_string(), "c.example".to_string()],
        );

        assert_eq!(
            url,
            "tcp://b.example:443 (name guessed from DNS; destination IP 93.184.216.34; other \
             names for this IP: a.example, c.example)"
        );
    }

    #[test]
    fn network_prompt_shows_destination_ip_for_a_guessed_ipv6_host() {
        let url = network_prompt_with_aliases(
            "b.example",
            443,
            "udp",
            Some("udp://[2001:db8::1]:443".to_string()),
            &[],
        );

        assert_eq!(
            url,
            "udp://b.example:443 (name guessed from DNS; destination IP 2001:db8::1)"
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
            "tcp://104.18.32.47:443 (other names seen for this IP: chatgpt.com)"
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

    #[test]
    fn prompt_renders_only_plain_hostnames_from_dns() {
        let hostile = [
            "good.example?.evil.example".to_string(),
            "a#b.example".to_string(),
            "two words.example".to_string(),
            "newline\n.example".to_string(),
            "user@good.example".to_string(),
            "10.0.0.9".to_string(),
            "benign.example".to_string(),
        ];

        let url = attach_check_aliases(Some("tcp://93.184.216.34:443".into()), &hostile);

        let prompt = prompt(None, origin(None), NetworkRequest {
            host: Some("b.example".into()),
            port: Some(443),
            scheme: Some("tcp".into()),
            url,
        });

        let subject = &prompt
            .review
            .presentation
            .as_ref()
            .expect("presentation")
            .subject;

        assert_eq!(
            subject,
            "tcp://b.example:443 (name guessed from DNS; destination IP 93.184.216.34; other \
             names for this IP: benign.example)"
        );
    }

    #[test]
    fn prompt_bounds_the_number_of_names_shown() {
        let many: Vec<String> = (0..50).map(|index| format!("n{index}.example")).collect();
        let url = attach_check_aliases(Some("tcp://93.184.216.34:443".into()), &many);

        let prompt = prompt(None, origin(None), NetworkRequest {
            host: Some("b.example".into()),
            port: Some(443),
            scheme: Some("tcp".into()),
            url,
        });

        let subject = &prompt
            .review
            .presentation
            .as_ref()
            .expect("presentation")
            .subject;
        assert_eq!(subject.matches(".example").count(), 9, "{subject}");
    }

    #[test]
    fn prompt_hides_a_host_that_is_not_a_hostname_and_shows_the_address() {
        let prompt = prompt(None, origin(None), NetworkRequest {
            host: Some("github.com?.evil.example".into()),
            port: Some(443),
            scheme: Some("tcp".into()),
            url: Some("tcp://93.184.216.34:443".into()),
        });

        let subject = &prompt
            .review
            .presentation
            .as_ref()
            .expect("presentation")
            .subject;
        assert_eq!(subject, "tcp://93.184.216.34:443");
    }
}

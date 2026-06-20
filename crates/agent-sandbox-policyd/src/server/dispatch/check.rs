//! Network `Check` RPC handling.

use std::sync::Arc;

use agent_sandbox_core::{
    CheckReply, RequestContext, RpcReply, is_ip_literal, normalize_host, policy_host_for_connect,
};

use crate::error::PolicydError;
use crate::store::PolicyStore;
use crate::wire::{MergeContext, NetworkCheckRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptHost {
    AsProvided,
    ResolvedFromIp,
}
fn format_host_for_url(host: &str) -> String {
    // IPv6 literals need brackets in URI authority.
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn prompt_url(
    scheme: &str,
    provided_url: Option<String>,
    policy_host: &str,
    port: u16,
    prompt_host: PromptHost,
) -> String {
    match prompt_host {
        PromptHost::AsProvided => {
            provided_url.unwrap_or_else(|| format!("{scheme}://{policy_host}:{port}"))
        }
        PromptHost::ResolvedFromIp => {
            let host = format_host_for_url(policy_host);
            format!("{scheme}://{host}:{port}")
        }
    }
}

pub(crate) async fn handle_check(
    store: &Arc<PolicyStore>,
    host: Option<String>,
    connect_host: Option<String>,
    port: Option<u16>,
    scheme: String,
    url: Option<String>,
    ctx: RequestContext,
) -> Result<RpcReply, PolicydError> {
    let connect_host = connect_host.or_else(|| host.clone()).unwrap_or_default();
    let port = port.unwrap_or(0);
    let mut policy_host = normalize_host(host.as_deref().unwrap_or(""));
    let prompt_host = if policy_host.is_empty() || is_ip_literal(&policy_host) {
        let resolution = policy_host_for_connect(&connect_host, None);
        policy_host = resolution.policy_host;
        PromptHost::ResolvedFromIp
    } else {
        PromptHost::AsProvided
    };
    let url = prompt_url(&scheme, url, &policy_host, port, prompt_host);
    let merge = MergeContext::from(&ctx);
    if let Some(source) = store.allow_source(&policy_host, port, merge.clone()).await {
        if source == "deny" {
            tracing::info!(%policy_host, port, "check deny (project policy)");
            return Ok(RpcReply::Check(CheckReply::denied("deny")));
        }
        if source == "once" {
            let allowed = store.is_allowed(&policy_host, port, merge, true).await;
            if allowed {
                tracing::info!(%policy_host, port, %source, "check allow");
            } else {
                tracing::info!(%policy_host, port, %source, "check deny (once grant consumed)");
            }
            return Ok(RpcReply::Check(if allowed {
                CheckReply::allowed(source)
            } else {
                CheckReply::denied(source)
            }));
        }
        tracing::info!(%policy_host, port, %source, "check allow");
        return Ok(RpcReply::Check(CheckReply::allowed(source)));
    }
    Ok(RpcReply::Check(
        store
            .request_network_approval(NetworkCheckRequest {
                host: policy_host,
                port,
                scheme,
                url,
                ctx: merge,
            })
            .await,
    ))
}

#[cfg(test)]
mod tests {
    use super::{PromptHost, prompt_url};

    #[test]
    fn prompt_url_uses_resolved_hostname_for_ip_backed_checks() {
        let url = prompt_url(
            "tcp",
            Some("tcp://104.18.32.47:443".to_string()),
            "example.com",
            443,
            PromptHost::ResolvedFromIp,
        );
        assert_eq!(url, "tcp://example.com:443");
    }

    #[test]
    fn prompt_url_keeps_provided_url_for_named_hosts() {
        let url = prompt_url(
            "https",
            Some("https://example.com/docs".to_string()),
            "example.com",
            443,
            PromptHost::AsProvided,
        );
        assert_eq!(url, "https://example.com/docs");
    }

    #[test]
    fn prompt_url_brackets_ipv6_literal_when_resolved_from_ip() {
        let url = prompt_url("tcp", None, "::1", 443, PromptHost::ResolvedFromIp);
        assert_eq!(url, "tcp://[::1]:443");
    }

    #[test]
    fn prompt_url_does_not_bracket_ipv4_literal_when_resolved_from_ip() {
        let url = prompt_url("tcp", None, "10.0.0.9", 8080, PromptHost::ResolvedFromIp);
        assert_eq!(url, "tcp://10.0.0.9:8080");
    }

    #[test]
    fn prompt_url_uses_resolved_hostname_for_ipv6_when_resolved() {
        let url = prompt_url(
            "https",
            Some("https://[2001:db8::1]:443".to_string()),
            "ipv6.example.com",
            443,
            PromptHost::ResolvedFromIp,
        );
        assert_eq!(url, "https://ipv6.example.com:443");
    }
}

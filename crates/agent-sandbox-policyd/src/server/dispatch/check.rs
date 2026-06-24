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
    // Port 0 is 'unspecified' in TCP/UDP sockaddr. The broker already
    // drops it before sending an RPC, but NFQUEUE reads the destination
    // port straight from the IP packet header and has no such filter.
    // Rejecting here means a tool that targets port 0 (e.g. nmap, custom
    // probes) never produces a `tcp://host:0` prompt.
    if port == 0 {
        tracing::info!(%policy_host, "check deny (port 0)");
        return Ok(RpcReply::Check(CheckReply::denied("port-zero")));
    }
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
    use super::{PromptHost, handle_check, prompt_url};
    use crate::store::{PolicyStore, PolicydArgs};
    use agent_sandbox_core::{ProcessIds, RequestContext, RpcReply, SandboxPaths};
    use std::sync::Arc;
    use std::time::Duration;

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
    fn test_store() -> PolicyStore {
        PolicyStore::new(PolicydArgs {
            host_socket: "/tmp/test.sock".into(),
            sandbox_socket: "/tmp/test-sandbox.sock".into(),
            declarative: "/tmp/declarative.json".into(),
            export_json: "/tmp/export.json".into(),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        })
    }

    fn empty_context() -> RequestContext {
        RequestContext::from_paths_and_ids(
            &SandboxPaths::default(),
            ProcessIds::from_options(Some(0), Some(1000)),
        )
    }

    #[tokio::test]
    async fn handle_check_denies_port_zero_before_prompting() {
        let store = Arc::new(test_store());
        // Hostname path: the broker would never let this through (port-0
        // skip in `sockaddr_target`), but NFQUEUE forwards whatever the
        // packet header says. A `tcp://chatgpt.com:0` prompt must never
        // reach the user.
        let reply = handle_check(
            &store,
            Some("chatgpt.com".into()),
            Some("104.18.32.47".into()),
            Some(0),
            "tcp".into(),
            Some("tcp://chatgpt.com:0".into()),
            empty_context(),
        )
        .await
        .expect("handle_check returns Ok");
        match reply {
            RpcReply::Check(check) => {
                assert!(!check.allowed, "port 0 must be denied");
                assert_eq!(
                    check.source, "port-zero",
                    "port 0 source must be 'port-zero'"
                );
            }
            other => panic!("expected Check reply, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_check_denies_none_port_without_prompting() {
        let store = Arc::new(test_store());
        // Missing port in the RPC also collapses to 0 via `unwrap_or(0)`;
        // the same deny path applies.
        let reply = handle_check(
            &store,
            Some("chatgpt.com".into()),
            Some("104.18.32.47".into()),
            None,
            "tcp".into(),
            Some("tcp://chatgpt.com".into()),
            empty_context(),
        )
        .await
        .expect("handle_check returns Ok");
        match reply {
            RpcReply::Check(check) => {
                assert!(!check.allowed, "None port must be denied as 0");
            }
            other => panic!("expected Check reply, got {other:?}"),
        }
    }
}

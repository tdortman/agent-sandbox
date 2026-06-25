//! Network `Check` RPC handling.

use std::sync::Arc;

use agent_sandbox_core::{
    CheckReply, RequestContext, RpcReply, is_ip_literal, normalize_host, policy_host_for_connect,
};

use crate::error::PolicydError;
use crate::store::PolicyStore;
use crate::wire::{MergeContext, NetworkCheckRequest};

/// Inputs for `handle_check`, grouped to keep the call signature small.
pub(crate) struct CheckArgs {
    pub host: Option<String>,
    pub connect_host: Option<String>,
    pub port: Option<u16>,
    pub scheme: String,
    pub url: Option<String>,
    pub aliases: Vec<String>,
    pub ctx: RequestContext,
}

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
    args: CheckArgs,
) -> Result<RpcReply, PolicydError> {
    let CheckArgs {
        host,
        connect_host,
        port,
        scheme,
        url,
        aliases,
        ctx,
    } = args;
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
            .request_network_approval_with_aliases(
                NetworkCheckRequest {
                    host: policy_host,
                    port,
                    scheme,
                    url,
                    ctx: merge,
                },
                aliases,
            )
            .await,
    ))
}

#[cfg(test)]
mod tests {
    use super::{CheckArgs, PromptHost, handle_check, prompt_url};
    use crate::store::{PolicyStore, PolicydArgs};
    use agent_sandbox_core::{ProcessIds, RequestContext, RpcReply, SandboxPaths};
    use std::sync::Arc;
    use std::time::Duration;
    fn test_store() -> PolicyStore {
        PolicyStore::new(PolicydArgs {
            host_socket: std::path::PathBuf::from("/tmp/host.sock"),
            sandbox_socket: std::path::PathBuf::from("/tmp/sandbox.sock"),
            declarative: std::path::PathBuf::from("/tmp/policy.json"),
            export_json: std::path::PathBuf::from("/tmp/export.json"),
            export_nix: None,
            approval_timeout: Duration::from_secs(1),
            interactive_approval: false,
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

    fn check_args(host: &str, port: Option<u16>) -> CheckArgs {
        CheckArgs {
            host: Some(host.into()),
            connect_host: Some("104.18.32.47".into()),
            port,
            scheme: "tcp".into(),
            url: Some(format!("tcp://{host}:443")),
            aliases: Vec::new(),
            ctx: empty_context(),
        }
    }

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

    #[tokio::test]
    async fn handle_check_denies_port_zero_before_prompting() {
        let store = Arc::new(test_store());
        // Hostname path: the broker would never let this through (port-0
        // skip in `sockaddr_target`), but NFQUEUE forwards whatever the
        // packet header says. A `tcp://chatgpt.com:0` prompt must never
        // reach the user.
        let reply = handle_check(&store, check_args("chatgpt.com", Some(0)))
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
        let reply = handle_check(&store, check_args("chatgpt.com", None))
            .await
            .expect("handle_check returns Ok");
        match reply {
            RpcReply::Check(check) => {
                assert!(!check.allowed, "port None must be denied");
                assert_eq!(check.source, "port-zero");
            }
            other => panic!("expected Check reply, got {other:?}"),
        }
    }
}

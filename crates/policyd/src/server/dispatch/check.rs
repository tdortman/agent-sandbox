//! Network `Check` RPC handling.

use std::sync::Arc;

use agent_sandbox_core::{
    CheckReply, ResolvedRequestContext, RpcReply, Verdict, VerdictSource, is_ip_literal,
    normalize_host, policy_host_for_connect,
};

use crate::{error::PolicydError, store::PolicyStore, wire::NetworkCheckRequest};

/// Inputs for `handle_check`, grouped to keep the call signature small.
pub struct CheckArgs {
    pub host: Option<String>,
    pub connect_host: Option<String>,
    pub port: Option<u16>,
    pub scheme: String,
    pub url: Option<String>,
    pub aliases: Vec<String>,
    pub ctx: ResolvedRequestContext,
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

pub async fn handle_check(
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
        tracing::debug!(%policy_host, "check deny (port 0)");
        return Ok(RpcReply::Check(CheckReply::denied(VerdictSource::PortZero)));
    }
    let prompt_host = if policy_host.is_empty() || is_ip_literal(&policy_host) {
        let resolution = policy_host_for_connect(&connect_host, None);
        policy_host = resolution.policy_host;
        PromptHost::ResolvedFromIp
    } else {
        PromptHost::AsProvided
    };
    let url = prompt_url(&scheme, url, &policy_host, port, prompt_host);
    if let Some(verdict) = store.allow_verdict(&policy_host, port, &ctx).await {
        if verdict.is_once() {
            let verdict = store
                .network_verdict(&policy_host, port, &ctx, true)
                .await
                .unwrap_or_else(Verdict::blocked);
            if verdict.allowed {
                tracing::info!(%policy_host, port, source = %verdict.source, "check allow");
            } else {
                tracing::info!(%policy_host, port, source = %verdict.source, "check deny (once grant consumed)");
            }
            return Ok(RpcReply::Check(CheckReply::from_verdict(verdict)));
        }
        if verdict.is_policy_denied() {
            tracing::info!(%policy_host, port, "check deny (project policy)");
        } else {
            tracing::info!(%policy_host, port, source = %verdict.source, "check allow");
        }
        return Ok(RpcReply::Check(CheckReply::from_verdict(verdict)));
    }
    Ok(RpcReply::Check(
        store
            .request_network_approval_with_aliases(
                NetworkCheckRequest {
                    host: policy_host,
                    port,
                    scheme,
                    url,
                    ctx,
                },
                aliases,
            )
            .await,
    ))
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use agent_sandbox_core::{
        ApprovalScope, NetworkRuleKey, ProcessIds, ResolvedRequestContext, RpcReply, SandboxPaths,
        VerdictSource,
    };
    use uuid::Uuid;

    use super::{CheckArgs, PromptHost, handle_check, prompt_url};
    use crate::store::PolicyStore;

    fn test_store() -> PolicyStore {
        let base =
            std::env::temp_dir().join(format!("agent-sandbox-check-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&base).expect("create temp test dir");
        PolicyStore::new(crate::store::test_args(
            base.join("host.sock"),
            base.join("sandbox.sock"),
            base.join("policy.json"),
            base.join("export.json"),
            Duration::from_secs(1),
            false,
        ))
    }

    fn empty_context() -> ResolvedRequestContext {
        ResolvedRequestContext::new(
            SandboxPaths::default(),
            ProcessIds::from_options(Some(0), Some(1000)),
            None,
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

    fn isolated_check_args(base: &std::path::Path, host: &str, port: Option<u16>) -> CheckArgs {
        let home = base.join("home-user");
        let project_root = base.join("repo");
        std::fs::create_dir_all(&home).expect("create isolated home");
        std::fs::create_dir_all(&project_root).expect("create isolated project root");
        let ctx = ResolvedRequestContext::new(
            SandboxPaths::from_wire(Some(project_root.clone()), Some(home), Some(project_root)),
            ProcessIds::default(),
            None,
        );
        CheckArgs {
            host: Some(host.into()),
            connect_host: Some("104.18.32.47".into()),
            port,
            scheme: "tcp".into(),
            url: Some(format!("tcp://{host}:443")),
            aliases: Vec::new(),
            ctx,
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
        let reply = handle_check(&store, check_args("chatgpt.com", Some(0)))
            .await
            .expect("handle_check returns Ok");
        match reply {
            RpcReply::Check(check) => {
                assert!(!check.allowed, "port 0 must be denied");
                assert_eq!(
                    check.source,
                    VerdictSource::PortZero,
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
                assert_eq!(check.source, VerdictSource::PortZero);
            }
            other => panic!("expected Check reply, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_check_consumes_once_allow_exactly_once() {
        let store = Arc::new(test_store());
        let base = std::env::temp_dir().join(format!(
            "agent-sandbox-once-check-{}",
            Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&base).expect("create isolated test base");
        {
            let mut inner = store.inner.lock().await;
            inner
                .once_allow
                .insert(NetworkRuleKey::new("chatgpt.com", 443));
        }

        let first = handle_check(&store, isolated_check_args(&base, "chatgpt.com", Some(443)))
            .await
            .expect("first handle_check returns Ok");
        match first {
            RpcReply::Check(check) => {
                assert!(check.allowed, "first once approval must allow");
                assert_eq!(check.source, VerdictSource::Scope(ApprovalScope::Once));
            }
            other => panic!("expected Check reply, got {other:?}"),
        }
        assert!(
            store.inner.lock().await.once_allow.is_empty(),
            "once approval must be consumed after the first check"
        );

        let second = handle_check(&store, isolated_check_args(&base, "chatgpt.com", Some(443)))
            .await
            .expect("second handle_check returns Ok");
        match second {
            RpcReply::Check(check) => {
                assert!(
                    !check.allowed,
                    "second check must not reuse consumed once approval"
                );
                assert_eq!(check.source, VerdictSource::Blocked);
            }
            other => panic!("expected Check reply, got {other:?}"),
        }
    }
}

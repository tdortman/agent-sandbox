use agent_sandbox_core::HttpUrl;
#[cfg(debug_assertions)]
use agent_sandbox_proxy::tcp_backend::destination_override;
use agent_sandbox_proxy::{
    alt_svc::AltSvcStore,
    cert::CertificateIssuer,
    ech_state,
    http3::{self, Http3Config},
    policy::PolicySession,
    tcp_backend::{
        ListenConfig, MAX_ACTIVE_CHECKS, canonical_http10_origins, destination_for_stream,
        run_tcp_listener,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Parser;
use rama_core::{
    error::{BoxError, BoxErrorExt},
    rt::Executor,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{Notify, Semaphore};

/// Select the client-facing ECH configuration and verify explicit overrides.
///
/// An override is accepted only when it is byte-for-byte identical to the
/// persisted configuration whose private key the proxy will use.
fn select_ech_config_list(
    encoded: Option<&str>,
    state: Option<&ech_state::EchState>,
) -> Result<Option<Arc<Vec<u8>>>, BoxError> {
    let Some(encoded) = encoded else {
        return Ok(state.map(|state| Arc::new(state.config_list.clone())));
    };

    let config_list = STANDARD.decode(encoded)?;

    let Some(state) = state else {
        return Err(BoxError::from_static_str(
            "ECH config override requires ECH state",
        ));
    };

    if config_list != state.config_list {
        return Err(BoxError::from_static_str(
            "ECH config override does not match ECH private key",
        ));
    }

    Ok(Some(Arc::new(config_list)))
}

#[derive(Debug, Parser)]
#[command(name = "agent-sandbox-proxy")]
struct Args {
    #[arg(
        long,
        env = "AGENT_SANDBOX_PROXY_SOCKET",
        default_value = "/run/agent-sandbox/proxy-policy.sock"
    )]
    policy_socket: PathBuf,

    #[arg(long, env = "AGENT_SANDBOX_PROXY_CA_CERT")]
    ca_certificate: Option<PathBuf>,

    #[arg(long, env = "AGENT_SANDBOX_PROXY_CA_KEY")]
    ca_private_key: Option<PathBuf>,

    #[arg(
        long = "enable-http3-backend",
        env = "AGENT_SANDBOX_PROXY_ENABLE_HTTP3"
    )]
    http3: bool,

    #[arg(long, default_value_t = 443)]
    http3_listen_port: u16,

    /// Additional UDP ports whose intercepted QUIC traffic terminates at
    /// the proxy, for validated `Alt-Svc` alternative endpoints.
    #[arg(long = "http3-alt-port", value_name = "PORT")]
    http3_alt_ports: Vec<u16>,

    #[arg(long)]
    init_ech_state_only: bool,

    #[arg(long, default_value_t = 18080)]
    listen_port: u16,

    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    test_destination: Option<SocketAddr>,

    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    test_ech_dns: Option<SocketAddr>,

    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    test_tls: bool,

    /// Write the actually bound listener ports to this file, one `key port`
    /// line per listener. The harness passes `--listen-port 0` and learns
    /// the real ports from this file, so no port allocation is raced.
    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    write_bound_ports: Option<PathBuf>,

    #[arg(long, default_value_t = 305_000)]
    policy_timeout_ms: u64,

    #[arg(long = "websocket-http11-url", value_name = "URL")]
    websocket_http11_urls: Vec<String>,

    #[arg(long = "http10-upstream-origin", value_name = "ORIGIN")]
    http10_upstream_origins: Vec<String>,

    #[arg(long, env = "AGENT_SANDBOX_ECH_CONFIG_LIST")]
    ech_config_list: Option<String>,

    #[arg(
        long,
        env = "AGENT_SANDBOX_ECH_STATE_DIR",
        default_value = ech_state::DEFAULT_ECH_STATE_DIR
    )]
    ech_state_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Logs are captured to files by the harness and journald; ANSI styling
    // would corrupt structured log parsing. The default would enable colours
    // whenever `NO_COLOR` is unset, so pin them off explicitly.
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .init();

    let args = Args::parse();

    if args.init_ech_state_only {
        let state_dir = args
            .ech_state_dir
            .as_deref()
            .ok_or_else(|| BoxError::from_static_str("ECH state directory is required"))?;

        ech_state::load_or_generate(state_dir)?;
        return Ok(());
    }

    let (issuer, listener_config) = load_listener_config(&args)?;

    let policy = Arc::new(
        PolicySession::open(
            &args.policy_socket,
            Duration::from_millis(args.policy_timeout_ms),
        )
        .await?,
    );

    let shutdown = Arc::new(Notify::new());
    let active_checks = Arc::new(Semaphore::new(MAX_ACTIVE_CHECKS));
    let executor = Executor::default();
    let alt_svc = listener_config.alt_svc.clone();
    let ech_config_list = listener_config.ech_config_list.clone();
    let ech_private_key = listener_config.ech_private_key;

    #[cfg(debug_assertions)]
    let mut http3_ports = Vec::new();

    if args.http3 {
        let http3 = Http3Config {
            policy: policy.clone(),
            issuer: issuer.clone(),
            shutdown: shutdown.clone(),
            active_checks: active_checks.clone(),
            listen_port: args.http3_listen_port,
            alt_ports: args.http3_alt_ports.clone(),
            alt_svc: alt_svc.clone(),
            #[cfg(debug_assertions)]
            test_destination: args.test_destination,
            #[cfg(not(debug_assertions))]
            test_destination: None,
            #[cfg(debug_assertions)]
            test_ech_dns: args.test_ech_dns,
            #[cfg(not(debug_assertions))]
            test_ech_dns: None,
            ech_config_list,
            ech_private_key,
        };

        let backend = http3::prepare(http3)?;

        for port in backend.bound_ports() {
            alt_svc.intercept(*port);
        }

        #[cfg(debug_assertions)]
        http3_ports.extend(backend.bound_ports().iter().copied());

        tokio::spawn(http3::run(backend));
    }

    #[cfg(debug_assertions)]
    let listener_config = {
        let mut config = listener_config;

        if let Some(path) = &args.write_bound_ports {
            config.write_bound_ports = Some((path.clone(), http3_ports));
        }

        config
    };

    run_tcp_listener(listener_config, executor, policy, shutdown, active_checks).await
}

fn load_listener_config(args: &Args) -> Result<(CertificateIssuer, ListenConfig), BoxError> {
    let websocket_http11_urls = args
        .websocket_http11_urls
        .iter()
        .map(|pattern| {
            HttpUrl::parse_pattern(pattern).map_err(|error| {
                BoxError::from(format!(
                    "invalid WebSocket HTTP/1.1 URL pattern {pattern:?}: {error}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let websocket_http11_urls = Arc::new(websocket_http11_urls);

    let http10_upstream_origins =
        Arc::new(canonical_http10_origins(&args.http10_upstream_origins)?);

    let ech_state = args
        .ech_state_dir
        .as_deref()
        .map(ech_state::load_or_generate)
        .transpose()?;

    let ech_config_list =
        select_ech_config_list(args.ech_config_list.as_deref(), ech_state.as_ref())?;

    let ech_private_key = ech_state.map(|state| state.private_key);

    let ca_certificate = args
        .ca_certificate
        .as_deref()
        .ok_or_else(|| BoxError::from_static_str("CA certificate is required"))?;

    let ca_certificate = std::fs::read_to_string(ca_certificate)?;

    let ca_private_key = args
        .ca_private_key
        .as_deref()
        .ok_or_else(|| BoxError::from_static_str("CA private key is required"))?;

    let ca_private_key = std::fs::read_to_string(ca_private_key)?;
    let issuer = CertificateIssuer::from_pem(&ca_certificate, &ca_private_key)?;

    #[cfg(debug_assertions)]
    let transparent = args.test_destination.is_none();

    #[cfg(not(debug_assertions))]
    let transparent = true;

    // The intercepted UDP set is filled after the HTTP/3 backend binds:
    // port-0 listeners only learn their real ports once bound.
    let listener_config = ListenConfig {
        listen_port: args.listen_port,
        transparent,
        issuer: issuer.clone(),
        ech_config_list,
        ech_private_key,
        alt_svc: Arc::new(AltSvcStore::new(Vec::new())),
        websocket_http11_urls,
        http10_upstream_origins,
        #[cfg(debug_assertions)]
        destination_resolver: args
            .test_destination
            .map_or_else(|| Arc::new(destination_for_stream), destination_override),
        #[cfg(not(debug_assertions))]
        destination_resolver: Arc::new(destination_for_stream),
        #[cfg(debug_assertions)]
        test_tls: args.test_tls,
        #[cfg(not(debug_assertions))]
        test_tls: false,
        #[cfg(debug_assertions)]
        write_bound_ports: None,
    };

    Ok((issuer, listener_config))
}

#[cfg(test)]
mod tests {
    use super::{Args, select_ech_config_list};
    use agent_sandbox_proxy::ech_state::EchState;
    use clap::Parser;

    #[test]
    fn args_disable_http3_by_default() {
        let args = Args::try_parse_from(["agent-sandbox-proxy"]).expect("proxy arguments");
        assert!(!args.http3);
    }

    #[test]
    fn args_enable_http3_with_explicit_flag() {
        let args = Args::try_parse_from(["agent-sandbox-proxy", "--enable-http3-backend"])
            .expect("proxy arguments");

        assert!(args.http3);
    }

    #[test]
    fn args_parse_http10_upstream_origins() {
        let args = Args::try_parse_from([
            "agent-sandbox-proxy",
            "--http10-upstream-origin",
            "http://example.com",
            "--http10-upstream-origin",
            "https://example.org:8443/",
        ])
        .expect("proxy arguments");

        assert!(!args.http3);

        assert_eq!(args.http10_upstream_origins, [
            "http://example.com",
            "https://example.org:8443/"
        ]);
    }

    #[test]
    fn ech_config_override_must_match_private_key() {
        let state = EchState {
            config_list: vec![1],
            private_key: [0; 32],
        };

        assert!(select_ech_config_list(Some("Ag=="), Some(&state)).is_err());

        assert_eq!(
            select_ech_config_list(Some("AQ=="), Some(&state))
                .expect("matching ECH config")
                .expect("ECH config")
                .as_slice(),
            &[1]
        );
    }
}

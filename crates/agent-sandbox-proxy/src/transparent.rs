use agent_sandbox_core::{ProcessIds, policy_host_for_connect};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::error::ProxyClientError;
use crate::pipe::{pipe_bidirectional, read_client_peek};
use crate::policy::check_destination;
use crate::state::ProxyState;

pub(crate) async fn handle_transparent(
    stream: TcpStream,
    connect_host: String,
    port: u16,
    state: ProxyState,
    ids: ProcessIds,
) -> Result<(), ProxyClientError> {
    let scheme = if port == 443 { "https" } else { "http" };
    let initial = read_client_peek(&stream).await;
    let cache_path = std::env::var("AGENT_SANDBOX_DNS_CACHE").ok();
    let cache_ref = cache_path.as_deref().map(std::path::Path::new);
    let (policy_host, upstream_host) =
        policy_host_for_connect(&connect_host, Some(&initial), cache_ref);
    if policy_host != connect_host {
        info!(
            policy_host = %policy_host,
            connect_host = %connect_host,
            port,
            "transparent policy host"
        );
    }
    if !check_destination(&state, &policy_host, &upstream_host, port, scheme, ids).await? {
        info!(policy_host = %policy_host, port, "transparent deny");
        return Ok(());
    }
    let remote = match TcpStream::connect((upstream_host.as_str(), port)).await {
        Ok(s) => s,
        Err(err) => {
            warn!(host = %upstream_host, port, error = %err, "transparent upstream failed");
            return Ok(());
        }
    };
    info!(
        upstream = %upstream_host,
        port,
        policy_host = %policy_host,
        "transparent upstream connected"
    );
    pipe_bidirectional(stream, remote, initial).await;
    Ok(())
}

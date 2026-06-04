use std::time::Duration;

use agent_sandbox_core::{ProcessIds, policy_host_for_connect};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::error::ProxyClientError;
use crate::http::write_http_response;
use crate::pipe::pipe_bidirectional;
use crate::policy::check_destination;
use crate::state::ProxyState;

pub(crate) async fn handle_connect(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    state: ProxyState,
    ids: ProcessIds,
) -> Result<(), ProxyClientError> {
    let cache_path = std::env::var("AGENT_SANDBOX_DNS_CACHE").ok();
    let cache_ref = cache_path.as_deref().map(std::path::Path::new);
    let (policy_host, connect_host) = policy_host_for_connect(host, None, cache_ref);
    if !check_destination(&state, &policy_host, &connect_host, port, "https", ids).await? {
        write_http_response(
            &mut stream,
            "403 Forbidden",
            "Denied by agent-sandbox policy\n",
        )
        .await?;
        return Ok(());
    }
    let remote = match tokio::time::timeout(
        Duration::from_secs(30),
        TcpStream::connect((connect_host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            let detail = err.to_string();
            warn!(host = %connect_host, port, error = %detail, "connect upstream failed");
            write_http_response(&mut stream, "502 Bad Gateway", &format!("{detail}\n")).await?;
            return Ok(());
        }
        Err(_) => {
            write_http_response(&mut stream, "504 Gateway Timeout", "upstream timed out\n").await?;
            return Ok(());
        }
    };
    info!(
        upstream = %connect_host,
        port,
        policy_host = %policy_host,
        "connect upstream connected"
    );
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    pipe_bidirectional(stream, remote, Vec::new()).await;
    Ok(())
}

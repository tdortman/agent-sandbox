use agent_sandbox_core::{ProcessIds, peer_cred};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::connect::handle_connect;
use crate::error::ProxyClientError;
use crate::http::read_connect_request;
use crate::pipe::original_dst;
use crate::state::ProxyState;
use crate::transparent::handle_transparent;

pub(crate) async fn handle_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: ProxyState,
) -> Result<(), ProxyClientError> {
    let cred = peer_cred(&stream);
    let ids = cred.map_or_else(ProcessIds::default, |(pid, uid, _gid)| {
        ProcessIds::new(pid, uid)
    });

    if state.args.transparent
        && let Some((orig_host, orig_port)) = original_dst(&stream)
    {
        let listen = format!("{}:{}", state.args.listen_host, state.args.listen_port);
        let redirected =
            matches!(orig_port, 80 | 443) && format!("{orig_host}:{orig_port}") != listen;
        if redirected {
            info!(%peer, %orig_host, orig_port, "transparent");
            return handle_transparent(stream, orig_host, orig_port, state, ids).await;
        }
    }

    let (host, port) = match read_connect_request(&mut stream).await {
        Ok(v) => v,
        Err(ProxyClientError::Closed) => return Ok(()),
        Err(err) => return Err(err),
    };
    info!(%peer, %host, port, "connect");
    handle_connect(stream, &host, port, state, ids).await
}

pub(crate) async fn accept_loop(state: ProxyState, listener: tokio::net::TcpListener) {
    loop {
        let (stream, peer) = listener.accept().await.expect("accept");
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, peer, state).await {
                warn!(%peer, error = %err, "proxy client error");
            }
        });
    }
}

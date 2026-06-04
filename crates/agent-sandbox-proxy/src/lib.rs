//! Policy proxy: HTTP CONNECT and transparent TCP (SO_ORIGINAL_DST).

pub mod client;
pub mod connect;
pub mod error;
pub mod http;
pub mod pipe;
pub mod policy;
pub mod state;
pub mod transparent;

use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;

use state::{Args, ProxyState};

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arc::new(Args::parse());
    let state = ProxyState { args: args.clone() };
    let addr = format!("{}:{}", args.listen_host, args.listen_port);
    let listener = TcpListener::bind(&addr).await?;
    let modes = if args.transparent {
        "explicit CONNECT, transparent"
    } else {
        "explicit CONNECT"
    };
    info!(%addr, modes, "proxy listening");

    client::accept_loop(state, listener).await;
    Ok(())
}

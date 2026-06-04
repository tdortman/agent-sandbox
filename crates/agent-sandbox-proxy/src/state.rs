use std::sync::Arc;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-proxy")]
pub(crate) struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    pub listen_host: String,
    #[arg(long, default_value_t = 17_888)]
    pub listen_port: u16,
    #[arg(long, default_value = "/run/agent-sandbox/policy.sock")]
    pub policy_socket: String,
    #[arg(long, default_value_t = 35.0)]
    pub policy_timeout: f64,
    #[arg(long, default_value_t = true)]
    pub transparent: bool,
}

#[derive(Clone)]
pub(crate) struct ProxyState {
    pub args: Arc<Args>,
}

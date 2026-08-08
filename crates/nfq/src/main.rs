//! Agent sandbox NFQUEUE, kernel-level packet policy enforcement.
//!
//! Runs inside the sandbox network namespace. nftables queues outbound TCP SYN
//! and UDP packets here. This daemon resolves the destination hostname from the
//! DNS forwarder's in-memory cache, asks policyd for a verdict, then accepts or
//! actively rejects the packet.

mod args;
mod attribution;
mod flow;
mod owner;
mod packet;
mod policy;
mod push;
mod queue;

use crate::{
    args::Cli,
    flow::{NfqState, handle_packet, mark_accepted_proxy_udp},
    push::spawn_push_socket_listener,
    queue::{open_queue, write_ready_marker_or_exit},
};
use clap::Parser;
use std::time::Duration;
use tracing::{info, warn};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agent_sandbox_nfq=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();
    let timeout = Duration::from_secs_f64(cli.policy_timeout.max(1.0));

    let mut queue = match open_queue(cli.queue, cli.queue_len) {
        Ok(queue) => queue,
        Err(err) => {
            eprintln!(
                "agent-sandbox-nfq: failed to bind queue {}: {err}",
                cli.queue
            );
            std::process::exit(1);
        }
    };

    let _ready_marker = cli.ready_file.as_deref().map(write_ready_marker_or_exit);
    info!(queue = cli.queue, "nfqueue listening");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let state = NfqState::new(&cli);
    spawn_push_socket_listener(&cli.push_socket, cli.push_trusted_uid, &state);

    loop {
        let mut message = match queue.recv() {
            Ok(message) => message,
            Err(err) => {
                warn!(error = %err, "nfqueue recv error");
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };

        let (verdict, meta) = handle_packet(&state, &cli.policy_socket, timeout, &message, &runtime);
        mark_accepted_proxy_udp(&state, &mut message, verdict, meta);
        message.set_verdict(verdict);

        if let Err(err) = queue.verdict(message) {
            warn!(error = %err, "nfqueue verdict error");
        }
    }
}


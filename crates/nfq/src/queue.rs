//! NFQUEUE binding, copy range, and the systemd readiness marker.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use agent_sandbox_core::PersistentRpcClient;
use nfq_updated::Queue;
use tokio::{
    io::{Interest, unix::AsyncFd},
    task::JoinSet,
};

use crate::{
    flow::{NfqState, handle_packet, mark_accepted_proxy_udp},
    packet,
};

/// Number of bytes to copy from each queued packet.
/// `u16::MAX` ensures the full UDP DNS response payload is available
/// for hickory-proto parsing (CNAME chains and multi-answer responses
/// routinely exceed the standard Ethernet MTU's 1500-byte segment).
const COPY_RANGE: u16 = u16::MAX;

pub fn open_queue(queue_num: u16, queue_len: u32) -> std::io::Result<Queue> {
    let mut queue = Queue::open()?;
    queue.bind(queue_num)?;
    queue.set_fail_open(queue_num, false)?;
    queue.set_recv_gso(queue_num, false)?;
    queue.set_copy_range(queue_num, COPY_RANGE)?;
    queue.set_queue_max_len(queue_num, queue_len)?;
    Ok(queue)
}

pub struct ReadyMarker(PathBuf);

/// Run bounded independent-flow checks without blocking the async I/O driver.
pub async fn run_queue(
    mut queue: Queue,
    state: NfqState,
    policy_socket: String,
    timeout: Duration,
) -> std::io::Result<()> {
    queue.set_nonblocking(true);
    let mut queue = AsyncFd::new(queue)?;
    let state = Arc::new(state);
    let concurrency = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(4);
    let mut clients: Vec<_> = (0..concurrency)
        .map(|_| Some(PersistentRpcClient::new(policy_socket.clone())))
        .collect();
    let mut deferred = None;
    loop {
        let first = if let Some(message) = deferred.take() {
            message
        } else {
            match queue.async_io_mut(Interest::READABLE, Queue::recv).await {
                Ok(message) => message,
                Err(error) => {
                    tracing::warn!(%error, "nfqueue recv error");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            }
        };
        let mut first = Some(first);
        let mut active = JoinSet::new();
        let mut flows = Vec::with_capacity(concurrency);
        for (index, client) in clients.iter_mut().enumerate() {
            let message = if let Some(message) = first.take() {
                message
            } else {
                match queue.get_mut().recv() {
                    Ok(message) => message,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        tracing::warn!(%error, "nfqueue recv error");
                        break;
                    }
                }
            };
            let meta = packet::parse_ipv4(message.get_payload())
                .or_else(|| packet::parse_ipv6(message.get_payload()));
            let key = meta.map(|meta| {
                (
                    meta.protocol,
                    meta.src_ip,
                    meta.src_port,
                    meta.dst_ip,
                    meta.dst_port,
                )
            });
            let barrier = meta.is_none_or(|meta| meta.src_port == 53);
            // Keep same-flow packets ordered and DNS updates between completed batches.
            if !active.is_empty() && (barrier || flows.contains(&key)) {
                deferred = Some(message);
                break;
            }
            flows.push(key);
            let state = Arc::clone(&state);
            let mut client = client.take().expect("policy worker available");
            let runtime = tokio::runtime::Handle::current();
            active.spawn_blocking(move || {
                let mut message = message;
                let (verdict, meta) =
                    handle_packet(&state, &mut client, timeout, &message, &runtime);
                mark_accepted_proxy_udp(&state, &mut message, verdict, meta);
                message.set_verdict(verdict);
                (index, message, client)
            });
            if barrier {
                break;
            }
        }
        // ponytail: bounded batches; streaming dispatch if batch drain limits
        // throughput.
        while let Some(result) = active.join_next().await {
            let (index, message, client) = result.map_err(std::io::Error::other)?;
            clients[index] = Some(client);
            if let Err(error) = queue.get_mut().verdict(message) {
                tracing::warn!(%error, "nfqueue verdict error");
            }
        }
    }
}

impl Drop for ReadyMarker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn validate_invocation_id(value: &str) -> std::io::Result<()> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "INVOCATION_ID must be exactly 32 lowercase hexadecimal characters",
    ))
}

pub fn write_ready_marker_or_exit(path: &Path) -> ReadyMarker {
    match write_ready_marker(path) {
        Ok(marker) => marker,

        Err(err) => {
            eprintln!(
                "agent-sandbox-nfq: failed to write readiness marker {}: {err}",
                path.display()
            );
            std::process::exit(1);
        }
    }
}

fn write_ready_marker(path: &Path) -> std::io::Result<ReadyMarker> {
    let invocation_id = std::env::var("INVOCATION_ID").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "INVOCATION_ID is required when --ready-file is configured",
        )
    })?;

    validate_invocation_id(&invocation_id)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, invocation_id.as_bytes())?;
    let mut permissions = std::fs::metadata(&temporary)?.permissions();

    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o644);
    }

    if let Err(error) = std::fs::set_permissions(&temporary, permissions)
        .and_then(|()| std::fs::rename(&temporary, path))
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }

    Ok(ReadyMarker(path.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_marker_requires_lowercase_32_hex_invocation_id() {
        assert!(validate_invocation_id("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_invocation_id("0123456789ABCDEF0123456789abcdef").is_err());
        assert!(validate_invocation_id("0123456789abcdef").is_err());
        assert!(validate_invocation_id("0123456789abcdef0123456789abcdeg").is_err());
    }
}

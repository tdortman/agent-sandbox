//! NFQUEUE binding, copy range, and the systemd readiness marker.

use std::path::{Path, PathBuf};

use nfq_updated::Queue;

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

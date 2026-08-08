//! DNS-forwarder push-socket listener.
//!
//! Receives `{"ip","host","ttl"}` frames from the DNS forwarder and inserts
//! them into the in-memory cache. The socket is optional: if it does not
//! exist or cannot be bound, the daemon falls back to the on-disk cache.

use crate::flow::NfqState;

use agent_sandbox_core::{DEFAULT_MAX_TTL, DnsCache};
use std::{path::Path, sync::Arc};
use tracing::{debug, info, warn};

/// Background thread that consumes `{"ip","host","ttl"}` lines from the DNS
/// forwarder's push socket and inserts them into the in-memory cache. The
/// socket is optional: if `push_socket` does not exist or cannot be bound,
/// the daemon falls back to the on-disk cache only.
pub fn spawn_push_socket_listener(push_socket: &Path, trusted_uid: u32, state: &NfqState) {
    if !push_socket.exists()
        && let Some(parent) = push_socket.parent()
    {
        let _ = std::fs::create_dir_all(parent);
    }

    // Remove any stale socket file so bind succeeds. The forwarder is a
    // client and does not own the socket file, so we always unlink before
    // binding.
    let _ = std::fs::remove_file(push_socket);

    let listener = match std::os::unix::net::UnixDatagram::bind(push_socket) {
        Ok(s) => s,
        Err(err) => {
            warn!(socket = %push_socket.display(), error = %err, "push socket bind failed");
            return;
        }
    };

    if let Err(err) = restrict_push_socket_permissions(push_socket) {
        warn!(socket = %push_socket.display(), error = %err, "push socket chmod failed");
    }

    if let Err(err) = enable_passcred(&listener) {
        warn!(socket = %push_socket.display(), error = %err, "push socket SO_PASSCRED failed");
        return;
    }

    info!(socket = %push_socket.display(), trusted_uid, "push socket listener bound");
    let cache = Arc::clone(&state.dns_cache);

    std::thread::Builder::new()
        .name("dns-push-listener".to_string())
        .spawn(move || {
            let mut buf = [0u8; 512];

            loop {
                let Ok((n, cred)) = recv_datagram_with_creds(&listener, &mut buf) else {
                    continue;
                };

                if cred.uid != trusted_uid {
                    warn!(
                        peer_uid = cred.uid,
                        peer_pid = cred.pid,
                        trusted_uid,
                        "push socket rejected untrusted peer"
                    );

                    continue;
                }

                let line = match std::str::from_utf8(&buf[..n]) {
                    Ok(s) => s,
                    Err(err) => {
                        debug!(error = %err, "push socket non-utf8 frame");
                        continue;
                    }
                };

                let line = line.trim_end_matches(['\n', '\r', '\0']);
                let parsed: Result<PushMapping, _> = serde_json::from_str(line);

                let Ok(entry) = parsed else {
                    debug!(line, "push socket malformed JSON");
                    continue;
                };

                apply_push_mapping(&cache, &entry);
            }
        })
        .expect("spawn push socket listener");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnixPeerCred {
    pid: u32,
    uid: u32,
    gid: u32,
}

fn restrict_push_socket_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn enable_passcred(sock: &std::os::unix::net::UnixDatagram) -> std::io::Result<()> {
    use nix::sys::socket::{setsockopt, sockopt::PassCred};

    setsockopt(sock, PassCred, &true).map_err(std::io::Error::from)
}

fn recv_datagram_with_creds(
    sock: &std::os::unix::net::UnixDatagram,
    buf: &mut [u8],
) -> std::io::Result<(usize, UnixPeerCred)> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use std::{io::IoSliceMut, os::unix::io::AsRawFd};

    let mut cmsg = [0u8; 128];
    let mut iov = [IoSliceMut::new(buf)];

    let msg: nix::sys::socket::RecvMsg<'_, '_, ()> = recvmsg(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::empty(),
    )
    .map_err(std::io::Error::from)?;

    let cred = msg
        .cmsgs()?
        .find_map(|cmsg| match cmsg {
            ControlMessageOwned::ScmCredentials(cred) => Some(UnixPeerCred {
                pid: u32::try_from(cred.pid()).unwrap_or(u32::MAX),
                uid: cred.uid(),
                gid: cred.gid(),
            }),
            _ => None,
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "push socket frame missing SCM_CREDENTIALS",
            )
        })?;

    Ok((msg.bytes, cred))
}

/// Apply a validated push mapping to the in-memory DNS cache.
fn apply_push_mapping(cache: &Arc<std::sync::Mutex<DnsCache>>, entry: &PushMapping) {
    if entry.host.is_empty() {
        return;
    }

    if let Ok(mut cache) = cache.lock() {
        cache.remember_ephemeral(&entry.ip, &entry.host, entry.ttl.min(DEFAULT_MAX_TTL));
    }
}

#[derive(serde::Deserialize)]
struct PushMapping {
    ip: String,
    host: String,

    #[serde(default)]
    ttl: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::tests::state_for_tests;

    #[test]
    fn push_mapping_applies_to_cache() {
        let state = state_for_tests();

        let entry = PushMapping {
            ip: "93.184.216.34".to_string(),
            host: "example.com".to_string(),
            ttl: 300,
        };

        apply_push_mapping(&state.dns_cache, &entry);

        assert_eq!(
            state
                .dns_cache
                .lock()
                .expect("lock dns cache")
                .lookup("93.184.216.34")
                .as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn push_socket_rejects_untrusted_peer_uid() {
        use std::{
            os::unix::fs::PermissionsExt,
            time::{SystemTime, UNIX_EPOCH},
        };

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());

        let socket_path = std::env::temp_dir().join(format!(
            "agent-sandbox-nfq-push-{}-{stamp}.sock",
            std::process::id()
        ));

        let _ = std::fs::remove_file(&socket_path);
        let listener = std::os::unix::net::UnixDatagram::bind(&socket_path).expect("bind listener");

        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod push socket");

        enable_passcred(&listener).expect("SO_PASSCRED");
        let state = state_for_tests();
        let cache = Arc::clone(&state.dns_cache);
        let listener_path = socket_path.clone();

        let listener_thread = std::thread::spawn(move || {
            let mut buf = [0_u8; 512];

            let Ok((n, cred)) = recv_datagram_with_creds(&listener, &mut buf) else {
                return false;
            };

            if cred.uid != 0 {
                return false;
            }

            let line = std::str::from_utf8(&buf[..n]).expect("utf8");
            let entry: PushMapping = serde_json::from_str(line.trim()).expect("json");
            apply_push_mapping(&cache, &entry);
            true
        });

        let sender = std::os::unix::net::UnixDatagram::unbound().expect("unbound sender");

        sender
            .send_to(
                br#"{"ip":"1.2.3.4","host":"evil.com","ttl":60}"#,
                &listener_path,
            )
            .expect("send push frame");

        let accepted = listener_thread.join().expect("listener thread");
        assert!(!accepted, "untrusted peer uid must not apply push mappings");

        assert!(
            state
                .dns_cache
                .lock()
                .expect("lock dns cache")
                .lookup("1.2.3.4")
                .is_none()
        );

        let _ = std::fs::remove_file(socket_path);
    }
}

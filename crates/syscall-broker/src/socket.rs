//! Classification of `connect`, `sendto`, `sendmsg` and `sendmmsg` targets.
//!
//! Destinations are captured once (see [`crate::capture`]); a filesystem
//! `AF_UNIX` destination is additionally pinned by inode so the policy key and
//! the emulated syscall name the same socket.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::{fd::AsFd, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
};

use agent_sandbox_core::{ResourceAccess, ResourceKind, SocketAccess};

use crate::{
    NetworkTarget, ResourceCapture, ResourceTarget, SeccompNotif, SyscallTarget, UnixCapture,
    capture::{Batch, Msghdr, Sockaddr, capture_sendmmsg, capture_sendmsg, read_sockaddr},
    errno_target,
    pinning::{DirBase, PinScope, Resolver},
};

/// Parsed `AF_UNIX` address: a filesystem path or a kernel abstract name.
///
/// Abstract names are encoded as either `@abstract:<text>` (when the name
/// is printable UTF-8, so rules like `nv_target_process_*` match) or
/// `@hex:<lower-hex>` (fallback for binary names). Both survive JSON
/// round-trips and match verbatim in policyd's resource rule engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnixAddress {
    /// Filesystem path of the Unix socket.
    Path(String),

    /// Kernel abstract socket name, keyed for policy (printable text or hex).
    AbstractHex(String),
}

/// Parsed sockaddr: either an Internet (`AF_INET`/`AF_INET6`) endpoint or a
/// Unix-domain (`AF_UNIX`) address, paired with the raw bytes so callers can
/// re-derive fields the high-level enum drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SockaddrTarget {
    /// Internet endpoint (`AF_INET`/`AF_INET6`): an IP address and port.
    Inet { ip: IpAddr, port: u16 },

    /// Unix-domain endpoint (`AF_UNIX`): a parsed address plus the raw
    /// captured sockaddr bytes.
    Unix { address: UnixAddress, raw: Vec<u8> },
}

/// Hex-encode a byte slice as lowercase ASCII, no `0x` prefix.
/// ponytail: inlined instead of pulling the `hex` crate for ~20 lines.
fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);

    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0F)] as char);
    }

    out
}

/// Format a kernel abstract socket name for use as a policy key.
///
/// Printable UTF-8 names become `@abstract:<text>` so users can write glob
/// rules (`nv_target_process_*`). Binary names fall back to `@hex:<hex>` to
/// stay byte-stable when the name is not valid text.
fn format_abstract_name(name: &[u8]) -> String {
    if name.is_empty() {
        return "@hex:".to_string();
    }

    if let Ok(s) = std::str::from_utf8(name)
        && s.bytes().all(|b| b >= 0x20 && b != 0x7F)
    {
        return format!("@abstract:{s}");
    }

    format!("@hex:{}", hex_encode_lower(name))
}

/// Look up the actual `SO_TYPE` of a tracee socket via `pidfd_open` +
/// `pidfd_getfd`. Returns `None` on any failure (process gone, fd not a
/// socket, kernel too old for the syscalls, etc.) so the caller can fall
/// back to a per-syscall default.
fn get_socket_type(pid: u32, sockfd: i32) -> Option<i32> {
    let dup = agent_sandbox_sysutil::dup_tracee_fd(pid, sockfd).ok()?;
    agent_sandbox_sysutil::socket_type(&dup)
}

/// Map a `SO_TYPE` value to a URL scheme. DGRAM sockets are UDP; everything
/// else (STREAM, RAW, SEQPACKET, ...) is reported as TCP for policy purposes,
/// because policyd only knows those two schemes today.
const fn scheme_for_socket_type(sock_type: i32) -> &'static str {
    if sock_type == libc::SOCK_DGRAM {
        "udp"
    } else {
        "tcp"
    }
}

/// Resolve the URL scheme for a tracee fd. Tries `get_socket_type` first;
/// on any failure, returns the per-syscall default. `sockfd` comes from
/// `notif.data.args[0]` for sendto/sendmsg/sendmmsg/connect.
fn scheme_for_fd(notif: &SeccompNotif, sockfd: u64, default: &str) -> String {
    let Some(sockfd_i32) = i32::try_from(sockfd).ok() else {
        return default.to_owned();
    };

    get_socket_type(notif.pid, sockfd_i32)
        .map_or(default, |sock_type| scheme_for_socket_type(sock_type))
        .to_owned()
}

/// Parse a raw sockaddr buffer into a `SockaddrTarget`.
///
/// Supports `AF_INET`/`AF_INET6` (`IpAddr` + port) and `AF_UNIX`
/// (filesystem path or kernel abstract-namespace name). `addrlen` is the
/// tracee-supplied sockaddr length; for abstract Unix names the policy key
/// uses the full `addrlen` span (including embedded NULs), not C-string
/// truncation. Returns `None` for any other family or a buffer too short
/// to hold the family prefix.
fn parse_sockaddr(bytes: &[u8], addrlen: usize) -> Option<SockaddrTarget> {
    let addrlen = addrlen.min(bytes.len());

    if addrlen < 2 {
        return None;
    }

    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);

    match i32::from(family) {
        libc::AF_INET if addrlen >= 16 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);

            Some(SockaddrTarget::Inet {
                ip: IpAddr::V4(ip),
                port,
            })
        }

        libc::AF_INET6 if addrlen >= 28 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[8..24]);

            Some(SockaddrTarget::Inet {
                ip: IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            })
        }

        libc::AF_UNIX => {
            let raw = bytes[..addrlen].to_vec();

            if addrlen <= 2 {
                // Empty path: unnamed Unix socket. Treat as no target.
                return None;
            }

            // Abstract namespace: the first byte of `sun_path` is NUL.
            if bytes[2] == 0 {
                // Abstract names CAN contain embedded NULs. The kernel uses
                // `addrlen`, not a C string, to bound the name. Use the full
                // span so the policy key matches the emulated connect target.
                let name = if addrlen > 3 { &bytes[3..addrlen] } else { &[] };

                Some(SockaddrTarget::Unix {
                    address: UnixAddress::AbstractHex(format_abstract_name(name)),
                    raw,
                })
            } else {
                // Filesystem path: NUL-terminated C string in sun_path.
                let path_bytes = &bytes[2..addrlen];
                let end = path_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(path_bytes.len());

                let path = std::str::from_utf8(&path_bytes[..end]).ok()?.to_owned();

                Some(SockaddrTarget::Unix {
                    address: UnixAddress::Path(path),
                    raw,
                })
            }
        }

        _ => None,
    }
}

/// Extract a target from a `connect` syscall notification.
///
/// `connect` on an `AF_INET`/`AF_INET6` sockaddr yields a `Network` target
/// routed through the `Check` RPC. `connect` on an `AF_UNIX` sockaddr yields
/// a `Resource` target of kind `UnixSocket` with `Connect` access.
///
/// # Errors
///
/// Returns an error if reading tracee memory fails.
pub fn target_from_connect(
    resolver: &Resolver,
    notif: &SeccompNotif,
) -> io::Result<Option<SyscallTarget>> {
    let args = &notif.data.args;
    let scheme = scheme_for_fd(notif, args[0], "tcp");
    let sockaddr = read_sockaddr(notif.pid, args[1], args[2])?;

    Ok(classify(
        resolver,
        notif.pid,
        sockaddr,
        &scheme,
        ResourceAccess::Socket(SocketAccess::Connect),
        None,
    ))
}

/// Extract a target from a `sendto` syscall notification.
///
/// `sendto` on an `AF_INET`/`AF_INET6` sockaddr yields a `Network` target
/// routed through the `Check` RPC. `sendto` on an `AF_UNIX` sockaddr yields
/// a `Resource` target of kind `UnixSocket` with `Send` access. A connected
/// socket calling `sendto` with a null `dest_addr` returns `None` because no
/// policy decision can be made from the syscall args alone (the socket is
/// already connected and the destination is fixed by the prior `connect`).
///
/// # Errors
///
/// Returns an error if reading tracee memory fails.
pub fn target_from_sendto(
    resolver: &Resolver,
    notif: &SeccompNotif,
) -> io::Result<Option<SyscallTarget>> {
    let args = &notif.data.args;
    let scheme = scheme_for_fd(notif, args[0], "udp");
    let sockaddr = read_sockaddr(notif.pid, args[4], args[5])?;

    Ok(classify(
        resolver,
        notif.pid,
        sockaddr,
        &scheme,
        ResourceAccess::Socket(SocketAccess::Send),
        None,
    ))
}

/// Extract a target from a `sendmsg` syscall notification.
///
/// `sendmsg` on an `AF_UNIX` sockaddr yields a `Resource` target of kind
/// `UnixSocket` with `Send` access, carrying the captured `msghdr` for
/// emulation. `sendmsg` on an `AF_INET`/`AF_INET6` sockaddr yields a `Network`
/// target. A `sendmsg` with a null `msg_name` returns `None`: the socket is
/// already connected and the message has no destination address to
/// policy-check, so the broker continues the syscall.
///
/// # Errors
///
/// Returns an error if reading the tracee's `msghdr` or sockaddr fails.
pub fn target_from_sendmsg(
    resolver: &Resolver,
    notif: &SeccompNotif,
) -> io::Result<Option<SyscallTarget>> {
    let Some(destination) = capture_sendmsg(notif.pid, notif.data.args[1])? else {
        return Ok(None);
    };

    let scheme = scheme_for_fd(notif, notif.data.args[0], "udp");

    Ok(classify(
        resolver,
        notif.pid,
        Some(destination.sockaddr),
        &scheme,
        ResourceAccess::Socket(SocketAccess::Send),
        Some(destination.msghdr),
    ))
}

/// Extract a target from a `sendmmsg` syscall notification.
///
/// `sendmmsg` sends a vector of messages. When the batch carries more than
/// one distinct destination address the broker denies the syscall: checking
/// one message while the whole batch runs under `CONTINUE` would be a
/// multi-destination bypass. A single destination, wherever it appears in the
/// batch, is classified.
///
/// # Errors
///
/// Returns an error if reading tracee memory fails.
pub fn target_from_sendmmsg(
    resolver: &Resolver,
    notif: &SeccompNotif,
) -> io::Result<Option<SyscallTarget>> {
    let msgvec = notif.data.args[1];
    let vlen = usize::try_from(notif.data.args[2]).unwrap_or(0);

    if msgvec == 0 || vlen == 0 {
        return Ok(None);
    }

    let destination = match capture_sendmmsg(notif.pid, msgvec, vlen)? {
        Batch::Unaddressed => return Ok(None),
        Batch::Conflicting => return Ok(Some(SyscallTarget::Errno(libc::EACCES))),
        Batch::Single(destination) => destination,
    };

    let scheme = scheme_for_fd(notif, notif.data.args[0], "udp");

    Ok(classify(
        resolver,
        notif.pid,
        Some(destination.sockaddr),
        &scheme,
        ResourceAccess::Socket(SocketAccess::Send),
        None,
    ))
}

/// Classify a captured sockaddr. `Inet` results become a `Network` target
/// (gated by policyd's `Check` RPC) and `Unix` results become a `Resource`
/// target of kind `UnixSocket` gated by `CheckResource`. `access` selects
/// `Connect` (for `connect`) or `Send` (for `sendto`/`sendmsg`/`sendmmsg`).
fn classify(
    resolver: &Resolver,
    pid: u32,
    sockaddr: Option<Sockaddr>,
    scheme: &str,
    access: ResourceAccess,
    msghdr: Option<Msghdr>,
) -> Option<SyscallTarget> {
    let sockaddr = sockaddr?;

    Some(match parse_sockaddr(&sockaddr.bytes, sockaddr.len)? {
        // Port 0 means "unspecified" in sockaddr_in(6). We cannot form a
        // meaningful policy key (and must never prompt for `host:0`), so
        // skip gating here and let the tracee run the syscall. NFQUEUE still
        // enforces egress on the real destination port from the packet header.
        SockaddrTarget::Inet { port: 0, .. } => return None,

        SockaddrTarget::Inet { ip, port } => SyscallTarget::Network(NetworkTarget {
            host: ip.to_string(),
            port,
            scheme: scheme.to_string(),
        }),

        SockaddrTarget::Unix {
            address: UnixAddress::Path(path),
            raw,
        } => pinned_unix_target(resolver, pid, &raw[..2], &path, access, msghdr),

        // Abstract namespace names are hex-encoded strings (@hex:...), not
        // filesystem paths, but ride in the same PathBuf field and
        // serde-serialize as strings for policyd's Path::New matching.
        SockaddrTarget::Unix {
            address: UnixAddress::AbstractHex(name),
            raw,
        } => SyscallTarget::Resource(ResourceTarget {
            kind: ResourceKind::UnixSocket,
            path: PathBuf::from(name),
            access,
            capture: ResourceCapture::Unix(UnixCapture {
                addr: raw,
                pinned: None,
                msghdr,
            }),
        }),
    })
}

/// Pin the socket inode a filesystem `sun_path` names, resolving a relative
/// path against the tracee's working directory. The policy key comes from the
/// pinned inode and the emulated syscall connects through it, so a `chdir`, a
/// symlink swap, or a replaced socket after classification cannot redirect an
/// approval. Failures deny with the errno the lookup would give the tracee.
fn pinned_unix_target(
    resolver: &Resolver,
    pid: u32,
    family: &[u8],
    name: &str,
    access: ResourceAccess,
    msghdr: Option<Msghdr>,
) -> SyscallTarget {
    let pinned = match resolver.pin_name(pid, DirBase::Cwd, Path::new(name), PinScope::default()) {
        Ok(fd) => fd,
        Err(err) => return errno_target(&err),
    };

    // Unlinked since the lookup: connecting by name would fail the same way.
    let Some(path) = resolver.fd_path(pinned.as_fd()) else {
        return SyscallTarget::Errno(libc::ENOENT);
    };

    let mut addr = family.to_vec();
    addr.extend_from_slice(resolver.self_fd(pinned.as_fd()).as_os_str().as_bytes());
    addr.push(0);

    SyscallTarget::Resource(ResourceTarget {
        kind: ResourceKind::UnixSocket,
        path,
        access,
        capture: ResourceCapture::Unix(UnixCapture {
            addr,
            pinned: Some(pinned),
            msghdr,
        }),
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        SockaddrTarget, UnixAddress, hex_encode_lower, parse_sockaddr, scheme_for_socket_type,
    };

    #[test]
    fn parse_ipv4_sockaddr() {
        let bytes = [2, 0, 0, 53, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(
            parse_sockaddr(&bytes, bytes.len()),
            Some(SockaddrTarget::Inet {
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 53,
            })
        );
    }

    #[test]
    fn parse_ipv4_sockaddr_port_zero() {
        // Port 0 in a sockaddr is 'unspecified'. `classify` drops these
        // before sending a Check RPC. parse_sockaddr still returns the raw
        // value so the caller can decide.
        let bytes = [2, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(
            parse_sockaddr(&bytes, bytes.len()),
            Some(SockaddrTarget::Inet {
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 0,
            })
        );
    }

    #[test]
    fn scheme_for_socket_type_dgram_is_udp() {
        assert_eq!(scheme_for_socket_type(libc::SOCK_DGRAM), "udp");
    }

    #[test]
    fn scheme_for_socket_type_stream_is_tcp() {
        assert_eq!(scheme_for_socket_type(libc::SOCK_STREAM), "tcp");
    }

    #[test]
    fn scheme_for_socket_type_raw_and_seqpacket_are_tcp() {
        // Policyd only knows tcp/udp today; raw and seqpacket default to tcp.
        assert_eq!(scheme_for_socket_type(libc::SOCK_RAW), "tcp");

        assert_eq!(scheme_for_socket_type(libc::SOCK_SEQPACKET), "tcp");
    }

    #[test]
    fn parse_unix_sockaddr_path() {
        // AF_UNIX (family=1), path "/tmp/agent-sandbox.sock".
        let mut bytes = vec![1, 0]; // sa_family = AF_UNIX

        let path = b"/tmp/agent-sandbox.sock";
        bytes.extend_from_slice(path);
        bytes.push(0); // NUL terminator
        bytes.resize(32, 0); // pad to a realistic length
        let parsed = parse_sockaddr(&bytes, bytes.len()).expect("AF_UNIX path parses");

        match parsed {
            SockaddrTarget::Unix { address, raw } => {
                assert_eq!(
                    address,
                    UnixAddress::Path("/tmp/agent-sandbox.sock".to_string())
                );
                assert_eq!(raw.len(), 32);
            }

            other @ SockaddrTarget::Inet { .. } => panic!("expected Unix, got {other:?}"),
        }
    }

    #[test]
    fn parse_unix_sockaddr_abstract_printable_uses_decoded_text() {
        // Printable UTF-8 abstract names become `@abstract:<text>` so glob
        // rules like `nv_target_process_*` match the decoded name.
        let mut bytes = vec![1, 0, 0]; // family + abstract marker

        bytes.extend_from_slice(b"nv_target_process_1104286");
        let parsed = parse_sockaddr(&bytes, bytes.len()).expect("AF_UNIX abstract parses");

        match parsed {
            SockaddrTarget::Unix { address, raw } => {
                assert_eq!(
                    address,
                    UnixAddress::AbstractHex("@abstract:nv_target_process_1104286".into())
                );
                assert_eq!(raw, bytes);
            }

            other @ SockaddrTarget::Inet { .. } => panic!("expected Unix, got {other:?}"),
        }
    }

    #[test]
    fn parse_unix_sockaddr_abstract_uses_addrlen_not_nul_truncation() {
        // Abstract names can contain embedded NULs. The policy key must use
        // the full addrlen span so it matches the emulated connect target.
        let mut bytes = vec![1, 0, 0]; // family + abstract marker

        bytes.extend_from_slice(b"agent\x00sandbox");
        let parsed = parse_sockaddr(&bytes, bytes.len()).expect("AF_UNIX abstract parses");

        match parsed {
            SockaddrTarget::Unix { address, raw } => {
                assert_eq!(
                    address,
                    UnixAddress::AbstractHex("@hex:6167656e740073616e64626f78".into())
                );
                assert_eq!(raw, bytes);
            }

            other @ SockaddrTarget::Inet { .. } => panic!("expected Unix, got {other:?}"),
        }
    }

    #[test]
    fn parse_unix_sockaddr_abstract_binary_falls_back_to_hex() {
        // Non-UTF-8 or control-byte names keep the `@hex:` form so the key
        // stays byte-stable when there is no printable text to decode.
        let mut bytes = vec![1, 0, 0]; // family + abstract marker

        bytes.extend_from_slice(&[0xFF, 0xAB, 0x01]);
        let parsed = parse_sockaddr(&bytes, bytes.len()).expect("AF_UNIX abstract parses");

        match parsed {
            SockaddrTarget::Unix { address, raw } => {
                assert_eq!(address, UnixAddress::AbstractHex("@hex:ffab01".into()));
                assert_eq!(raw, bytes);
            }

            other @ SockaddrTarget::Inet { .. } => panic!("expected Unix, got {other:?}"),
        }
    }

    #[test]
    fn parse_unix_sockaddr_unnamed_is_none() {
        // AF_UNIX with empty sun_path: unnamed socket.
        let bytes = [1, 0];

        assert_eq!(parse_sockaddr(&bytes, bytes.len()), None);
    }

    #[test]
    fn hex_encode_lower_matches_hex_crate() {
        // Ponytail: inlined encoder must match the canonical lowercase
        // hex alphabet so policyd's @hex: keys are byte-stable.
        assert_eq!(hex_encode_lower(b""), "");

        assert_eq!(hex_encode_lower(&[0x00, 0xFF, 0xAB, 0x10]), "00ffab10");
        assert_eq!(hex_encode_lower(b"agent"), "6167656e74");
    }
}

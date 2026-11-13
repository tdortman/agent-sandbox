//! Emulation of policy-allowed syscalls from their captured arguments.
//!
//! Classification read every decision-relevant tracee argument once (see the
//! library's `capture` module); emulation only consumes those captured values.
//! The one thing it still reads from the tracee is payload bytes, reached
//! through the `iovec` pointer of the captured `msghdr` or the `buf` register
//! of `sendto`, which no decision depends on.

use std::{
    ffi::CString,
    io,
    os::fd::{AsFd, AsRawFd, OwnedFd},
};

use agent_sandbox_core::ResourceKind;
use agent_sandbox_syscall::policy::nr;
use agent_sandbox_syscall_broker::{
    AddfdFailure, FilesystemMutation, FilesystemTarget, MutationDir, PendingNotif, Resolver,
    ResourceCapture, ResourceTarget, SECCOMP_USER_NOTIF_FLAG_CONTINUE, SeccompNotif, UnixCapture,
    read_tracee_bytes,
};
use agent_sandbox_sysutil::{
    connect_raw, ftruncate, is_socket_connected, linkat, mkdirat, mknodat, renameat, sendmsg_raw,
    sendto_raw, socket_type, symlinkat, truncate, unlinkat,
};
use tracing::{debug, info};

/// Largest payload the broker copies out of the tracee for one send.
const MAX_PAYLOAD: usize = 1024 * 1024;

/// Most `iovec` entries a `sendmsg` may carry through emulation.
const MAX_IOVECS: usize = 1024;

/// Size of one `struct iovec`.
const IOVEC_LEN: usize = 16;

/// How an emulated syscall completes.
#[derive(Debug)]
pub enum Completion {
    /// Run the syscall unmodified.
    Continue,

    /// Return this value to the tracee.
    Return(i64),

    /// Fail with this errno.
    Errno(i32),

    /// Install this broker descriptor as the syscall's result.
    InstallFd { fd: OwnedFd, cloexec: bool },
}

fn errno_of(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or(libc::EACCES)
}

/// Answer the notification with `completion`, logging a failed send.
fn complete(pending: PendingNotif, completion: Completion) {
    let sent = match completion {
        Completion::Continue => pending.send_response(0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE),
        Completion::Return(value) => pending.send_response(value, 0, 0),
        Completion::Errno(errno) => pending.send_response(0, -errno, 0),
        // `fd` closes on drop once the kernel has installed its copy.
        Completion::InstallFd { fd, cloexec } => {
            match pending.send_addfd(fd.as_raw_fd(), cloexec) {
                Ok(()) => Ok(()),
                Err(AddfdFailure { error, pending }) => {
                    debug!(error = %error, "installing descriptor failed");
                    pending.send_response(0, -errno_of(&error), 0)
                }
            }
        }
    };

    super::log_notification_response(sent);
}

/// Emulate a policy-allowed resource syscall without continuing it and answer
/// the notification.
///
/// # Errors
///
/// The emulation could not be planned; the notification is already answered
/// with the error's errno, so the error is only for logging.
pub fn resource(
    resolver: &Resolver,
    pending: PendingNotif,
    notif: &SeccompNotif,
    target: &ResourceTarget,
) -> io::Result<()> {
    match plan_resource(resolver, notif, target) {
        Ok(completion) => {
            complete(pending, completion);
            Ok(())
        }
        Err(err) => {
            complete(pending, Completion::Errno(errno_of(&err)));
            Err(err)
        }
    }
}

/// Decide how a policy-allowed resource syscall completes.
pub fn plan_resource(
    resolver: &Resolver,
    notif: &SeccompNotif,
    target: &ResourceTarget,
) -> io::Result<Completion> {
    debug_assert_eq!(
        target.kind == ResourceKind::Device,
        matches!(target.capture, ResourceCapture::Device(_))
    );

    match &target.capture {
        ResourceCapture::Unix(unix) => plan_unix_socket(notif, unix),

        // The broker opens the pinned device with its own privileges and
        // installs the descriptor, so the tracee never re-runs the open with
        // live pointer arguments. `O_CLOEXEC` follows the tracee's request.
        ResourceCapture::Device(device) => Ok(match device.open(resolver, 0) {
            Ok(fd) => Completion::InstallFd {
                fd,
                cloexec: device.flags & libc::O_CLOEXEC != 0,
            },
            Err(err) => Completion::Errno(errno_of(&err)),
        }),
    }
}

/// Whether `sock` is a connected `SOCK_STREAM` / `SOCK_SEQPACKET` socket. The
/// kernel ignores any destination on those, so it is fixed by the approved
/// `connect` and `CONTINUE` cannot be redirected.
fn is_connected_stream(sock: &OwnedFd) -> bool {
    matches!(
        socket_type(sock.as_fd()),
        Some(libc::SOCK_STREAM | libc::SOCK_SEQPACKET)
    ) && is_socket_connected(sock.as_fd())
}

/// Emulate a `connect`/`sendto`/`sendmsg`/`sendmmsg` on a Unix-domain socket
/// the tracee already holds open. The broker duplicates the tracee's socket
/// fd, performs the syscall against the captured destination, and returns the
/// result. A `sendmsg` with control data (e.g. `SCM_RIGHTS`) is denied with
/// `EACCES` because the broker cannot safely relay ancillary data across the
/// pidfd boundary.
fn plan_unix_socket(notif: &SeccompNotif, unix: &UnixCapture) -> io::Result<Completion> {
    let sockfd = i32::try_from(notif.data.args[0]).unwrap_or(-1);

    if sockfd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid sockfd in notification",
        ));
    }

    let dup = agent_sandbox_sysutil::dup_tracee_fd(notif.pid, sockfd)?;
    let nr_val = i64::from(notif.data.nr);

    // The destination was non-null when approved. An empty capture is a
    // broker bug: deny rather than CONTINUE, which would bypass the gate.
    if unix.addr.is_empty() {
        return Ok(Completion::Errno(libc::EACCES));
    }

    match nr_val {
        nr::CONNECT => Ok(match connect_raw(&dup, &unix.addr) {
            Ok(()) => Completion::Return(0),
            Err(err) => Completion::Errno(errno_of(&err)),
        }),

        nr::SENDTO => plan_sendto(notif, &dup, unix),
        nr::SENDMSG => plan_sendmsg(notif, &dup, unix),

        // Multi-message emulation is not supported, and CONTINUE on a
        // datagram or unconnected socket would allow a TOCTOU on the
        // destination.
        nr::SENDMMSG if is_connected_stream(&dup) => Ok(Completion::Continue),

        nr::SENDMMSG => {
            info!("sendmmsg on AF_UNIX denied: multi-message emulation not supported");
            Ok(Completion::Errno(libc::EACCES))
        }

        // Unknown socket syscall, deny to be safe.
        _ => Ok(Completion::Errno(libc::EACCES)),
    }
}

/// Emulate `sendto(sockfd, buf, len, flags, dest_addr, addrlen)` on a
/// duplicated tracee socket, sending to the captured destination.
fn plan_sendto(notif: &SeccompNotif, dup: &OwnedFd, unix: &UnixCapture) -> io::Result<Completion> {
    let buf = notif.data.args[1];
    let len = usize::try_from(notif.data.args[2]).unwrap_or(0);
    let flags = i32::try_from(notif.data.args[3]).unwrap_or(0);

    // The user namespace does NOT share the address space, so tracee
    // pointers are invalid in the broker: copy the payload out.
    if len > MAX_PAYLOAD {
        return Ok(Completion::Errno(libc::E2BIG));
    }

    let payload = read_tracee_bytes(notif.pid, buf, len)?;

    Ok(match sendto_raw(dup, &payload, flags, &unix.addr) {
        Ok(sent) => Completion::Return(i64::try_from(sent).unwrap_or(0)),
        Err(err) => Completion::Errno(errno_of(&err)),
    })
}

/// Emulate `sendmsg(sockfd, msg, flags)` on a duplicated tracee socket from
/// the captured `msghdr` and destination. Control data is denied.
fn plan_sendmsg(notif: &SeccompNotif, dup: &OwnedFd, unix: &UnixCapture) -> io::Result<Completion> {
    let flags = i32::try_from(notif.data.args[2]).unwrap_or(0);

    // The kernel ignores `msg_name` on a connected stream socket, so the
    // destination is fixed by the prior approved connect. This covers the
    // common case of sendmsg with SCM_RIGHTS on a connected stream socket
    // (D-Bus, Wayland fd passing).
    if is_connected_stream(dup) {
        return Ok(Completion::Continue);
    }

    let Some(msghdr) = unix.msghdr else {
        return Ok(Completion::Errno(libc::EACCES));
    };

    if msghdr.has_control() {
        info!("sendmsg with control data denied");
        return Ok(Completion::Errno(libc::EACCES));
    }

    // Copy each iovec's payload from the tracee into broker-owned buffers.
    let iov_count = usize::try_from(msghdr.iov_len)
        .unwrap_or(usize::MAX)
        .min(MAX_IOVECS);
    let vector = read_tracee_bytes(notif.pid, msghdr.iov, iov_count * IOVEC_LEN)?;

    if vector.len() < iov_count * IOVEC_LEN {
        return Ok(Completion::Errno(libc::EINVAL));
    }

    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(iov_count);
    let mut total: usize = 0;

    for iov in vector.as_chunks::<IOVEC_LEN>().0 {
        let (base, len) = iov.split_at(IOVEC_LEN / 2);
        let base = u64::from_ne_bytes(base.try_into().map_err(|_| io::ErrorKind::InvalidData)?);
        let len = u64::from_ne_bytes(len.try_into().map_err(|_| io::ErrorKind::InvalidData)?);
        let len = usize::try_from(len).unwrap_or(usize::MAX);

        total = total.saturating_add(len);

        if total > MAX_PAYLOAD {
            return Ok(Completion::Errno(libc::E2BIG));
        }

        payloads.push(if len == 0 {
            Vec::new()
        } else {
            read_tracee_bytes(notif.pid, base, len)?
        });
    }

    // Broker-owned iovec array pointing into our payloads.
    let mut iovs: Vec<libc::iovec> = payloads
        .iter_mut()
        .map(|buf| libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        })
        .collect();

    // Broker-owned msghdr whose destination is the captured sockaddr.
    let msg = libc::msghdr {
        msg_name: unix.addr.as_ptr().cast::<libc::c_void>().cast_mut(),
        msg_namelen: u32::try_from(unix.addr.len()).unwrap_or(u32::MAX),
        msg_iov: iovs.as_mut_ptr(),
        msg_iovlen: iovs.len(),
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };

    // SAFETY: `msg` is a broker-owned msghdr with iovecs and a captured
    // sockaddr. All pointers are valid for the kernel call.
    #[allow(unsafe_code, reason = "raw seccomp notification iovec construction")]
    let sent = unsafe { sendmsg_raw(dup, &msg, flags) };

    Ok(match sent {
        Ok(sent) => Completion::Return(i64::try_from(sent).unwrap_or(0)),
        Err(err) => Completion::Errno(errno_of(&err)),
    })
}

/// Emulate a captured filesystem mutation and answer the notification.
///
/// # Errors
///
/// The mutation could not be set up; the notification is already answered
/// with the error's errno, so the error is only for logging.
pub fn filesystem_mutation(
    resolver: &Resolver,
    pending: PendingNotif,
    notif: &SeccompNotif,
    target: &FilesystemTarget,
) -> io::Result<()> {
    match apply_mutation(resolver, notif, target) {
        Ok(completion) => {
            complete(pending, completion);
            Ok(())
        }
        Err(err) => {
            complete(pending, Completion::Errno(errno_of(&err)));
            Err(err)
        }
    }
}

fn apply_mutation(
    resolver: &Resolver,
    notif: &SeccompNotif,
    target: &FilesystemTarget,
) -> io::Result<Completion> {
    fn cstring(bytes: &[u8]) -> io::Result<CString> {
        CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }

    /// Absolute name of `path` for syscalls that take no directory argument.
    fn path_at(resolver: &Resolver, dir: &MutationDir, path: &[u8]) -> Vec<u8> {
        if path.starts_with(b"/") {
            return path.to_vec();
        }

        let mut resolved = resolver
            .self_fd(dir.as_fd())
            .into_os_string()
            .into_encoded_bytes();
        resolved.push(b'/');
        resolved.extend_from_slice(path);
        resolved
    }

    let result = match &target.operation {
        FilesystemMutation::Rename {
            old_dir,
            old,
            new_dir,
            new,
            flags,
        } => {
            let old = cstring(old)?;
            let new = cstring(new)?;
            renameat(old_dir, &old, new_dir, &new, *flags)
        }
        FilesystemMutation::Link {
            old_dir,
            old,
            new_dir,
            new,
            flags,
        } => {
            let old = cstring(old)?;
            let new = cstring(new)?;
            linkat(old_dir, &old, new_dir, &new, flags.cast_signed())
        }
        FilesystemMutation::LinkFd {
            fd,
            new_dir,
            new,
            flags,
        } => {
            let old = cstring(resolver.self_fd(fd.as_fd()).as_os_str().as_encoded_bytes())?;
            let new = cstring(new)?;
            linkat(&MutationDir::Root, &old, new_dir, &new, flags.cast_signed())
        }
        FilesystemMutation::Symlink {
            target,
            link_dir,
            link,
        } => {
            let target = cstring(target)?;
            let link = cstring(link)?;
            symlinkat(&target, link_dir, &link)
        }
        FilesystemMutation::Unlink { dir, path, flags } => {
            let path = cstring(path)?;
            unlinkat(dir, &path, flags.cast_signed())
        }
        FilesystemMutation::Truncate { dir, path, len } => {
            let path = cstring(&path_at(resolver, dir, path))?;
            truncate(&path, *len as libc::off_t)
        }
        FilesystemMutation::Ftruncate { fd, len } => ftruncate(fd, *len as libc::off_t),
        FilesystemMutation::Mkdir { dir, path, mode } => {
            let path = cstring(path)?;
            mkdirat(dir, &path, *mode as libc::mode_t)
        }
        FilesystemMutation::Rmdir { dir, path } => {
            let path = cstring(path)?;
            unlinkat(dir, &path, libc::AT_REMOVEDIR)
        }
        FilesystemMutation::Mknod {
            dir,
            path,
            mode,
            device,
        } => {
            let path = cstring(path)?;
            mknodat(dir, &path, *mode as libc::mode_t, *device as libc::dev_t)
        }
    };

    let completion = match result {
        Ok(()) => Completion::Return(0),
        Err(err) => {
            debug!(
                error = %err,
                operation = ?target.operation,
                pid = notif.pid,
                "filesystem mutation syscall failed"
            );
            Completion::Errno(errno_of(&err))
        }
    };

    Ok(completion)
}

#[cfg(test)]
mod tests {
    use std::{
        os::{fd::AsRawFd, unix::net::UnixDatagram},
        path::PathBuf,
    };

    use agent_sandbox_syscall::policy::nr;
    use agent_sandbox_syscall_broker::{
        Resolver, ResourceCapture, ResourceTarget, SeccompData, SeccompNotif, SyscallTarget,
        target_from_notification,
    };

    use super::{Completion, plan_resource};

    struct Fixture {
        dir: PathBuf,
        approved: UnixDatagram,
        other: UnixDatagram,
        client: UnixDatagram,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("broker-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create socket dir");
            let dir = dir.canonicalize().expect("canonical socket dir");
            let bind = |name: &str| {
                let socket = UnixDatagram::bind(dir.join(name)).expect("bind listener");
                socket.set_nonblocking(true).expect("nonblocking listener");
                socket
            };

            Self {
                approved: bind("approved.sock"),
                other: bind("other.sock"),
                client: UnixDatagram::unbound().expect("client socket"),
                dir,
            }
        }

        /// Replace the approved name with a different socket, as a tracee
        /// racing the broker could.
        fn swap_approved_name(&self) -> UnixDatagram {
            std::fs::remove_file(self.dir.join("approved.sock")).expect("remove approved name");
            let impostor = UnixDatagram::bind(self.dir.join("approved.sock")).expect("rebind");
            impostor
                .set_nonblocking(true)
                .expect("nonblocking impostor");
            impostor
        }

        /// A `sockaddr_un` naming `file` in the fixture directory.
        fn sockaddr(&self, file: &str) -> Vec<u8> {
            let mut addr = u16::try_from(libc::AF_UNIX)
                .expect("AF_UNIX fits sa_family_t")
                .to_ne_bytes()
                .to_vec();
            addr.extend_from_slice(self.dir.join(file).as_os_str().as_encoded_bytes());
            addr.push(0);
            addr
        }

        fn notif(&self, syscall: i64, args: [u64; 6]) -> SeccompNotif {
            let mut args = args;
            args[0] = u64::try_from(self.client.as_raw_fd()).expect("fd");

            SeccompNotif {
                pid: std::process::id(),
                data: SeccompData {
                    nr: i32::try_from(syscall).expect("syscall number"),
                    args,
                    ..SeccompData::default()
                },
                ..SeccompNotif::default()
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn classify(notif: &SeccompNotif) -> ResourceTarget {
        let Some(SyscallTarget::Resource(target)) =
            target_from_notification(&Resolver::default(), notif).expect("classify")
        else {
            panic!("expected a unix socket resource target");
        };
        target
    }

    fn received(socket: &UnixDatagram) -> Option<Vec<u8>> {
        let mut buf = [0_u8; 64];
        socket.recv(&mut buf).ok().map(|len| buf[..len].to_vec())
    }

    fn sent_bytes(completion: &Completion) -> i64 {
        let Completion::Return(sent) = completion else {
            panic!("expected the emulated send to return, got {completion:?}");
        };
        *sent
    }

    #[test]
    fn sendto_emulation_sends_to_the_classified_socket() {
        let fixture = Fixture::new("sendto");
        let payload = b"hello".to_vec();
        let mut addr = fixture.sockaddr("approved.sock");
        let notif = fixture.notif(nr::SENDTO, [
            0,
            payload.as_ptr() as u64,
            payload.len() as u64,
            0,
            addr.as_ptr() as u64,
            addr.len() as u64,
        ]);

        let target = classify(&notif);

        // After classification the tracee retargets its sockaddr and the
        // approved name is rebound to another socket.
        let other = fixture.sockaddr("other.sock");
        addr[2..other.len()].copy_from_slice(&other[2..]);
        let impostor = fixture.swap_approved_name();

        let sent = sent_bytes(
            &plan_resource(&Resolver::default(), &notif, &target).expect("emulate sendto"),
        );

        assert_eq!(sent, 5);
        assert_eq!(received(&fixture.approved), Some(payload));
        assert_eq!(
            received(&fixture.other),
            None,
            "retargeted socket gets nothing"
        );
        assert_eq!(received(&impostor), None, "rebound name gets nothing");
    }

    #[test]
    fn sendmsg_emulation_sends_to_the_classified_socket() {
        let fixture = Fixture::new("sendmsg");
        let payload = b"world".to_vec();
        let iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let mut addr = fixture.sockaddr("approved.sock");
        let mut msg = libc::msghdr {
            msg_name: addr.as_mut_ptr().cast(),
            msg_namelen: u32::try_from(addr.len()).expect("addrlen"),
            msg_iov: (&raw const iov).cast_mut(),
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let notif = fixture.notif(nr::SENDMSG, [0, (&raw const msg) as u64, 0, 0, 0, 0]);

        let target = classify(&notif);
        let ResourceCapture::Unix(unix) = &target.capture else {
            panic!("socket target carries a unix capture");
        };
        assert!(
            unix.msghdr.is_some(),
            "msghdr captured with the destination"
        );

        // The tracee rewrites msg_name, adds ancillary data and swaps the name.
        let other = fixture.sockaddr("other.sock");
        addr[2..other.len()].copy_from_slice(&other[2..]);
        let mut fd_payload = [0_u8; 16];
        msg.msg_control = fd_payload.as_mut_ptr().cast();
        msg.msg_controllen = fd_payload.len();
        // The raw pointer in the notification is what the broker reads.
        std::hint::black_box(&msg);
        let impostor = fixture.swap_approved_name();

        let sent = sent_bytes(
            &plan_resource(&Resolver::default(), &notif, &target).expect("emulate sendmsg"),
        );

        assert_eq!(sent, 5);
        assert_eq!(received(&fixture.approved), Some(payload));
        assert_eq!(received(&fixture.other), None);
        assert_eq!(received(&impostor), None);
    }

    #[test]
    fn sendmsg_with_control_data_is_denied_from_the_captured_header() {
        let fixture = Fixture::new("sendmsg-control");
        let payload = b"x".to_vec();
        let iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let mut addr = fixture.sockaddr("approved.sock");
        let mut control = [0_u8; 24];
        let msg = libc::msghdr {
            msg_name: addr.as_mut_ptr().cast(),
            msg_namelen: u32::try_from(addr.len()).expect("addrlen"),
            msg_iov: (&raw const iov).cast_mut(),
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr().cast(),
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        let notif = fixture.notif(nr::SENDMSG, [0, (&raw const msg) as u64, 0, 0, 0, 0]);

        let target = classify(&notif);
        let completion =
            plan_resource(&Resolver::default(), &notif, &target).expect("emulate sendmsg");

        assert!(matches!(completion, Completion::Errno(libc::EACCES)));
        assert_eq!(received(&fixture.approved), None);
    }

    #[test]
    fn sendmmsg_names_a_destination_wherever_it_appears_in_the_batch() {
        let fixture = Fixture::new("sendmmsg");
        let payload = b"batch".to_vec();
        let iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let addr = fixture.sockaddr("approved.sock");
        let header = |named: bool| libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: if named {
                    addr.as_ptr().cast_mut().cast()
                } else {
                    std::ptr::null_mut()
                },
                msg_namelen: if named {
                    u32::try_from(addr.len()).expect("addrlen")
                } else {
                    0
                },
                msg_iov: (&raw const iov).cast_mut(),
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        };
        let batch = [header(false), header(true)];
        let notif = fixture.notif(nr::SENDMMSG, [0, batch.as_ptr() as u64, 2, 0, 0, 0]);

        let target = classify(&notif);

        assert_eq!(
            target.path,
            fixture.dir.join("approved.sock"),
            "an unaddressed first message must not hide the destination"
        );
    }

    #[test]
    fn sendmmsg_to_two_destinations_is_denied() {
        let fixture = Fixture::new("sendmmsg-split");
        let payload = b"batch".to_vec();
        let iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let approved = fixture.sockaddr("approved.sock");
        let other = fixture.sockaddr("other.sock");
        let header = |addr: &[u8]| libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: addr.as_ptr().cast_mut().cast(),
                msg_namelen: u32::try_from(addr.len()).expect("addrlen"),
                msg_iov: (&raw const iov).cast_mut(),
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        };
        let batch = [header(&approved), header(&other)];
        let notif = fixture.notif(nr::SENDMMSG, [0, batch.as_ptr() as u64, 2, 0, 0, 0]);

        assert!(matches!(
            target_from_notification(&Resolver::default(), &notif),
            Ok(Some(SyscallTarget::Errno(libc::EACCES)))
        ));
    }
}

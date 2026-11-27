use std::{
    io::{BufRead, BufReader, Write},
    os::{
        fd::AsFd,
        unix::net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    thread::JoinHandle,
};

use agent_sandbox_core::{ErrorReply, RequestContext, RpcMessage, RpcReply, SimpleOkReply};
use agent_sandbox_sysutil::{recv_with_fds, send_fd};
use nix::sys::{
    pthread::{pthread_kill, pthread_self},
    signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction},
};

use super::{Endpoint, ShimError, mount, unmount, unmount_when_client_exits};

/// A stand-in for policyd that answers one request.
struct FakeDaemon {
    thread: JoinHandle<serde_json::Value>,
}

impl FakeDaemon {
    /// Serve one connection: record the request line, then send
    /// `descriptor_first` as a lone newline with a descriptor, a heartbeat,
    /// and `reply`.
    fn serve(socket: &Path, reply: RpcReply, descriptor_first: bool) -> Self {
        Self::serve_after(socket, reply, descriptor_first, || {})
    }

    /// [`Self::serve`], running `before_reply` once the request is read.
    fn serve_after(
        socket: &Path,
        reply: RpcReply,
        descriptor_first: bool,
        before_reply: impl FnOnce() + Send + 'static,
    ) -> Self {
        let listener = UnixListener::bind(socket).expect("bind fake policyd");

        let thread = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut line = String::new();

            BufReader::new(&conn)
                .read_line(&mut line)
                .expect("read request");

            before_reply();

            if descriptor_first {
                let null = std::fs::File::open("/dev/null").expect("open /dev/null");
                send_fd(&conn, b"\n", null.as_fd()).expect("send descriptor");
            }

            conn.write_all(b"{\"type\":\"heartbeat\"}\n")
                .expect("heartbeat");
            conn.write_all(
                RpcMessage::Reply(reply)
                    .encode_line()
                    .expect("encode")
                    .as_bytes(),
            )
            .expect("reply");

            serde_json::from_str(&line).expect("request is JSON")
        });

        Self { thread }
    }

    fn request(self) -> serde_json::Value {
        self.thread.join().expect("fake policyd")
    }
}

fn endpoint(socket: PathBuf) -> Endpoint {
    Endpoint {
        socket,
        ctx: RequestContext {
            sandbox_session_id: Some("sandbox-test".into()),
            ..RequestContext::default()
        },
        require_foreign_listener: false,
    }
}

#[test]
fn mount_forwards_the_descriptor_to_the_fuse_client() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("policy.sock");
    let daemon = FakeDaemon::serve(&socket, RpcReply::Simple(SimpleOkReply::OK), true);
    let (shim_end, client_end) = UnixStream::pair().expect("comm socket pair");

    mount(
        &endpoint(socket),
        Path::new("/home/u/mnt"),
        "ro,fsname=x",
        shim_end.as_fd(),
    )
    .expect("mount");

    let request = daemon.request();

    assert_eq!(request["op"], "fuse_mount");
    assert_eq!(request["mountpoint"], "/home/u/mnt");
    assert_eq!(request["options"], "ro,fsname=x");
    assert_eq!(request["heartbeat"], true);
    assert_eq!(request["ctx"]["sandbox_session_id"], "sandbox-test");

    let mut data = [0_u8; 4];
    let received = recv_with_fds(&client_end, &mut data).expect("client receives");

    assert_eq!(received.len, 1);
    assert_eq!(received.fds.len(), 1);

    let null = rustix::fs::stat("/dev/null").expect("stat /dev/null");
    let passed = rustix::fs::fstat(&received.fds[0]).expect("stat passed descriptor");

    assert_eq!(
        (passed.st_rdev, passed.st_mode),
        (null.st_rdev, null.st_mode)
    );
}

/// A signal reaching the shim while it waits for the reply interrupts its
/// receive, as a freeze of the sandbox's cgroup does while the mount waits on
/// an approval prompt. The shim keeps waiting and mounts.
#[test]
fn interrupted_wait_for_the_reply_still_mounts() {
    extern "C" fn ignore(_: nix::libc::c_int) {}

    // SA_RESTART would restart a receive without a timeout; the shim's
    // timeout makes the kernel fail it with EINTR, as on a cgroup thaw.
    let action = SigAction::new(
        SigHandler::Handler(ignore),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );

    // SAFETY: the handler does nothing, so it is async-signal-safe.
    #[allow(unsafe_code, reason = "installing a signal handler is unsafe")]
    let installed = unsafe { sigaction(Signal::SIGUSR1, &action) };
    installed.expect("install a SIGUSR1 handler");

    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("policy.sock");
    let shim_thread = pthread_self();
    let shim_syscall = format!(
        "/proc/self/task/{}/syscall",
        rustix::thread::gettid().as_raw_nonzero()
    );

    let daemon = FakeDaemon::serve_after(
        &socket,
        RpcReply::Simple(SimpleOkReply::OK),
        true,
        move || {
            let recvmsg = nix::libc::SYS_recvmsg.to_string();

            while std::fs::read_to_string(&shim_syscall)
                .expect("read the shim's syscall")
                .split_whitespace()
                .next()
                != Some(recvmsg.as_str())
            {
                std::thread::yield_now();
            }

            pthread_kill(shim_thread, Signal::SIGUSR1).expect("signal the shim");
        },
    );

    let (shim_end, client_end) = UnixStream::pair().expect("comm socket pair");

    mount(
        &endpoint(socket),
        Path::new("/home/u/mnt"),
        "",
        shim_end.as_fd(),
    )
    .expect("mount");

    daemon.request();

    let mut data = [0_u8; 4];
    let received = recv_with_fds(&client_end, &mut data).expect("client receives");

    assert_eq!(received.fds.len(), 1);
}

#[test]
fn refused_mount_sends_nothing_to_the_client() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("policy.sock");

    let daemon = FakeDaemon::serve(
        &socket,
        RpcReply::Error(ErrorReply::new("mountpoint must not contain symlinks")),
        false,
    );

    let (shim_end, client_end) = UnixStream::pair().expect("comm socket pair");

    let error = mount(&endpoint(socket), Path::new("/x"), "", shim_end.as_fd())
        .expect_err("policyd refuses");

    daemon.request();

    assert!(
        matches!(&error, ShimError::Refused(reason) if reason == "mountpoint must not contain symlinks"),
        "{error:?}"
    );

    client_end.set_nonblocking(true).expect("nonblocking");

    let mut data = [0_u8; 4];

    assert_eq!(
        recv_with_fds(&client_end, &mut data)
            .err()
            .map(|err| err.kind()),
        Some(std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn mount_without_a_descriptor_is_a_protocol_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("policy.sock");
    let daemon = FakeDaemon::serve(&socket, RpcReply::Simple(SimpleOkReply::OK), false);
    let (shim_end, _client_end) = UnixStream::pair().expect("comm socket pair");

    let error =
        mount(&endpoint(socket), Path::new("/x"), "", shim_end.as_fd()).expect_err("no descriptor");

    daemon.request();

    assert!(matches!(error, ShimError::Protocol), "{error:?}");
}

#[test]
fn lazy_unmount_request_names_the_mountpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("policy.sock");
    let daemon = FakeDaemon::serve(&socket, RpcReply::Simple(SimpleOkReply::OK), false);

    unmount(&endpoint(socket), Path::new("/home/u/mnt"), true).expect("unmount");

    let request = daemon.request();

    assert_eq!(request["op"], "fuse_unmount");
    assert_eq!(request["mountpoint"], "/home/u/mnt");
    assert_eq!(request["lazy"], true);
}

#[test]
fn auto_unmount_waits_for_the_client_to_close_its_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("policy.sock");
    let daemon = FakeDaemon::serve(&socket, RpcReply::Simple(SimpleOkReply::OK), false);
    let (shim_end, client_end) = UnixStream::pair().expect("comm socket pair");
    let endpoint = endpoint(socket);

    let waiter = std::thread::spawn(move || {
        unmount_when_client_exits(&endpoint, Path::new("/home/u/mnt"), shim_end.as_fd())
    });

    assert!(!waiter.is_finished());
    drop(client_end);
    waiter.join().expect("waiter thread").expect("auto unmount");

    assert_eq!(daemon.request()["lazy"], true);
}

#[test]
fn listener_running_as_the_sandbox_user_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("policy.sock");
    let _listener = UnixListener::bind(&socket).expect("bind impostor");
    let (shim_end, _client_end) = UnixStream::pair().expect("comm socket pair");

    let strict = Endpoint {
        require_foreign_listener: true,
        ..endpoint(socket)
    };

    assert!(matches!(
        mount(&strict, Path::new("/x"), "", shim_end.as_fd()),
        Err(ShimError::UntrustedListener)
    ));
}

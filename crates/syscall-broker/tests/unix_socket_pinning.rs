//! Security regression: a filesystem `AF_UNIX` target is pinned when the
//! broker classifies the syscall. The policy key and the emulated connect both
//! name the socket the calling thread resolved, regardless of the broker's
//! cwd or path changes made before emulation.

use std::{
    io::ErrorKind,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixListener,
    },
    path::{Path, PathBuf},
    sync::mpsc,
};

use agent_sandbox_syscall::policy::nr;
use agent_sandbox_syscall_broker::{
    ResourceTarget, SeccompData, SeccompNotif, SyscallTarget, target_from_notification,
};
use nix::{
    sched::CloneFlags,
    sys::socket::{AddressFamily, SockFlag, SockType, socket},
};

fn socket_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("agent-sandbox-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create socket dir");
    dir.canonicalize().expect("canonical socket dir")
}

fn listener(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    listener
}

fn client_socket() -> OwnedFd {
    socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .expect("client socket")
}

/// Classify `connect(client, sun_path)` as issued by a thread whose cwd is
/// `cwd`. This thread (the broker side) keeps the process cwd. The calling
/// thread exits before this returns, so emulation cannot rely on it.
fn classify_connect(cwd: &Path, sun_path: &str, client: &OwnedFd) -> ResourceTarget {
    let (tid_tx, tid_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let tracee = std::thread::spawn({
        let cwd = cwd.to_path_buf();
        move || {
            nix::sched::unshare(CloneFlags::CLONE_FS).expect("unshare fs");
            std::env::set_current_dir(&cwd).expect("chdir tracee");
            tid_tx
                .send(nix::unistd::gettid().as_raw())
                .expect("send tid");
            done_rx.recv().ok();
        }
    });
    let tid = tid_rx.recv().expect("tracee tid");
    assert_ne!(std::env::current_dir().expect("broker cwd"), cwd);

    let mut addr = u16::try_from(libc::AF_UNIX)
        .expect("AF_UNIX fits sa_family_t")
        .to_ne_bytes()
        .to_vec();
    addr.extend_from_slice(sun_path.as_bytes());
    addr.push(0);

    let notif = SeccompNotif {
        pid: tid.cast_unsigned(),
        data: SeccompData {
            nr: i32::try_from(nr::CONNECT).expect("syscall number fits"),
            args: [
                u64::try_from(client.as_raw_fd()).expect("fd is non-negative"),
                addr.as_ptr() as u64,
                u64::try_from(addr.len()).expect("addrlen fits"),
                0,
                0,
                0,
            ],
            ..SeccompData::default()
        },
        ..SeccompNotif::default()
    };

    let target = target_from_notification(&notif).expect("classify connect");
    done_tx.send(()).expect("release tracee");
    tracee.join().expect("tracee joins");

    let Some(SyscallTarget::Resource(target)) = target else {
        panic!("expected unix socket resource target, got {target:?}");
    };
    target
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn relative_unix_connect_reaches_socket_in_tracee_cwd() {
    let dir = socket_dir("relsock");
    let socket_path = dir.join("rel.sock");
    let approved = listener(&socket_path);
    let client = client_socket();

    let target = classify_connect(&dir, "rel.sock", &client);

    assert_eq!(target.path, socket_path);
    agent_sandbox_sysutil::connect_raw(&client, &target.raw)
        .expect("emulated connect reaches the tracee-relative socket");
    approved.accept().expect("listener receives the connection");

    std::fs::remove_dir_all(&dir).expect("remove socket dir");
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn socket_swapped_after_classification_does_not_redirect_connect() {
    let dir = socket_dir("swapsock");
    let real = dir.join("real");
    std::fs::create_dir(&real).expect("create real dir");
    let alias = dir.join("alias");
    std::os::unix::fs::symlink(&real, &alias).expect("alias -> real");
    let approved = listener(&real.join("agent.sock"));
    let client = client_socket();

    let target = classify_connect(&dir, &alias.join("agent.sock").to_string_lossy(), &client);
    assert_eq!(target.path, real.join("agent.sock"));

    // Before emulation, repoint the alias at a different socket of the same
    // name.
    let other = dir.join("other");
    std::fs::create_dir(&other).expect("create other dir");
    let redirected = listener(&other.join("agent.sock"));
    std::fs::remove_file(&alias).expect("remove alias");
    std::os::unix::fs::symlink(&other, &alias).expect("alias -> other");

    agent_sandbox_sysutil::connect_raw(&client, &target.raw)
        .expect("emulated connect reaches the approved socket");
    approved
        .accept()
        .expect("approved listener receives the connection");
    assert_eq!(
        redirected
            .accept()
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(ErrorKind::WouldBlock),
        "swapped-in listener must not receive the connection"
    );

    std::fs::remove_dir_all(&dir).expect("remove socket dir");
}

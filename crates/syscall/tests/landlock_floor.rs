//! Security regression: a syscall the broker continues re-reads its pointer
//! arguments, so another tracee thread can swap the path or socket address
//! after the broker classified it. The Landlock floor must keep such syscalls
//! away from gated device nodes and from UNIX sockets outside the sandbox,
//! while ordinary files, ungated devices, and the policy socket keep working.

use std::{
    io::ErrorKind,
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::Command,
};

const PROBE_DIR: &str = "AGENT_SANDBOX_FLOOR_PROBE_DIR";
const PROBE_PTY: &str = "AGENT_SANDBOX_FLOOR_PROBE_PTY";
const PROBE_ABSTRACT: &str = "AGENT_SANDBOX_FLOOR_PROBE_ABSTRACT";
const TEST_NAME: &str = "floor_blocks_gated_targets_and_keeps_ordinary_access";

#[test]
fn floor_blocks_gated_targets_and_keeps_ordinary_access() {
    if let Ok(dir) = std::env::var(PROBE_DIR) {
        let pty = std::env::var(PROBE_PTY).expect("pty path");
        let abstract_name = std::env::var(PROBE_ABSTRACT).expect("abstract name");
        probe(Path::new(&dir), Path::new(&pty), &abstract_name);
        return;
    }

    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("data"), "ordinary").expect("write data file");
    let _policy = UnixListener::bind(dir.path().join("policy.sock")).expect("bind policy socket");
    let _other = UnixListener::bind(dir.path().join("other.sock")).expect("bind other socket");

    let abstract_name = format!("agent-sandbox-floor-{}", std::process::id());
    let _abstract = UnixListener::bind_addr(
        &SocketAddr::from_abstract_name(&abstract_name).expect("abstract address"),
    )
    .expect("bind abstract socket");

    // A terminal the confined process does not hold, standing in for another
    // pane's pty.
    let pty = nix::pty::openpty(None, None).expect("openpty");
    let pty_path: PathBuf = nix::unistd::ttyname(&pty.slave).expect("pty name");

    // The floor binds the calling thread for good, so it runs in a fresh
    // process: this test binary, filtered to this test.
    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(PROBE_DIR, dir.path())
        .env(PROBE_PTY, &pty_path)
        .env(PROBE_ABSTRACT, &abstract_name)
        .output()
        .expect("run confined probe");

    assert!(
        output.status.success(),
        "confined probe failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn probe(dir: &Path, pty: &Path, abstract_name: &str) {
    agent_sandbox_syscall::floor::restrict_self(&dir.join("policy.sock"))
        .expect("kernel supports the Landlock floor");

    let err = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pty)
        .expect_err("a terminal outside the floor stays closed");
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);

    let err = UnixStream::connect(dir.join("other.sock"))
        .expect_err("a pathname socket created outside the sandbox stays closed");
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);

    let address = SocketAddr::from_abstract_name(abstract_name).expect("abstract address");
    UnixStream::connect_addr(&address)
        .expect_err("an abstract socket created outside the sandbox stays closed");

    UnixStream::connect(dir.join("policy.sock")).expect("the policy socket stays reachable");
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("ungated devices stay open");
    assert_eq!(
        std::fs::read_to_string(dir.join("data")).expect("ordinary files stay readable"),
        "ordinary"
    );
}

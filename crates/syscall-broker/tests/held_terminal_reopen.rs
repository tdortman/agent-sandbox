//! Security regression: a sandboxed process may reopen its own terminal by
//! path without a policy prompt, but never a terminal it does not hold.

use std::{
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use agent_sandbox_syscall_broker::{DeviceCapture, Resolver, reopen_held_terminal};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    pty::openpty,
    unistd::ttyname,
};

/// Ask whether the tracee `pid` may reopen the terminal at `path`, as the
/// broker does for a classified `open(path, O_RDWR)`.
fn reopen(pid: u32, path: &Path) -> Option<OwnedFd> {
    let pinned = nix::fcntl::open(
        path,
        OFlag::O_PATH | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .expect("pin terminal");
    let device = DeviceCapture {
        pinned,
        flags: libc::O_RDWR | libc::O_CLOEXEC,
        mode: 0,
    };

    reopen_held_terminal(&Resolver::default(), pid, path, &device)
}

/// A pty pair whose descriptors the spawned tracee does not inherit.
struct PrivatePty {
    /// The `/dev/ptmx` side.
    controller: OwnedFd,
    /// The `/dev/pts/N` side.
    terminal: OwnedFd,
    terminal_path: PathBuf,
}

fn private_pty() -> PrivatePty {
    let pty = openpty(None, None).expect("openpty");
    for fd in [pty.master.as_fd(), pty.slave.as_fd()] {
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).expect("set cloexec");
    }
    let terminal_path = ttyname(&pty.slave).expect("terminal name");

    PrivatePty {
        controller: pty.master,
        terminal: pty.slave,
        terminal_path,
    }
}

/// Run `sleep` with `held` as its stdin, the only descriptor it holds to a pty.
fn tracee_holding(held: OwnedFd) -> Child {
    Command::new("sleep")
        .arg("30")
        .stdin(Stdio::from(held))
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn tracee")
}

fn assert_is_terminal(reopened: Option<OwnedFd>, path: &Path) {
    let reopened = std::fs::File::from(reopened.expect("held terminal reopens without policy"));
    let opened = reopened.metadata().expect("stat reopened terminal");
    let expected = std::fs::metadata(path).expect("stat terminal");
    assert_eq!(opened.dev(), expected.dev(), "same devpts instance");
    assert_eq!(opened.ino(), expected.ino(), "same terminal");
}

#[test]
fn tracee_reopens_only_the_terminal_it_holds() {
    let own = private_pty();
    let other = private_pty();

    let mut tracee = tracee_holding(own.terminal.try_clone().expect("dup own terminal"));
    let reopened = reopen(tracee.id(), &own.terminal_path);
    let foreign = reopen(tracee.id(), &other.terminal_path);
    tracee.kill().expect("kill tracee");
    tracee.wait().expect("reap tracee");

    assert_is_terminal(reopened, &own.terminal_path);
    assert!(
        foreign.is_none(),
        "a terminal the tracee does not hold stays policy-gated"
    );
}

#[test]
fn tracee_holding_a_controller_opens_only_its_own_terminal() {
    let own = private_pty();
    let other = private_pty();

    let mut tracee = tracee_holding(own.controller.try_clone().expect("dup own controller"));
    let reopened = reopen(tracee.id(), &own.terminal_path);
    let foreign = reopen(tracee.id(), &other.terminal_path);
    tracee.kill().expect("kill tracee");
    tracee.wait().expect("reap tracee");

    assert_is_terminal(reopened, &own.terminal_path);
    assert!(
        foreign.is_none(),
        "another pty's terminal stays policy-gated"
    );
}

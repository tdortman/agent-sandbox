//! Seccomp-BPF arming CLI used with an external sandbox loader.
//!
//! Loads a syscall allow-list filter (optionally including filesystem
//! syscalls) into the calling thread, then `exec`s a child command. Intended
//! for runtime environments the loader cannot prepare itself (e.g. a foreign
//! architecture or nested sandbox), where the filter is armed in a non-Rust
//! process and a command is launched under it.
use std::{
    env,
    ffi::{CStr, CString, OsString},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    process,
};

use agent_sandbox_syscall::{build_filter, default_syscalls, syscalls_without_filesystem};
use agent_sandbox_sysutil::{install_seccomp_notify, pidfd_getfd, pidfd_open, pre_exec_fork};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    sys::{
        prctl::set_no_new_privs,
        signal::{Signal, raise},
    },
    unistd::{ForkResult, Pid, execvp, pipe2},
};

const DEFAULT_POLICY_SOCKET: &str = "/run/agent-sandbox/policy.sock";
const HELP: &str = "Usage: agent-sandbox-syscall-arm [OPTIONS] [COMMAND]...

Options:
  --filesystem  Include filesystem syscalls in the notification filter
  -h, --help    Print help

Everything after the flags is forwarded verbatim to COMMAND.
The broker uses AGENT_SANDBOX_POLICY_SOCKET when set.
";

fn die(msg: &str) -> ! {
    eprintln!(
        "agent-sandbox-syscall-arm: {msg}: {}",
        std::io::Error::last_os_error()
    );

    process::exit(1);
}

fn cstring(bytes: &[u8]) -> CString {
    CString::new(bytes).unwrap_or_else(|_| {
        eprintln!("agent-sandbox-syscall-arm: argument contains interior NUL");
        process::exit(1);
    })
}

fn install_filter(include_filesystem: bool) -> OwnedFd {
    set_no_new_privs()
        .map_err(|_| ())
        .unwrap_or_else(|()| die("prctl PR_SET_NO_NEW_PRIVS failed"));

    let syscalls = if include_filesystem {
        default_syscalls()
    } else {
        syscalls_without_filesystem()
    };

    let filter = build_filter(&syscalls);

    // `seccompiler::BpfProgram` is `Vec<seccompiler::sock_filter>`. The
    // seccomp syscall takes a `*mut libc::sock_filter`, both struct types
    // are `#[repr(C)]` with identical field layout (code: u16, jt: u8,
    // jf: u8, k: u32), so the pointer cast is sound. The wrapper statically
    // asserts the size match in `bpf.rs`.
    let mut prog = libc::sock_fprog {
        len: u16::try_from(filter.len()).unwrap_or(u16::MAX),
        filter: filter.as_ptr().cast::<libc::sock_filter>().cast_mut(),
    };

    install_seccomp_notify(&mut prog)
        .unwrap_or_else(|_| die("seccomp user notification install failed"))
}

fn exec_command(os_args: &[OsString]) -> ! {
    let cargs: Vec<CString> = os_args
        .iter()
        .map(|arg| cstring(arg.as_os_str().as_bytes()))
        .collect();

    let cstr_refs: Vec<&CStr> = cargs.iter().map(CString::as_c_str).collect();

    let _ = execvp(&cargs[0], &cstr_refs)
        .map_err(|_| die("execvp command failed"))
        .map(|never| match never {});

    die("execvp command failed");
}

fn exec_broker(listener_fd: &impl AsRawFd, child_pid: Pid) -> ! {
    let broker = cstring(b"agent-sandbox-syscall-broker");
    let fd_arg = listener_fd.as_raw_fd().to_string();
    let child_arg = child_pid.as_raw().to_string();

    let policy_socket = env::var("AGENT_SANDBOX_POLICY_SOCKET")
        .unwrap_or_else(|_| DEFAULT_POLICY_SOCKET.to_string());

    let mut broker_args = vec![
        cstring(b"agent-sandbox-syscall-broker"),
        cstring(b"--listener-fd"),
        cstring(fd_arg.as_bytes()),
        cstring(b"--child-pid"),
        cstring(child_arg.as_bytes()),
        cstring(b"--policy-socket"),
        cstring(policy_socket.as_bytes()),
    ];

    if let Ok(session) = env::var("AGENT_SANDBOX_SESSION_ID") {
        broker_args.push(cstring(b"--sandbox-session-id"));
        broker_args.push(cstring(session.as_bytes()));
    }

    let cstr_refs: Vec<&CStr> = broker_args.iter().map(CString::as_c_str).collect();

    let _ = execvp(&broker, &cstr_refs)
        .map_err(|_| die("execvp broker failed"))
        .map(|never| match never {});

    die("execvp broker failed");
}

fn main() {
    let mut include_filesystem = false;
    let mut command: Vec<OsString> = Vec::new();
    let mut only_command = false;
    for arg in env::args_os().skip(1) {
        if !only_command && (arg == "--help" || arg == "-h") {
            print!("{HELP}");
            return;
        } else if !only_command && arg == "--filesystem" {
            include_filesystem = true;
        } else if !only_command && arg == "--" {
            only_command = true;
        } else {
            only_command = true;
            command.push(arg);
        }
    }

    if command.is_empty() {
        eprintln!(
            "agent-sandbox-syscall-arm: missing command\n\nUSAGE:\nagent-sandbox-syscall-arm [--] \
             <command> [args...]"
        );

        process::exit(2);
    }

    let (read_end, write_end) = pipe2(OFlag::O_CLOEXEC).unwrap_or_else(|_| die("pipe2 failed"));
    let fork_result = pre_exec_fork().unwrap_or_else(|_| die("fork failed"));

    match fork_result {
        ForkResult::Child => {
            // Child: drop the read end (we only write our side), install the
            // seccomp filter, hand the listener fd NUMBER to the parent, raise
            // SIGSTOP so the parent can re-acquire the listener fd via
            // pidfd_getfd before the command execs, then exec.
            drop(read_end);
            let listener_fd = install_filter(include_filesystem);
            let mut pipe = std::fs::File::from(write_end);
            pipe.write_all(format!("{}\n", listener_fd.as_raw_fd()).as_bytes())
                .unwrap_or_else(|_| die("writing listener fd to handoff pipe failed"));
            raise(Signal::SIGSTOP)
                .map_err(|_| ())
                .unwrap_or_else(|()| die("raise SIGSTOP failed"));
            exec_command(&command);
        }

        ForkResult::Parent { child } => {
            // Parent: drop the write end, read the listener fd number from the
            // pipe, reopen the actual listener fd file descriptor from the child
            // via pidfd_open + pidfd_getfd (the child still holds it open while
            // SIGSTOP'd), then SIGCONT and exec the broker. This replaces the
            // `sendmsg(SCM_RIGHTS)` handoff, which trapped sendmsg and forced the
            // broker to be single-arg-only. With the fd-number handoff the broker
            // never touches SCM_RIGHTS and the listener fd is acquired through
            // the same pidfd path it already uses for socket emulation.
            drop(write_end);
            let mut pipe = std::fs::File::from(read_end);
            let mut text = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                pipe.read_exact(&mut byte)
                    .unwrap_or_else(|_| die("reading listener fd from handoff pipe failed"));
                if byte[0] == b'\n' {
                    break;
                }
                text.push(byte[0]);
                if text.len() > 11 {
                    die("listener fd on handoff pipe was not a decimal integer");
                }
            }
            let listener_fd_number: i32 = std::str::from_utf8(&text)
                .ok()
                .and_then(|text| text.parse().ok())
                .unwrap_or_else(|| die("listener fd on handoff pipe was not a decimal integer"));

            // pidfd_open(2): Linux 5.3+. Refer to the child pid so we can dup its
            // fds without racing /proc.
            let child_pid = u32::try_from(child.as_raw()).unwrap_or_else(|_| {
                eprintln!("agent-sandbox-syscall-arm: child pid out of range");
                process::exit(1);
            });
            let pidfd = pidfd_open(child_pid).unwrap_or_else(|_| die("pidfd_open child failed"));

            // pidfd_getfd(2): Linux 5.6+. Duplicate the child's listener fd into
            // the parent's fd table. The child is SIGSTOP'd, so the fd is still
            // valid. We will SIGCONT only after acquiring it.
            let listener_fd = pidfd_getfd(&pidfd, listener_fd_number)
                .unwrap_or_else(|_| die("pidfd_getfd listener fd failed"));

            // pidfd_getfd sets FD_CLOEXEC on the duplicated fd (per the Linux man
            // page). The parent execs the broker immediately after, which would
            // close the listener fd during exec, leaving the broker with a stale
            // fd. Clear FD_CLOEXEC so the listener survives execvp into the broker.
            if let Ok(flags) = fcntl(&listener_fd, FcntlArg::F_GETFD) {
                let _ = fcntl(
                    &listener_fd,
                    FcntlArg::F_SETFD(FdFlag::from_bits_truncate(flags) & !FdFlag::FD_CLOEXEC),
                );
            }
            // Do NOT SIGCONT the child here. The broker must be ready to receive
            // seccomp notifications before the child resumes, otherwise the child's
            // first openat (during dynamic linking) traps with no broker listening,
            // causing ENOSYS. The broker SIGCONTs the child on the first iteration
            // of its notification loop, ensuring it is inside the loop and the
            // listener fd is held before the child resumes.
            exec_broker(&listener_fd, child);
        }
    }
}

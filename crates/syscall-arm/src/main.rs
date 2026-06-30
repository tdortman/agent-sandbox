#![allow(unsafe_code)]

use agent_sandbox_syscall::{
    LISTENER_FLAG_NEW_LISTENER, SECCOMP_SET_MODE_FILTER, build_filter, default_syscalls,
};
use clap::Parser as _;
use std::env;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::process;

const DEFAULT_POLICY_SOCKET: &str = "/run/agent-sandbox/policy.sock";

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

fn install_filter() -> i32 {
    let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if no_new_privs < 0 {
        die("prctl PR_SET_NO_NEW_PRIVS failed");
    }

    let filter = build_filter(&default_syscalls());
    // `seccompiler::BpfProgram` is `Vec<seccompiler::sock_filter>`. The
    // seccomp syscall takes a `*mut libc::sock_filter`; both struct types
    // are `#[repr(C)]` with identical field layout (code: u16, jt: u8,
    // jf: u8, k: u32), so the pointer cast is sound. The wrapper statically
    // asserts the size match in `bpf.rs`.
    let mut prog = libc::sock_fprog {
        len: u16::try_from(filter.len()).unwrap_or(u16::MAX),
        filter: filter.as_ptr().cast::<libc::sock_filter>().cast_mut(),
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            u64::from(SECCOMP_SET_MODE_FILTER),
            u64::from(LISTENER_FLAG_NEW_LISTENER),
            &mut prog,
        )
    };
    if fd < 0 {
        die("seccomp user notification install failed");
    }
    i32::try_from(fd).unwrap_or_else(|_| {
        eprintln!("agent-sandbox-syscall-arm: listener fd out of range");
        process::exit(1);
    })
}

/// Create a `pipe2(O_CLOEXEC)` pair for passing the listener fd number
/// across the fork→exec boundary. Both ends are CLOEXEC so they close
/// automatically in any exec'd child except when we explicitly keep one.
fn handoff_pipe() -> [i32; 2] {
    let mut fds = [0_i32; 2];
    // ponytail: pipe2 with O_CLOEXEC is the atomic, thread-safe way to
    // build a pipe that survives fork but closes on exec, matching the
    // pre-exec handoff semantics exactly.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc < 0 {
        die("pipe2 failed");
    }
    fds
}

/// Write the listener fd number, decimal + newline, to the write end of
/// the handoff pipe. Closes the pipe fd on success.
fn write_listener_fd(write_end: i32, listener_fd: i32) {
    let mut buf = listener_fd.to_string();
    buf.push('\n');
    let bytes = buf.as_bytes();
    let mut written = 0_usize;
    while written < bytes.len() {
        let n = unsafe {
            libc::write(
                write_end,
                bytes[written..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - written,
            )
        };
        if n < 0 {
            die("writing listener fd to handoff pipe failed");
        }
        written += usize::try_from(n).unwrap_or(0);
    }
    unsafe {
        libc::close(write_end);
    }
}

/// Read the listener fd number (decimal + newline) from the read end of
/// the handoff pipe. Closes the pipe fd on success.
fn read_listener_fd(read_end: i32) -> i32 {
    let mut buf = [0_u8; 32];
    let mut filled = 0_usize;
    while filled < buf.len() {
        let n = unsafe {
            libc::read(
                read_end,
                buf[filled..].as_mut_ptr().cast::<libc::c_void>(),
                buf.len() - filled,
            )
        };
        if n < 0 {
            die("reading listener fd from handoff pipe failed");
        }
        if n == 0 {
            die("handoff pipe closed before listener fd was sent");
        }
        filled += usize::try_from(n).unwrap_or(0);
        // Stop at the newline regardless of how many bytes arrived.
        if buf[..filled].contains(&b'\n') {
            break;
        }
    }
    let newline = buf[..filled]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(filled);
    let text = std::str::from_utf8(&buf[..newline]).unwrap_or_else(|_| {
        die("listener fd on handoff pipe was not valid UTF-8");
    });
    let fd: i32 = text.trim().parse().unwrap_or_else(|_| {
        die("listener fd on handoff pipe was not a decimal integer");
    });
    unsafe {
        libc::close(read_end);
    }
    fd
}

fn exec_command(args: &[OsString]) -> ! {
    let cargs: Vec<CString> = args
        .iter()
        .map(|arg| cstring(arg.as_os_str().as_bytes()))
        .collect();
    let mut argv_ptrs: Vec<*const libc::c_char> = cargs.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    unsafe {
        libc::execvp(cargs[0].as_ptr(), argv_ptrs.as_ptr());
    }
    die("execvp command failed");
}

fn exec_broker(listener_fd: i32, child_pid: libc::pid_t) -> ! {
    let broker = cstring(b"agent-sandbox-syscall-broker");
    let fd_arg = listener_fd.to_string();
    let child_arg = child_pid.to_string();
    let policy_socket = env::var("AGENT_SANDBOX_POLICY_SOCKET")
        .unwrap_or_else(|_| DEFAULT_POLICY_SOCKET.to_string());
    let mut args = vec![
        cstring(b"agent-sandbox-syscall-broker"),
        cstring(b"--listener-fd"),
        cstring(fd_arg.as_bytes()),
        cstring(b"--child-pid"),
        cstring(child_arg.as_bytes()),
        cstring(b"--policy-socket"),
        cstring(policy_socket.as_bytes()),
    ];
    if let Ok(session) = env::var("AGENT_SANDBOX_SESSION_ID") {
        args.push(cstring(b"--sandbox-session-id"));
        args.push(cstring(session.as_bytes()));
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    unsafe {
        libc::execvp(broker.as_ptr(), argv_ptrs.as_ptr());
    }
    die("execvp broker failed");
}

#[derive(clap::Parser, Debug)]
#[command(
    name = "agent-sandbox-syscall-arm",
    version,
    about = "Install a seccomp user-notification filter, then exec the command",
    long_about = "Runs INSIDE the sandbox as the first process in the syscall-gate path. \
        Installs a seccomp user-notification filter on the immediate child, forks the child, \
        sends the seccomp listener fd number to the parent over a `pipe2(O_CLOEXEC)` pair, \
        raises SIGSTOP, and execs the command. The parent reads the fd number, re-acquires \
        the listener fd from the sibling via `pidfd_open` + `pidfd_getfd`, kills the child \
        SIGCONT, and execs `agent-sandbox-syscall-broker` with the listener fd and child \
        pid, which talks to policyd over the policy socket to make per-syscall verdicts.\n\n\
        Environment variables consumed from the bwrap wrapper:\n\
          AGENT_SANDBOX_POLICY_SOCKET  policyd socket path \
                                        (default /run/agent-sandbox/policy.sock)\n\
          AGENT_SANDBOX_SESSION_ID     forwarded to the broker and policyd for per-session \
                                        audit logging\n\n\
    EXAMPLES:\n\
        # Install the filter, then exec python3. The `--` is optional.\n\
        agent-sandbox-syscall-arm /usr/bin/python3 -i\n\n\
        # Install the filter, then exec a wrapped agent.\n\
        agent-sandbox-syscall-arm /home/user/bin/my-agent --flag"
)]
struct Cli {
    /// The command to exec after the seccomp filter is installed. Everything after the flags is forwarded verbatim to execvp, including values that look like flags. A `--` separator is accepted but not required.
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    command: Vec<OsString>,
}

fn main() {
    let cli = Cli::parse();
    let command = cli.command;
    if command.is_empty() {
        eprintln!(
            "agent-sandbox-syscall-arm: missing command\n\
             \n\
             USAGE:\n\
                 agent-sandbox-syscall-arm [--] <command> [args...]"
        );
        process::exit(2);
    }
    let pipes = handoff_pipe();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        die("fork failed");
    }
    if pid == 0 {
        // Child: close the read end (we only write our side), install the
        // seccomp filter, hand the listener fd NUMBER to the parent, raise
        // SIGSTOP so the parent can re-acquire the listener fd via
        // pidfd_getfd before the command execs, then exec.
        unsafe {
            libc::close(pipes[0]);
        }
        let listener_fd = install_filter();
        write_listener_fd(pipes[1], listener_fd);
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
        exec_command(&command);
    }

    // Parent: close the write end, read the listener fd number from the
    // pipe, reopen the actual listener fd file descriptor from the child
    // via pidfd_open + pidfd_getfd (the child still holds it open while
    // SIGSTOP'd), then SIGCONT and exec the broker. This replaces the
    // `sendmsg(SCM_RIGHTS)` handoff, which trapped sendmsg and forced the
    // broker to be single-arg-only. With the fd-number handoff the broker
    // never touches SCM_RIGHTS and the listener fd is acquired through
    // the same pidfd path it already uses for socket emulation.
    unsafe {
        libc::close(pipes[1]);
    }
    let listener_fd_number = read_listener_fd(pipes[0]);

    // pidfd_open(2): Linux 5.3+. Refer to the child pid so we can dup its
    // fds without racing /proc.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if pidfd < 0 {
        die("pidfd_open child failed");
    }
    let pidfd_i32 = i32::try_from(pidfd).unwrap_or_else(|_| {
        eprintln!("agent-sandbox-syscall-arm: pidfd out of range");
        process::exit(1);
    });
    // pidfd_getfd(2): Linux 5.6+. Duplicate the child's listener fd into
    // the parent's fd table. The child is SIGSTOP'd, so the fd is still
    // valid. We will SIGCONT only after acquiring it.
    let listener_fd =
        unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd_i32, listener_fd_number, 0) };
    if listener_fd < 0 {
        die("pidfd_getfd listener fd failed");
    }
    let listener_fd_i32 = i32::try_from(listener_fd).unwrap_or_else(|_| {
        eprintln!("agent-sandbox-syscall-arm: listener fd out of range");
        process::exit(1);
    });

    // pidfd_getfd sets FD_CLOEXEC on the duplicated fd (per the Linux man
    // page). The parent execs the broker immediately after, which would
    // close the listener fd during exec, leaving the broker with a stale
    // fd. Clear FD_CLOEXEC so the listener survives execvp into the broker.
    let fdflags = unsafe { libc::fcntl(listener_fd_i32, libc::F_GETFD) };
    if fdflags >= 0 {
        unsafe {
            libc::fcntl(listener_fd_i32, libc::F_SETFD, fdflags & !libc::FD_CLOEXEC);
        }
    }
    // Do NOT SIGCONT the child here. The broker must be ready to receive
    // seccomp notifications before the child resumes, otherwise the child's
    // first openat (during dynamic linking) traps with no broker listening,
    // causing ENOSYS. The broker SIGCONTs the child after entering its loop.
    exec_broker(listener_fd_i32, pid);
}

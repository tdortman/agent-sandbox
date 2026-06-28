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

fn socketpair() -> [i32; 2] {
    let mut fds = [0_i32; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc < 0 {
        die("socketpair failed");
    }
    fds
}

/// Layout of `struct cmsghdr` (matches Linux UAPI) followed by the trailing
/// data payload. The Linux ABI leaves the data as a flexible array member
/// (FAM), so we model it as inline bytes here.
///
/// `cmsg_len` is `u64` rather than `libc::socklen_t` because the Linux kernel
/// UAPI defines it as `__kernel_size_t`, which is 8 bytes on `x86_64`, while
/// glibc exposes `socklen_t` as 4 bytes. Mismatching the kernel's width makes
/// `sendmsg` reject the message with `EINVAL`, so we mirror the kernel width
/// directly. The `u64` first field also gives the struct 8-byte alignment,
/// which the cmsg buffer requires.
#[repr(C)]
struct CmsgBuf {
    cmsg_len: u64,
    cmsg_level: libc::c_int,
    cmsg_type: libc::c_int,
    data: [u8; 4],
}

const SCM_RIGHTS_LEN: usize = std::mem::size_of::<i32>();

fn write_cmsg(buf: &mut CmsgBuf, level: libc::c_int, ty: libc::c_int, data: i32) {
    let cmsg_len = u64::try_from(std::mem::offset_of!(CmsgBuf, data) + SCM_RIGHTS_LEN)
        .expect("cmsg_len fits in u64");
    buf.cmsg_len = cmsg_len;
    buf.cmsg_level = level;
    buf.cmsg_type = ty;
    let bytes = data.to_ne_bytes();
    buf.data[..bytes.len()].copy_from_slice(&bytes);
}

fn read_cmsg(buf: &CmsgBuf) -> i32 {
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&buf.data[..SCM_RIGHTS_LEN]);
    i32::from_ne_bytes(bytes)
}

fn send_fd(sock: i32, fd: i32) {
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut cmsg = CmsgBuf {
        cmsg_len: 0,
        cmsg_level: 0,
        cmsg_type: 0,
        data: [0; 4],
    };
    write_cmsg(&mut cmsg, libc::SOL_SOCKET, libc::SCM_RIGHTS, fd);
    let cmsg_len = std::mem::size_of::<CmsgBuf>();
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&raw mut cmsg).cast();
    msg.msg_controllen = cmsg_len;
    if unsafe { libc::sendmsg(sock, &raw const msg, 0) } < 0 {
        die("sendmsg listener fd failed");
    }
}

fn recv_fd(sock: i32) -> i32 {
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut cmsg = CmsgBuf {
        cmsg_len: 0,
        cmsg_level: 0,
        cmsg_type: 0,
        data: [0; 4],
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&raw mut cmsg).cast();
    msg.msg_controllen = std::mem::size_of::<CmsgBuf>();
    if unsafe { libc::recvmsg(sock, &raw mut msg, 0) } < 0 {
        die("recvmsg listener fd failed");
    }
    read_cmsg(&cmsg)
}

fn exec_command(args: &[OsString]) -> ! {
    let cargs: Vec<CString> = args
        .iter()
        .map(|arg| cstring(arg.as_os_str().as_bytes()))
        .collect();
    let mut argv: Vec<*const libc::c_char> = cargs.iter().map(|arg| arg.as_ptr()).collect();
    argv.push(std::ptr::null());
    unsafe {
        libc::execvp(cargs[0].as_ptr(), argv.as_ptr());
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
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
    argv.push(std::ptr::null());
    unsafe {
        libc::execvp(broker.as_ptr(), argv.as_ptr());
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
        sends the seccomp listener fd to the parent over a Unix socketpair, raises SIGSTOP, \
        and execs the command. The parent execs `agent-sandbox-syscall-broker` with the \
        listener fd and the child pid, which talks to policyd over the policy socket to make \
        per-syscall verdicts.\n\n\
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
    let sockets = socketpair();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        die("fork failed");
    }
    if pid == 0 {
        unsafe {
            libc::close(sockets[0]);
        }
        let listener_fd = install_filter();
        send_fd(sockets[1], listener_fd);
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
        exec_command(&command);
    }

    unsafe {
        libc::close(sockets[1]);
    }
    let listener_fd = recv_fd(sockets[0]);
    unsafe {
        libc::close(sockets[0]);
        libc::kill(pid, libc::SIGCONT);
    }
    exec_broker(listener_fd, pid);
}

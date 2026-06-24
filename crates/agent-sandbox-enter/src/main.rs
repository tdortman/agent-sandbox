#![allow(unsafe_code)]

//! Join a named network namespace, drop inherited capabilities, then exec the command.
//!
//! Installed as a setuid-root wrapper (`security.wrappers`) so unprivileged sandboxes can
//! `setns` without keeping ambient/file capabilities (required for bubblewrap).

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process;

use caps::CapSet;
use clap::Parser as _;
use nix::sched::{CloneFlags, setns};
use nix::unistd::execvp;

fn die(msg: &str, err: &io::Error) -> ! {
    eprintln!("{msg}: {err}");
    process::exit(1);
}

/// Drop caps granted to this wrapper so bubblewrap does not inherit them across exec.
///
/// The NixOS wrapper uses file capabilities (`setuid = false`), so we only have
/// `CAP_SYS_ADMIN` / `CAP_NET_ADMIN` in the effective set, not `CAP_SETPCAP`.
/// Clearing permitted/inheritable/bounding (`PR_CAPBSET_DROP`) would fail with EPERM.
/// exec replaces the image anyway. Ambient + effective must be cleared before execvp.
fn drop_capabilities() -> io::Result<()> {
    caps::clear(None, CapSet::Effective).map_err(io::Error::other)?;

    // SAFETY: `PR_CAP_AMBIENT` + `PR_CAP_AMBIENT_LOWER`. Stop when the kernel returns EINVAL.
    unsafe {
        for cap in 0_i32.. {
            if libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_LOWER, cap, 0, 0) < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINVAL) {
                    break;
                }
                return Err(err);
            }
        }
    }
    Ok(())
}

#[derive(clap::Parser, Debug)]
#[command(
    name = "agent-sandbox-enter",
    version,
    about = "Join a named network namespace, drop inherited capabilities, then exec the command",
    long_about = "Setuid-root wrapper (installed via security.wrappers) that joins the network \
        namespace at /run/netns/<NETNS>, drops the inherited ambient and effective capabilities \
        so bubblewrap does not inherit CAP_SYS_ADMIN / CAP_NET_ADMIN across exec, then execvp \
        the command. The remaining caps in the effective set are cleared; permitted, inheritable, \
        and bounding sets are not touched because the wrapper has no CAP_SETPCAP and dropping \
        bounding bits would fail with EPERM.\n\n\
    EXAMPLES:\n\
        # Join the sandbox netns and exec python3. The `--` is optional.\n\
        agent-sandbox-enter sandbox-netns-1 /usr/bin/python3 -i\n\n\
        # Join the default netns and exec a wrapped agent.\n\
        agent-sandbox-enter default-netns /home/user/bin/my-agent --verbose"
)]
struct Cli {
    /// Name of the network namespace under /run/netns/. Capped at 200 characters by the kernel; rejected here as a friendlier error.
    #[arg(value_name = "NETNS")]
    netns: String,

    /// The command to exec inside the namespace, with its own arguments. Everything after the netns name is forwarded verbatim to execvp, including values that look like flags. A `--` separator is accepted but not required.
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    command: Vec<std::ffi::OsString>,
}

fn main() {
    let cli = Cli::parse();

    if cli.netns.len() > 200 {
        eprintln!("netns name too long");
        process::exit(1);
    }

    let path = PathBuf::from("/run/netns").join(&cli.netns);
    let file = OpenOptions::new()
        .read(true)
        .open(&path)
        .unwrap_or_else(|e| die("open netns", &e));

    if let Err(err) = setns(&file, CloneFlags::CLONE_NEWNET) {
        if err == nix::errno::Errno::EPERM {
            eprintln!("setns: need CAP_SYS_ADMIN on agent-sandbox-enter (rebuild NixOS)");
        }
        die("setns", &io::Error::other(err));
    }

    if let Err(err) = drop_capabilities() {
        die("drop capabilities", &err);
    }

    let cargs: Vec<CString> = cli
        .command
        .iter()
        .map(|s| CString::new(s.as_os_str().as_bytes()).expect("interior NUL"))
        .collect();
    let cmd = cargs
        .first()
        .expect("clap requires at least one command")
        .clone();

    // execvp returns Result<Infallible, Errno>; the Ok arm is uninhabited
    // because the process image is replaced. unwrap_err is safe because
    // the compiler can prove the Ok variant is uninhabited.
    let err = execvp(&cmd, &cargs).unwrap_err();
    die("execvp", &io::Error::other(err));
}

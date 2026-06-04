#![allow(unsafe_code)]

//! Join a named network namespace, drop inherited capabilities, then exec the command.
//!
//! Installed as a setuid-root wrapper (`security.wrappers`) so unprivileged sandboxes can
//! `setns` without keeping ambient/file capabilities (required for bubblewrap).

use std::env;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::path::PathBuf;
use std::process;

use caps::CapSet;
use nix::sched::{CloneFlags, setns};
use nix::unistd::execvp;

fn die(msg: &str, err: &io::Error) -> ! {
    eprintln!("{msg}: {err}");
    process::exit(1);
}

/// Clear file caps and lower all ambient capabilities (bwrap refuses inherited file caps).
fn drop_capabilities() -> io::Result<()> {
    for set in [
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
        CapSet::Ambient,
        CapSet::Bounding,
    ] {
        caps::clear(None, set).map_err(io::Error::other)?;
    }

    // SAFETY: `PR_CAP_AMBIENT` + `PR_CAP_AMBIENT_LOWER`; stop when the kernel returns EINVAL.
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <netns-name> <command> [args...]", args[0]);
        process::exit(2);
    }

    let nsname = &args[1];
    if nsname.len() > 200 {
        eprintln!("netns name too long");
        process::exit(1);
    }

    let path = PathBuf::from("/run/netns").join(nsname);
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

    let cmd = CString::new(args[2].as_bytes()).unwrap_or_else(|_| {
        eprintln!("command contains interior NUL");
        process::exit(1);
    });
    let argv: Vec<CString> = args[2..]
        .iter()
        .map(|s| CString::new(s.as_bytes()).expect("interior NUL"))
        .collect();

    match execvp(&cmd, &argv) {
        Ok(never) => match never {},
        Err(err) => die("execvp", &io::Error::other(err)),
    }
}

//! `fusermount3` stand-in for sandboxes: asks policyd to mount and unmount.

use std::{ffi::OsString, path::PathBuf, process::ExitCode};

use agent_sandbox_core::{ProcessIds, RequestContext};
use agent_sandbox_fuse::{
    mountpoint::lexical_absolute,
    options::parse_mount_options,
    shim::{Endpoint, ShimError, mount, unmount, unmount_when_client_exits},
};
use agent_sandbox_sysutil::take_inherited_socket;
use clap::Parser;
use rustix::{
    process::{getuid, setsid},
    stdio::{dup2_stderr, dup2_stdin, dup2_stdout},
};

/// Where the sandbox reaches policyd when the environment does not say.
const DEFAULT_SOCKET: &str = "/run/agent-sandbox/shared/sandbox-policy.sock";

/// The environment variable libfuse and go-fuse pass the socket number in.
const COMM_FD_ENV: &str = "_FUSE_COMMFD";

/// The `fusermount3` options clients use.
#[derive(Parser, Debug)]
#[command(
    name = "fusermount3",
    disable_version_flag = true,
    about = "Mount and unmount FUSE filesystems for the agent sandbox"
)]
struct Cli {
    /// Mount options, comma separated.
    #[arg(short = 'o', long = "options", value_name = "OPTIONS")]
    options: Vec<String>,

    /// Unmount instead of mount.
    #[arg(short = 'u', long = "unmount")]
    unmount: bool,

    /// Detach the mount lazily when unmounting.
    #[arg(short = 'z', long = "lazy")]
    lazy: bool,

    /// Print no error text when unmounting.
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Print the version.
    #[arg(short = 'V', long = "version")]
    version: bool,

    /// Only wait for the client to exit, then unmount.
    #[arg(long = "auto-unmount")]
    auto_unmount: bool,

    /// Descriptor number of the socket to return the `/dev/fuse` descriptor on.
    #[arg(long = "comm-fd", value_name = "FD")]
    comm_fd: Option<i32>,

    /// The mountpoint.
    #[arg(value_name = "MOUNTPOINT")]
    mountpoint: Option<PathBuf>,
}

fn main() -> ExitCode {
    run(std::env::args_os())
}

/// Run the shim with `args` (including `argv[0]`).
fn run(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            let code = u8::from(err.use_stderr());
            let _ = err.print();

            return ExitCode::from(code);
        }
    };

    if cli.version {
        println!("fusermount3 version: agent-sandbox");

        return ExitCode::SUCCESS;
    }

    let quiet = cli.quiet;

    match execute(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            if !quiet {
                eprintln!("fusermount3: {message}");
            }

            ExitCode::FAILURE
        }
    }
}

fn execute(cli: &Cli) -> Result<(), String> {
    let mountpoint = cli
        .mountpoint
        .as_deref()
        .ok_or("missing mountpoint argument")?;

    let cwd = std::env::current_dir()
        .map_err(|err| format!("cannot read the working directory: {err}"))?;
    let mountpoint = lexical_absolute(&cwd, mountpoint);
    let endpoint = endpoint();

    if cli.lazy && !cli.unmount {
        return Err("-z can only be used with -u".into());
    }

    if cli.unmount && !cli.auto_unmount {
        return unmount(&endpoint, &mountpoint, cli.lazy).map_err(|err| err.to_string());
    }

    let comm_fd = comm_fd(cli.comm_fd)?;
    let options = cli.options.join(",");

    // Refuse here what policyd would refuse, so the client sees the option
    // name.
    let params = parse_mount_options(&options, true).map_err(|err| err.to_string())?;

    if !cli.auto_unmount {
        mount(
            &endpoint,
            &mountpoint,
            &options,
            std::os::fd::AsFd::as_fd(&comm_fd),
        )
        .map_err(|err: ShimError| err.to_string())?;
    }

    if params.auto_unmount || cli.auto_unmount {
        detach_from_client();

        return unmount_when_client_exits(
            &endpoint,
            &mountpoint,
            std::os::fd::AsFd::as_fd(&comm_fd),
        )
        .map_err(|err| err.to_string());
    }

    Ok(())
}

fn endpoint() -> Endpoint {
    // The request names no session: the client's environment is cleared by
    // some FUSE libraries and is the sandbox's own claim anyway. policyd
    // attributes the peer by its place in the sandbox's process tree.
    let ctx = RequestContext::from_paths_and_ids(
        &agent_sandbox_core::SandboxPaths::default(),
        ProcessIds::new(std::process::id(), getuid().as_raw()),
    );

    Endpoint {
        socket: std::env::var_os("AGENT_SANDBOX_POLICY_SOCKET")
            .map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from),
        ctx,
        require_foreign_listener: true,
    }
}

fn comm_fd(flag: Option<i32>) -> Result<std::os::fd::OwnedFd, String> {
    let number = match flag {
        Some(number) => number,
        None => std::env::var(COMM_FD_ENV)
            .map_err(|_| "old style mounting not supported".to_owned())?
            .parse()
            .map_err(|_| format!("invalid {COMM_FD_ENV}"))?,
    };

    take_inherited_socket(number).map_err(|err| {
        format!("file descriptor {number} is not a socket, can't send fuse fd: {err}")
    })
}

/// Leave the client's session and release its terminal and pipes, so a
/// `fusermount3` that stays behind for `auto_unmount` blocks nobody.
fn detach_from_client() {
    let _ = setsid();
    let _ = std::env::set_current_dir("/");

    if let Ok(null) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        let _ = dup2_stdin(&null);
        let _ = dup2_stdout(&null);
        let _ = dup2_stderr(&null);
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("fusermount arguments parse")
    }

    #[test]
    fn go_fuse_argument_order_is_accepted() {
        let cli = parse(&[
            "/usr/bin/fusermount3",
            "/home/u/checkouts",
            "-o",
            "default_permissions,nodev,nosuid,noatime,fsname=ovnfs,subtype=ovnfs,max_read=131072",
        ]);

        assert_eq!(
            cli.mountpoint.as_deref(),
            Some("/home/u/checkouts".as_ref())
        );
        assert!(!cli.unmount);
        assert_eq!(cli.options.len(), 1);
    }

    #[test]
    fn libfuse_argument_order_is_accepted() {
        let cli = parse(&["fusermount3", "-o", "rw,nosuid,nodev", "--", "/mnt/x"]);

        assert_eq!(cli.mountpoint.as_deref(), Some("/mnt/x".as_ref()));
    }

    #[test]
    fn unmount_flags_combine() {
        let cli = parse(&["fusermount3", "-uz", "/mnt/x"]);

        assert!(cli.unmount && cli.lazy);

        let cli = parse(&["fusermount3", "-u", "-z", "-q", "/mnt/x"]);

        assert!(cli.unmount && cli.lazy && cli.quiet);
    }

    #[test]
    fn libfuse_auto_unmount_helper_form_is_accepted() {
        let cli = parse(&[
            "fusermount3",
            "--auto-unmount",
            "--comm-fd=7",
            "--",
            "/mnt/x",
        ]);

        assert!(cli.auto_unmount);
        assert_eq!(cli.comm_fd, Some(7));
    }
}

//! Join a named network namespace, optionally enter a fresh time namespace,
//! drop inherited capabilities, then exec the command.
//!
//! Installed as a setuid-root wrapper (`security.wrappers`) so unprivileged
//! sandboxes can `setns` without keeping ambient/file capabilities (required
//! for bubblewrap).

use std::{
    fs::OpenOptions,
    io,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process,
};

use caps::CapSet;
use clap::Parser as _;
use nix::sched::{CloneFlags, setns, unshare};

fn die(msg: &str, err: &io::Error) -> ! {
    eprintln!("{msg}: {err}");
    process::exit(1);
}

/// Drop caps granted to this wrapper so bubblewrap does not inherit them across
/// exec.
///
/// The NixOS wrapper uses file capabilities (`setuid = false`), so we only have
/// `CAP_SYS_ADMIN` / `CAP_NET_ADMIN` in the effective set, not `CAP_SETPCAP`.
/// Clearing permitted/inheritable/bounding (`PR_CAPBSET_DROP`) would fail with
/// EPERM. exec replaces the image anyway. Ambient + effective must be cleared
/// before execvp.
fn drop_capabilities() -> io::Result<()> {
    caps::clear(None, CapSet::Effective).map_err(io::Error::other)?;
    agent_sandbox_sysutil::clear_ambient_capabilities()
}

const NETNS_DIR: &str = "/run/netns";

/// Reject traversal, separators, and names outside the agent-sandbox netns
/// convention.
fn netns_name_allowed(name: &str) -> bool {
    if name.is_empty() || name.len() > 200 {
        return false;
    }

    if name.contains("..") {
        return false;
    }

    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Resolve `/run/netns/<name>` and ensure it stays under the netns directory.
fn resolve_netns_path(name: &str) -> io::Result<PathBuf> {
    if !netns_name_allowed(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid netns name",
        ));
    }

    let requested = PathBuf::from(NETNS_DIR).join(name);

    let canonical = requested.canonicalize().map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("canonicalize netns path {}: {err}", requested.display()),
        )
    })?;

    let netns_root = Path::new(NETNS_DIR)
        .canonicalize()
        .map_err(|err| io::Error::new(err.kind(), format!("canonicalize {NETNS_DIR}: {err}")))?;

    if !canonical.starts_with(&netns_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "netns path escapes /run/netns",
        ));
    }

    if canonical.file_name().and_then(|n| n.to_str()) != Some(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "netns symlink target name mismatch",
        ));
    }

    Ok(canonical)
}

#[derive(clap::Parser, Debug)]
#[command(
    name = "agent-sandbox-enter",
    version,
    about = "Join a named network namespace, drop inherited capabilities, then exec the command",
    long_about = r"Setuid-root wrapper (installed via security.wrappers) that joins the network namespace at /run/netns/<NETNS>, drops the inherited ambient and effective capabilities so bubblewrap does not inherit CAP_SYS_ADMIN / CAP_NET_ADMIN across exec, then execvp the command. The remaining caps in the effective set are cleared; permitted, inheritable, and bounding sets are not touched because the wrapper has no CAP_SETPCAP and dropping bounding bits would fail with EPERM.

With --new-time-namespace the wrapper also unshares a fresh time namespace (zero offsets) after joining the netns and before dropping capabilities. The exec'd command and its descendants run in it, so a host helper can rewind the namespace's CLOCK_MONOTONIC and CLOCK_BOOTTIME after the sandbox was frozen. The option must come before NETNS. The wrapper fails when the kernel has no time namespace support.

EXAMPLES:
# Join the sandbox netns and exec python3. The `--` is optional.
agent-sandbox-enter sandbox-netns-1 /usr/bin/python3 -i

# Join the default netns and exec a wrapped agent.
agent-sandbox-enter default-netns /home/user/bin/my-agent --verbose

# Join the netns and run the agent in its own time namespace.
agent-sandbox-enter --new-time-namespace sandbox-netns-1 /home/user/bin/my-agent"
)]
struct Cli {
    /// Unshare a fresh time namespace after joining the netns, so the command
    /// gets its own `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` offsets. Must
    /// precede NETNS; anything after NETNS belongs to the command.
    #[arg(long)]
    new_time_namespace: bool,

    /// Name of the network namespace under /run/netns/. Capped at 200
    /// characters by the kernel; rejected here as a friendlier error.
    #[arg(value_name = "NETNS")]
    netns: String,

    /// The command to exec inside the namespace, with its own arguments.
    /// Everything after the netns name is forwarded verbatim to execvp,
    /// including values that look like flags. A `--` separator is accepted but
    /// not required.
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    command: Vec<std::ffi::OsString>,
}

struct UnjoinedNetns {
    netns: String,
    new_time_namespace: bool,
    command: Vec<std::ffi::OsString>,
}

struct JoinedNetns {
    new_time_namespace: bool,
    command: Vec<std::ffi::OsString>,
}

struct CapabilitiesDropped {
    command: Vec<std::ffi::OsString>,
}

impl UnjoinedNetns {
    fn join(self) -> JoinedNetns {
        let path = resolve_netns_path(&self.netns).unwrap_or_else(|e| die("resolve netns", &e));
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

        JoinedNetns {
            new_time_namespace: self.new_time_namespace,
            command: self.command,
        }
    }
}

impl JoinedNetns {
    /// Make the command (and its descendants) start in a fresh time
    /// namespace: the unshared namespace applies to children, and execve moves
    /// the process into it.
    fn unshare_time_namespace(self) -> Self {
        if self.new_time_namespace
            && let Err(err) = unshare(CloneFlags::from_bits_retain(nix::libc::CLONE_NEWTIME))
        {
            if err == nix::errno::Errno::EINVAL {
                eprintln!("unshare: this kernel has no time namespace support (CONFIG_TIME_NS)");
            }

            die("unshare time namespace", &io::Error::other(err));
        }

        self
    }

    fn drop_caps(self) -> CapabilitiesDropped {
        if let Err(err) = drop_capabilities() {
            die("drop capabilities", &err);
        }
        CapabilitiesDropped {
            command: self.command,
        }
    }
}

impl CapabilitiesDropped {
    fn exec_command(self) -> ! {
        let (prog, args) = self
            .command
            .split_first()
            .expect("clap requires at least one command");

        // Replaces the process image; only returns when the exec fails.
        let err = process::Command::new(prog).args(args).exec();
        die("exec", &err);
    }
}

fn main() {
    let cli = Cli::parse();
    UnjoinedNetns {
        netns: cli.netns,
        new_time_namespace: cli.new_time_namespace,
        command: cli.command,
    }
    .join()
    .unshare_time_namespace()
    .drop_caps()
    .exec_command();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netns_name_rejects_traversal_and_separators() {
        assert!(!netns_name_allowed(".."));
        assert!(!netns_name_allowed("../agent-sandbox"));
        assert!(!netns_name_allowed("agent/sandbox"));
        assert!(!netns_name_allowed(""));
    }

    #[test]
    fn netns_name_accepts_agent_sandbox_convention() {
        assert!(netns_name_allowed("agent-sandbox"));
        assert!(netns_name_allowed("sandbox-netns-1"));
        assert!(netns_name_allowed("default-netns"));
    }

    #[test]
    fn time_namespace_flag_precedes_netns_and_stays_with_the_command_after_it() {
        let cli = Cli::try_parse_from(["enter", "--new-time-namespace", "ns", "prog", "-x"])
            .expect("flag before netns parses");
        assert!(cli.new_time_namespace);
        assert_eq!(cli.netns, "ns");

        let cli = Cli::try_parse_from(["enter", "ns", "prog", "--new-time-namespace"])
            .expect("flag after netns parses");
        assert!(!cli.new_time_namespace);
        assert_eq!(cli.command.len(), 2);
    }
}

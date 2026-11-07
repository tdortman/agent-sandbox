//! Kernel-enforced floor under the seccomp user-notification gate.
//!
//! The broker answers many notifications with
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. The kernel then re-reads pointer
//! arguments (paths, socket addresses, `msghdr`) from tracee memory, so another
//! tracee thread can swap them after the broker classified them. A Landlock
//! domain on the tracee keeps every continued syscall away from what the broker
//! gates: device nodes outside [`UNGATED_DEVICES`], pathname UNIX sockets, and
//! abstract UNIX sockets created outside the sandbox. The broker runs outside
//! the domain and reaches approved targets by emulating the syscall.

use std::path::{Path, PathBuf};

use landlock::{
    AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, PathFdError, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetError, Scope,
};

/// Device nodes the sandbox opens without a broker decision. The pty
/// multiplexers only create new pairs, so they reach no existing terminal.
pub const UNGATED_DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
    "/dev/full",
    "/dev/tty",
    "/dev/ptmx",
    "/dev/pts/ptmx",
];

/// Directories under `/dev` that hold ordinary files: POSIX shared memory and
/// message queues.
const UNGATED_DEV_DIRS: &[&str] = &["/dev/shm", "/dev/mqueue"];

/// Errors from building or enforcing the floor.
#[derive(Debug, thiserror::Error)]
pub enum FloorError {
    /// The root directory could not be listed.
    #[error("listing the root directory: {0}")]
    ListRoot(#[from] std::io::Error),

    /// An existing path to allow could not be opened.
    #[error("opening {path}: {source}")]
    Open {
        /// The path to allow.
        path: PathBuf,
        /// Why opening it failed.
        source: PathFdError,
    },

    /// Landlock refused the ruleset, including when the kernel lacks a
    /// required right.
    #[error(transparent)]
    Ruleset(#[from] RulesetError),
}

/// Confine the calling thread and its future children to the floor.
///
/// Files outside `/dev` stay readable and writable as before; the filesystem
/// gate still decides them. Of the pathname UNIX sockets created outside the
/// domain, only `policy_socket` can be resolved; abstract ones cannot be
/// reached. Every right is a hard requirement, so a kernel without Landlock
/// ABI 9 fails here.
///
/// # Errors
/// Returns any error from building or enforcing the ruleset. Callers must not
/// run the sandbox without the floor: the seccomp gate alone is bypassable.
pub fn restrict_self(policy_socket: &Path) -> Result<(), FloorError> {
    let files = AccessFs::ReadFile | AccessFs::WriteFile;

    // Landlock rules only add access, so "everything but /dev" is every other
    // top-level entry.
    let mut file_paths = Vec::new();
    for entry in std::fs::read_dir("/")? {
        let entry = entry?;
        if entry.file_name() != "dev" {
            file_paths.push(entry.path());
        }
    }
    file_paths.extend(
        UNGATED_DEVICES
            .iter()
            .chain(UNGATED_DEV_DIRS)
            .map(PathBuf::from),
    );

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(files | AccessFs::ResolveUnix)?
        .scope(Scope::AbstractUnixSocket)?
        .create()?;

    for path in &file_paths {
        ruleset = add_existing(ruleset, path, files)?;
    }
    ruleset = add_existing(ruleset, policy_socket, AccessFs::ResolveUnix.into())?;

    ruleset.restrict_self()?;

    Ok(())
}

/// Allow `access` beneath `path`; a missing path needs no rule.
fn add_existing(
    ruleset: landlock::RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<landlock::RulesetCreated, FloorError> {
    match PathFd::new(path) {
        Ok(fd) => Ok(ruleset.add_rule(PathBeneath::new(fd, access))?),
        Err(_) if !path.exists() => Ok(ruleset),
        Err(source) => Err(FloorError::Open {
            path: path.to_path_buf(),
            source,
        }),
    }
}

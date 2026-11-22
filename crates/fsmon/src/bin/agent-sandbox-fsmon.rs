//! Root fanotify monitor: setns into the sandbox mount namespace,
//! mark each mountpoint, then event-loop handling permission events.

use std::{
    ffi::CString,
    fs,
    fs::File,
    io,
    io::{Read, Seek, SeekFrom, Write},
    mem::size_of,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use agent_sandbox_core::{
    FilesystemReplica, PersistentRpcClient, PolicydRpc, ProcessIds, wire_context,
};
use agent_sandbox_fsmon::permission::{
    Answer, CgroupPath, DecisionCounts, GateSetup, HostProc, IgnoreMarks, Kernel, PermissionEvent,
    PermissionGate, SandboxStop,
};
use agent_sandbox_sysutil::{
    FanotifyEventMetadata, FanotifyResponse, fanotify_flush_inode_marks, fanotify_mark_ignore,
    fanotify_response_bytes, take_fanotify_event_fd,
};
use clap::Parser;
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-fsmon",
    version,
    about = "fanotify filesystem policy monitor that brokers open() calls to policyd",
    long_about = r#"fanotify-based filesystem monitor that runs in the host mount namespace.
Given a target sandbox PID, it joins the sandbox mount namespace, marks every mount that overlaps the sandbox's working directory/home/project, and processes permission events for open and exec requests.
Each event is forwarded to policyd over a Unix domain socket and the verdict (allow/deny) is written back to the kernel via the fanotify response fd.

Normally spawned by policyd in response to an "agent-sandbox-fs-arm" request, not invoked directly.

EXAMPLES:
# Start a monitor for sandbox PID 12345 with the default policyd socket.
agent-sandbox-fsmon --pid 12345

# Override context for tools that do not export the AGENT_SANDBOX_* env vars.
agent-sandbox-fsmon \
    --pid 12345 \
    --cwd /home/user/project \
    --home /home/user \
    --project-root /home/user/project"#
)]
struct Cli {
    /// PID of the sandbox arm helper. The monitor joins the mount namespace of
    /// this PID and marks its filesystems.
    #[arg(long, value_name = "PID")]
    pid: u32,

    /// Path to the policyd Unix domain socket. fsmon forwards every fanotify
    /// permission event here and waits for an allow/deny verdict.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    socket: PathBuf,

    /// Working directory inside the sandbox. Used to scope per-project policy
    /// and to pick which mounts are marked. Defaults to the env var
    /// `AGENT_SANDBOX_CWD` if unset.
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_CWD")]
    cwd: Option<PathBuf>,

    /// Home directory inside the sandbox. Used to expand "~" in filesystem
    /// rules and to gate "global" scope. Defaults to the env var
    /// `AGENT_SANDBOX_HOME` if unset.
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_HOME")]
    home: Option<PathBuf>,

    /// Project root directory inside the sandbox. Required for "project" scope
    /// approvals to land in the right per-project policy file. Defaults to the
    /// env var `AGENT_SANDBOX_PROJECT_ROOT` if unset.
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_PROJECT_ROOT")]
    project_root: Option<PathBuf>,

    #[arg(
        long,
        value_name = "BOOL",
        action = clap::ArgAction::Set,
        default_value = "true",
        value_parser = clap::value_parser!(bool)
    )]
    fs_ignore_static_allows: bool,
}

// fanotify constants and event structs come from `agent_sandbox_sysutil`.
use agent_sandbox_sysutil::{FAN_ALLOW, FAN_DENY, FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM};

/// How long a finished sandbox's launcher may take to exit on its own before
/// it is killed.
const LAUNCHER_EXIT_GRACE: Duration = Duration::from_secs(1);

/// Process pidfds that bound the sandbox's lifetime.
///
/// The peer is the agent. Its parent is the broker or bwrap: when that dies
/// (the launcher was killed) the agent keeps a seccomp filter with no
/// listener, so the sandbox is over even though the peer lives. The launcher
/// is the outer bwrap. policyd kills the sandbox's scope once the launcher it
/// registered exits, so killing the launcher stops every process of the
/// sandbox.
enum LauncherCapability {
    MonitoringOnly,
    Controllable(OwnedFd),
}

struct SandboxLifetime {
    peer: OwnedFd,
    parent: OwnedFd,
    launcher: LauncherCapability,
}

impl SandboxLifetime {
    fn open(host_proc: &HostProc, peer: u32) -> io::Result<Self> {
        let peer_pid = i32::try_from(peer).map_err(io::Error::other)?;
        let peer_fd = agent_sandbox_sysutil::pidfd_open(peer)?;
        let parent_pid = host_proc
            .parent_pid(peer_pid)
            .and_then(|parent| u32::try_from(parent).ok())
            .filter(|parent| *parent > 0)
            .ok_or_else(|| io::Error::other("cannot read the peer's parent pid"))?;
        let parent_fd = agent_sandbox_sysutil::pidfd_open(parent_pid)?;

        // A pidfd only pins the pid it was opened for, so the peer must still
        // be a child of that process after the open.
        if host_proc.parent_pid(peer_pid) != i32::try_from(parent_pid).ok() {
            return Err(io::Error::other("the peer's parent changed while opening"));
        }

        let launcher = outer_bwrap_pid(host_proc, peer_pid)
            .and_then(|pid| {
                let launcher = agent_sandbox_sysutil::pidfd_open(u32::try_from(pid).ok()?)
                    .inspect_err(
                        |error| tracing::warn!(%error, "cannot watch the sandbox launcher"),
                    )
                    .ok()?;

                (outer_bwrap_pid(host_proc, peer_pid) == Some(pid)).then_some(launcher)
            })
            .map_or(
                LauncherCapability::MonitoringOnly,
                LauncherCapability::Controllable,
            );

        Ok(Self {
            peer: peer_fd,
            parent: parent_fd,
            launcher,
        })
    }

    /// Whether the sandbox can be stopped from here.
    const fn can_stop(&self) -> bool {
        matches!(self.launcher, LauncherCapability::Controllable(_))
    }

    /// Kill the launcher unless it exits within `grace`.
    fn stop(&self, grace: Duration) -> io::Result<()> {
        let LauncherCapability::Controllable(launcher) = &self.launcher else {
            return Err(io::Error::other("the sandbox has no launcher handle"));
        };
        if !grace.is_zero() {
            let mut exited = [PollFd::new(launcher.as_fd(), PollFlags::POLLIN)];

            if matches!(
                poll(
                    &mut exited,
                    PollTimeout::try_from(grace).unwrap_or(PollTimeout::MAX)
                ),
                Ok(ready) if ready > 0
            ) {
                return Ok(());
            }
        }

        match rustix::process::pidfd_send_signal(launcher, rustix::process::Signal::KILL) {
            Err(rustix::io::Errno::SRCH) => Ok(()),
            result => result.map_err(io::Error::from),
        }
    }

    /// Wait up to `timeout` for the peer or its parent to exit, or for the
    /// mount table behind `mountinfo` to change.
    fn wait(&self, mountinfo: &File, timeout: Duration) -> Wake {
        let mut descriptors = [
            PollFd::new(self.peer.as_fd(), PollFlags::POLLIN),
            PollFd::new(self.parent.as_fd(), PollFlags::POLLIN),
            PollFd::new(mountinfo.as_fd(), PollFlags::POLLPRI),
        ];

        match poll(
            &mut descriptors,
            PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX),
        ) {
            Ok(0) | Err(Errno::EINTR) => Wake::Idle,
            Ok(_) => {
                let ready = |descriptor: &PollFd<'_>| {
                    descriptor
                        .revents()
                        .is_some_and(|events| !events.is_empty())
                };
                if descriptors[..2].iter().any(ready) {
                    Wake::Ended
                } else {
                    Wake::MountsChanged
                }
            }
            Err(error) => {
                tracing::warn!(%error, "cannot poll sandbox process handles");
                std::thread::sleep(timeout);
                Wake::Idle
            }
        }
    }
}

/// Why [`SandboxLifetime::wait`] returned.
enum Wake {
    Ended,
    MountsChanged,
    Idle,
}

/// Maximum ppid hops when searching for the sandbox's outer bwrap.
const MAX_ANCESTOR_HOPS: usize = 16;

/// Pid of the outer bwrap: the nearest ancestor of `peer` outside the peer's
/// user namespace.
fn outer_bwrap_pid(host_proc: &HostProc, peer: i32) -> Option<i32> {
    let peer_namespace = host_proc.read_link(peer, "ns/user").ok()?;
    let mut pid = peer;

    for _ in 0..MAX_ANCESTOR_HOPS {
        pid = host_proc.parent_pid(pid)?;
        if host_proc.read_link(pid, "ns/user").ok()? != peer_namespace {
            return Some(pid);
        }
    }

    None
}

/// A mount point entry parsed from /proc/self/mountinfo.
struct MountRecord {
    mount_point: PathBuf,
    fstype: String,
    readonly_filesystem: bool,
    fuse_owner: Option<FuseOwner>,
}

/// Owner of a FUSE mount, from its `user_id=`/`group_id=` super options.
/// Without `allow_other`, only processes with exactly these ids, root
/// included, can resolve paths on the mount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FuseOwner {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

impl FuseOwner {
    fn parse(fstype: &str, super_options: &str) -> Option<Self> {
        if fstype != "fuse" && !fstype.starts_with("fuse.") {
            return None;
        }

        let option = |key: &str| {
            super_options
                .split(',')
                .find_map(|option| option.strip_prefix(key)?.parse().ok())
        };

        Some(Self {
            uid: option("user_id=")?,
            gid: option("group_id=")?,
        })
    }
}

/// Returns true if the filesystem type is synthetic and should be skipped
/// when adding fanotify marks.
fn is_synthetic_fs(fstype: &str) -> bool {
    matches!(
        fstype,
        "proc"
            | "sysfs"
            | "cgroup"
            | "cgroup2"
            | "devpts"
            | "devtmpfs"
            | "pstore"
            | "bpf"
            | "tracefs"
            | "securityfs"
            | "debugfs"
            | "hugetlbfs"
            | "mqueue"
            | "nsfs"
            | "none"
            | "overlay"
            | "fuse.gvfsd-fuse"
            | "fuse.portal"
    )
}

/// Parse mountinfo text and return all mount entries with their fstype.
fn parse_mountinfo_content(content: &str) -> Vec<MountRecord> {
    let mut mounts = Vec::new();

    for line in content.lines() {
        // Format: id parent_id major:minor root mount_point options ... -
        // fstype source super_options
        let fields: Vec<&str> = line.split(' ').collect();

        if fields.len() < 9 {
            continue;
        }

        // Fields: 0=id, 1=parent, 2=dev, 3=root, 4=mount_point, ...
        // The separator `-` is at position fields.len()-4.
        let mount_point = fields[4];

        let sep_idx = fields.iter().position(|&f| f == "-");

        let fstype = sep_idx
            .and_then(|i| fields.get(i + 1))
            .copied()
            .unwrap_or("");
        let super_options = sep_idx
            .and_then(|i| fields.get(i + 3))
            .copied()
            .unwrap_or("");

        mounts.push(MountRecord {
            mount_point: PathBuf::from(mount_point),
            fstype: fstype.to_owned(),
            readonly_filesystem: super_options.split(',').any(|option| option == "ro"),
            fuse_owner: FuseOwner::parse(fstype, super_options),
        });
    }

    mounts
}

/// Return the deepest mount point that contains `target`.
fn deepest_covering_mount<'a>(mounts: &'a [MountRecord], target: &Path) -> Option<&'a Path> {
    mounts
        .iter()
        .filter(|mount| target.starts_with(&mount.mount_point))
        .max_by_key(|mount| mount.mount_point.as_os_str().len())
        .map(|mount| mount.mount_point.as_path())
}

/// Mark each mount point, skipping synthetic filesystem types. Returns whether
/// a marked mount covers `home`, or why monitoring under `home` cannot be
/// guaranteed.
fn mark_mountpoints(
    fan_fd: impl std::os::fd::AsFd,
    mounts: &[MountRecord],
    home: Option<&Path>,
) -> Result<bool, String> {
    let home_covering_mount = home.and_then(|home| deepest_covering_mount(mounts, home));
    let mut home_covered = false;

    for mount in mounts {
        let covers_home = home_covering_mount == Some(mount.mount_point.as_path());

        if is_synthetic_fs(&mount.fstype) {
            if covers_home {
                return Err(format!(
                    "--home {} is on unsupported synthetic filesystem {} at {}; cannot guarantee \
                     filesystem monitoring",
                    home.map_or_else(|| "?".into(), Path::to_string_lossy),
                    mount.fstype,
                    mount.mount_point.display()
                ));
            }

            tracing::debug!(
                path = %mount.mount_point.display(),
                fstype = %mount.fstype,
                "skipping synthetic mount"
            );

            continue;
        }

        let mp_cstr =
            CString::new(mount.mount_point.as_os_str().as_bytes()).expect("null in mount path");

        let marked = match (
            agent_sandbox_sysutil::fanotify_mark(&fan_fd, &mp_cstr),
            mount.fuse_owner,
        ) {
            (Err(error), Some(owner)) if error.raw_os_error() == Some(libc::EACCES) => {
                agent_sandbox_sysutil::fanotify_mark_as(&fan_fd, &mp_cstr, owner.uid, owner.gid)
            }
            (result, _) => result,
        };

        match marked {
            Ok(()) => {
                home_covered |= covers_home;
                tracing::debug!(path = %mount.mount_point.display(), "marked mountpoint");
            }

            Err(e)
                if covers_home || home.is_some_and(|home| mount.mount_point.starts_with(home)) =>
            {
                return Err(format!(
                    "fanotify_mark {} (under --home): {e}",
                    mount.mount_point.display()
                ));
            }

            Err(e) => {
                tracing::warn!(
                    path = %mount.mount_point.display(),
                    fstype = %mount.fstype,
                    error = %e,
                    "failed to mark mountpoint (not under home, continuing)"
                );
            }
        }
    }

    Ok(home_covered)
}

/// The target's mount table. Mounts that appear after startup, such as a FUSE
/// daemon started later or an automount, propagate into the sandbox unmarked
/// until they are marked here.
struct MountWatch {
    mountinfo: File,
    home: Option<PathBuf>,
}

impl MountWatch {
    /// Open before the first [`Self::read`]: every later change to the mount
    /// table raises `POLLPRI` on this descriptor.
    fn open(host_proc: &HostProc, pid: i32, home: Option<PathBuf>) -> io::Result<Self> {
        Ok(Self {
            mountinfo: host_proc.open_entry(pid, "mountinfo")?,
            home,
        })
    }

    fn read(&mut self) -> io::Result<Vec<MountRecord>> {
        let mut content = String::new();
        self.mountinfo.seek(SeekFrom::Start(0))?;
        self.mountinfo.read_to_string(&mut content)?;
        Ok(parse_mountinfo_content(&content))
    }
}

/// Mark the target's mounts again after its mount table changed. Repeating a
/// mark on an already marked mount only repeats its mask, so mount id reuse
/// cannot hide a new mount. A mount under home that cannot be marked would
/// leave part of home unmonitored, so the sandbox is stopped instead.
fn remark_mounts(shared: &Shared, watch: &mut MountWatch) {
    let result = watch
        .read()
        .map_err(|error| format!("cannot read target mountinfo: {error}"))
        .and_then(|mounts| {
            mark_mountpoints(&shared.gate.kernel().fd, &mounts, watch.home.as_deref())
        });

    let Err(reason) = result else {
        return;
    };

    tracing::error!(%reason, "new mount cannot be monitored; stopping sandbox");
    if let Err(error) = shared.lifetime.stop(Duration::ZERO) {
        tracing::error!(%error, "cannot stop sandbox; the new mount stays unmonitored");
    }
}

/// Maximum concurrent permission decisions. Each worker reads one event from
/// the bounded kernel queue before answering it, including any approval wait.
const WORKER_LIMIT: usize = 4;

/// The fanotify group events are read from and answered through.
struct Fanotify {
    fd: OwnedFd,
}

impl Kernel for Fanotify {
    fn answer(&self, event_fd: &OwnedFd, answer: Answer) {
        let response = FanotifyResponse {
            fd: event_fd.as_raw_fd(),
            response: match answer {
                Answer::Allow => FAN_ALLOW,
                Answer::Deny => FAN_DENY,
            },
        };

        let bytes = fanotify_response_bytes(&response);

        if let Err(error) = nix::unistd::write(&self.fd, bytes) {
            tracing::warn!(%error, "failed to send fanotify response");
        }
    }

    fn mark_ignore(&self, event_fd: &OwnedFd, mask: u64) -> io::Result<()> {
        fanotify_mark_ignore(&self.fd, event_fd, mask)
    }

    fn flush_marks(&self) -> io::Result<()> {
        fanotify_flush_inode_marks(&self.fd)
    }
}

/// Stops the sandbox through its launcher. The fanotify group and the policy
/// writer stay alive meanwhile.
struct LauncherStop {
    lifetime: Arc<SandboxLifetime>,
}

impl SandboxStop for LauncherStop {
    fn stop_sandbox(&self) -> io::Result<()> {
        self.lifetime.stop(Duration::ZERO)
    }

    fn request_shutdown(&self) {
        request_shutdown(0);
    }
}

struct Shared {
    gate: PermissionGate<Fanotify>,
    lifetime: Arc<SandboxLifetime>,
}

/// How often the control loop logs the decision counters.
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum delay before the control loop observes shutdown or logs counters.
const CONTROL_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Set by the terminate handler; the control loop flushes ignore marks, logs
/// the final counters, and exits on its next iteration.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Log the decision counters as one structured line.
fn log_stats(counts: DecisionCounts, reason: &str) {
    tracing::info!(
        events = counts.events,
        local_answers = counts.local_answers,
        policyd_calls = counts.policyd_calls,
        marks_added = counts.marks_added,
        marks_flushed = counts.marks_flushed,
        reason,
        "fsmon decisions",
    );
}

/// Run permission readers and policy refresh independently of the control
/// loop, so shutdown and counters remain responsive even during approval waits.
fn run_event_loop(shared: Shared, mut mount_watch: MountWatch) {
    let shared = Arc::new(shared);

    for _ in 0..std::thread::available_parallelism()
        .map_or(1, |parallelism| parallelism.get().min(WORKER_LIMIT))
        .max(1)
    {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || worker(&shared));
    }

    let refresh_shared = Arc::clone(&shared);
    std::thread::spawn(move || refresh_policy(&refresh_shared));
    let mut last_stats_log = Instant::now();

    loop {
        let wake = shared
            .lifetime
            .wait(&mount_watch.mountinfo, CONTROL_POLL_INTERVAL);
        if matches!(wake, Wake::MountsChanged) {
            remark_mounts(&shared, &mut mount_watch);
        }
        let sandbox_ended = matches!(wake, Wake::Ended);

        if sandbox_ended {
            tracing::info!("sandbox ended; stopping its launcher");
            if shared.lifetime.can_stop()
                && let Err(error) = shared.lifetime.stop(LAUNCHER_EXIT_GRACE)
            {
                tracing::error!(%error, "cannot stop sandbox launcher");
            }
        }

        if sandbox_ended || SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            tracing::info!("flushing ignore marks before exit");
            let _revoked = shared.gate.revoke_grants();
            log_stats(shared.gate.counts(), "shutdown");
            return;
        }

        run_periodic_work(&shared, &mut last_stats_log);
    }
}

/// Snapshot I/O runs independently of the permission workers because the
/// monitor's own opens can generate permission events.
fn refresh_policy(shared: &Shared) {
    shared
        .gate
        .follow_policy(|| SHUTDOWN_REQUESTED.load(Ordering::Relaxed))
        .expect("tokio runtime");
}

fn run_periodic_work(shared: &Shared, last_stats_log: &mut Instant) {
    if last_stats_log.elapsed() >= STATS_LOG_INTERVAL {
        *last_stats_log = Instant::now();
        log_stats(shared.gate.counts(), "interval");
    }
}

/// Read permission events until killed and hand each to the gate. Fanotify
/// distributes events to the workers through its shared kernel queue.
fn worker(shared: &Shared) -> ! {
    let mut decisions = shared.gate.worker().expect("tokio runtime");
    let fan_fd = &shared.gate.kernel().fd;
    // FAN_REPORT_TID adds no information records. Reading one metadata record
    // leaves later events available to workers whose policy calls are ready.
    let mut buf = [0u8; size_of::<FanotifyEventMetadata>()];

    loop {
        let length = match nix::unistd::read(fan_fd, &mut buf) {
            Ok(length) => length,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::EBADF | nix::errno::Errno::EINVAL) => {
                tracing::error!("fanotify fd became invalid; stopping worker");
                request_shutdown(0);
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            Err(error) => {
                eprintln!("agent-sandbox-fsmon: read from fanotify fd: {error}");
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let Some(meta) = agent_sandbox_sysutil::fanotify_event(&buf[..length]) else {
            continue;
        };
        let Some(event_fd) = take_fanotify_event_fd(meta.fd) else {
            continue;
        };
        if meta.mask & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM) == 0 {
            continue;
        }
        decisions.decide(PermissionEvent {
            mask: meta.mask,
            pid: meta.pid,
            event_fd,
        });
    }
}

/// Join the mount namespace of `target_pid`, refusing when it is our own.
fn join_target_mount_namespace(target_pid: u32) {
    let ns_path = format!("/proc/{target_pid}/ns/mnt");

    // Defense in depth: never mark our own (host) mount namespace. A wrong
    // --pid (e.g. a namespace-local pid like 1 resolving to systemd) would
    // otherwise put FAN_OPEN_PERM marks on every host mount and gate every
    // file access on the machine through policyd.
    match (fs::metadata("/proc/self/ns/mnt"), fs::metadata(&ns_path)) {
        (Ok(self_ns), Ok(target_ns))
            if self_ns.dev() == target_ns.dev() && self_ns.ino() == target_ns.ino() =>
        {
            eprintln!(
                "agent-sandbox-fsmon: refusing to monitor pid {target_pid}: it shares this \
                 process's own mount namespace (would mark every host mount)"
            );
            process::exit(1);
        }

        (Err(e), _) | (_, Err(e)) => {
            eprintln!("agent-sandbox-fsmon: cannot compare mount namespaces ({ns_path}): {e}");
            process::exit(1);
        }

        _ => {}
    }

    if let Err(e) = agent_sandbox_sysutil::join_mount_namespace(target_pid) {
        eprintln!("agent-sandbox-fsmon: setns {ns_path}: {e}");
        process::exit(1);
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let self_pid = i32::try_from(process::id()).unwrap_or_else(|_| {
        eprintln!("agent-sandbox-fsmon: process id does not fit in pid_t");
        process::exit(1);
    });

    // Open fanotify fd.
    let agent_sandbox_sysutil::FanotifyInit { fd, reports_tid } =
        agent_sandbox_sysutil::fanotify_init_content().unwrap_or_else(|e| {
            eprintln!("agent-sandbox-fsmon: fanotify_init failed: {e}");
            process::exit(1);
        });

    if !reports_tid {
        eprintln!("agent-sandbox-fsmon: FAN_REPORT_TID is required to identify the opener safely");
        process::exit(1);
    }

    // Open host procfs before setns. After joining the sandbox mount namespace,
    // `/proc` no longer resolves tracee PIDs reported by fanotify.
    let host_proc = HostProc::open().unwrap_or_else(|e| {
        eprintln!("agent-sandbox-fsmon: open host /proc: {e}");
        process::exit(1);
    });

    // Resolve the request context before joining the sandbox mount namespace.
    // wire_context reads /run/agent-sandbox/shared/session-context.json, and
    // after mark_mountpoints installs FAN_OPEN_PERM marks below, that read
    // would raise a permission event to our own fanotify group. The event loop
    // that answers it starts only after this read returns, so the read would
    // deadlock (the process wedges in the kernel, state D).
    let mut ctx = wire_context(
        cli.cwd,
        cli.home.clone(),
        cli.project_root.clone(),
        ProcessIds::default(),
        std::env::var("AGENT_SANDBOX_SESSION_ID").ok(),
    );
    ctx.pid = Some(cli.pid);

    let target_pid = i32::try_from(cli.pid).unwrap_or_else(|_| {
        eprintln!("agent-sandbox-fsmon: --pid does not fit in pid_t");
        process::exit(1);
    });

    // Read mountinfo through the host procfs before entering the target
    // namespace. The watch stays open to mark mounts added later.
    let mut mount_watch = MountWatch::open(&host_proc, target_pid, cli.home.clone())
        .unwrap_or_else(|e| {
            eprintln!("agent-sandbox-fsmon: failed to open target mountinfo: {e}");
            process::exit(1);
        });
    let mounts = mount_watch.read().unwrap_or_else(|e| {
        eprintln!("agent-sandbox-fsmon: failed to parse target mountinfo: {e}");
        process::exit(1);
    });
    let sandbox_cgroup = CgroupPath::read(&host_proc, target_pid).unwrap_or_else(|| {
        eprintln!("agent-sandbox-fsmon: cannot read target cgroup membership");
        process::exit(1);
    });
    // Open the process pidfds before setns.
    let lifetime = SandboxLifetime::open(&host_proc, cli.pid).unwrap_or_else(|error| {
        eprintln!("agent-sandbox-fsmon: cannot watch sandbox processes: {error}");
        process::exit(1);
    });

    let mut snapshots = PolicydRpc::new(PersistentRpcClient::new(cli.socket.clone()), ctx.clone())
        .expect("tokio runtime");
    let policy = FilesystemReplica::fetch(&mut snapshots, cli.project_root);
    drop(snapshots);

    // setns into the target mount namespace before marking its mounts.
    join_target_mount_namespace(cli.pid);

    let readonly_devices = mounts
        .iter()
        .filter(|mount| mount.readonly_filesystem)
        .filter_map(|mount| {
            fs::metadata(&mount.mount_point)
                .ok()
                .map(|metadata| metadata.dev())
        })
        .collect();

    let home_covered =
        mark_mountpoints(&fd, &mounts, cli.home.as_deref()).unwrap_or_else(|reason| {
            eprintln!("agent-sandbox-fsmon: {reason}");
            process::exit(1);
        });

    // Before signaling ready, require that at least one marked mount covers
    // --home.
    if let Some(home) = &cli.home
        && !home_covered
    {
        eprintln!(
            "agent-sandbox-fsmon: no successfully marked mount covers --home {}; cannot guarantee \
             filesystem monitoring",
            home.display()
        );

        process::exit(1);
    }

    // Signal readiness.
    println!("ready");

    let _ = io::stdout().flush();

    // Ask the control loop to flush ignore marks and exit on SIGTERM/SIGINT.
    // Closing the fanotify fd would drop the marks anyway; the explicit flush
    // keeps the unmark path exercised and the counters exact.
    if let Err(error) = agent_sandbox_sysutil::install_shutdown_signals(request_shutdown) {
        tracing::warn!(%error, "cannot install shutdown signals; ignore marks will not be flushed");
    }

    let lifetime = Arc::new(lifetime);
    let ignore_marks = (cli.fs_ignore_static_allows && lifetime.can_stop()).then(|| {
        IgnoreMarks::new(
            readonly_devices,
            Box::new(LauncherStop {
                lifetime: Arc::clone(&lifetime),
            }),
        )
    });

    run_event_loop(
        Shared {
            gate: PermissionGate::new(GateSetup {
                kernel: Fanotify { fd },
                self_pid,
                sandbox_cgroup,
                host_proc,
                ctx,
                socket_path: cli.socket,
                policy,
                ignore_marks,
            }),
            lifetime,
        },
        mount_watch,
    );
}

/// Note a terminate request for the control loop. Runs in signal context:
/// only a lock-free atomic store.
extern "C" fn request_shutdown(_signum: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    fn test_host_proc() -> HostProc {
        HostProc::open().expect("open host proc")
    }

    #[test]
    fn stop_kills_the_launcher_and_a_missing_launcher_is_an_error() {
        let host_proc = test_host_proc();
        let mut peer = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn peer");
        let mut launcher = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn launcher");
        let mut lifetime = SandboxLifetime::open(&host_proc, peer.id()).expect("watch peer");

        assert!(!lifetime.can_stop());
        lifetime
            .stop(Duration::ZERO)
            .expect_err("no launcher handle");

        lifetime.launcher = LauncherCapability::Controllable(
            agent_sandbox_sysutil::pidfd_open(launcher.id()).expect("open launcher pidfd"),
        );
        assert!(lifetime.can_stop());
        lifetime.stop(Duration::ZERO).expect("kill launcher");

        let status = launcher.wait().expect("reap launcher");

        assert!(!status.success(), "the launcher must die by signal");
        lifetime
            .stop(Duration::ZERO)
            .expect("an exited launcher is already stopped");
        peer.kill().expect("kill peer");
        peer.wait().expect("reap peer");
    }

    #[test]
    fn lifetime_ends_when_the_peer_exits() {
        let host_proc = test_host_proc();
        let mut peer = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn peer");
        let lifetime = SandboxLifetime::open(&host_proc, peer.id()).expect("watch peer");
        let mountinfo = File::open("/proc/self/mountinfo").expect("open mountinfo");

        assert!(!matches!(
            lifetime.wait(&mountinfo, Duration::from_millis(50)),
            Wake::Ended
        ));

        peer.kill().expect("kill peer");
        peer.wait().expect("reap peer");

        assert!(matches!(
            lifetime.wait(&mountinfo, Duration::from_secs(5)),
            Wake::Ended
        ));
    }

    #[test]
    fn tmpfs_is_not_synthetic() {
        assert!(!is_synthetic_fs("tmpfs"));
    }

    #[test]
    fn proc_and_sysfs_remain_synthetic() {
        assert!(is_synthetic_fs("proc"));
        assert!(is_synthetic_fs("sysfs"));
        assert!(is_synthetic_fs("cgroup2"));
    }

    #[test]
    fn fuse_owner_comes_from_super_options_of_fuse_mounts_only() {
        let mounts = parse_mountinfo_content(
            "578 55 0:219 / /home/tim/checkouts rw,nosuid,nodev,noatime shared:1091 - fuse.ovnfs \
             ovnfs rw,user_id=1000,group_id=100,default_permissions,max_read=1048576\n90 30 0:50 \
             / /mnt/gdrive rw,nosuid,nodev,relatime shared:60 - fuse.rclone gdrive: \
             rw,user_id=0,group_id=0,allow_other\n55 1 0:33 /home /home rw,noatime shared:5 - \
             btrfs /dev/nvme1n1p2 rw,user_id=7,group_id=7\n91 30 0:51 / /mnt/broken rw shared:61 \
             - fuse.x x rw,user_id=1000\n",
        );
        let owners: Vec<_> = mounts.iter().map(|mount| mount.fuse_owner).collect();

        assert_eq!(owners, [
            Some(FuseOwner {
                uid: 1000,
                gid: 100
            }),
            Some(FuseOwner { uid: 0, gid: 0 }),
            None,
            None,
        ]);
    }

    #[test]
    fn context_arguments_declare_environment_defaults() {
        use clap::CommandFactory;

        let command = Cli::command();

        for (argument, environment) in [
            ("cwd", "AGENT_SANDBOX_CWD"),
            ("home", "AGENT_SANDBOX_HOME"),
            ("project_root", "AGENT_SANDBOX_PROJECT_ROOT"),
        ] {
            let argument = command
                .get_arguments()
                .find(|candidate| candidate.get_id().as_str() == argument)
                .expect("context argument should exist");

            assert_eq!(
                argument.get_env().and_then(|value| value.to_str()),
                Some(environment)
            );
        }
    }
}

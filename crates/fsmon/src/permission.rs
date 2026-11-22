//! Permission decisions for fanotify open events.
//!
//! A [`PermissionGate`] carries one permission event to its answer: process
//! identity first, then the local policy replica, then policyd. It owns the
//! ignore marks derived from static allows and revokes them when the policy
//! changes. Kernel effects go through [`Kernel`].

mod blocked_open;
mod host_proc;

use std::{
    collections::HashSet,
    io,
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    sync::{
        Mutex, RwLockWriteGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use agent_sandbox_core::{
    FileAccess, FilesystemReplica, InodeIdentity, LocalFilesystem, PersistentRpcClient, PolicydRpc,
    REFRESH_INTERVAL, RequestContext, StaticPolicyAllow, normalize_directory_traverse_access,
};
use agent_sandbox_sysutil::{FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM};
use nix::sys::stat::{SFlag, fstat};

use self::blocked_open::{EventPath, mask_to_access, resolve_blocked_open_path};
pub use self::host_proc::{CgroupPath, HostProc};
use crate::MonitorClient;

/// Answer to one permission event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Answer {
    /// The open proceeds.
    Allow,
    /// The open fails.
    Deny,
}

/// Kernel effects of permission decisions.
pub trait Kernel {
    /// Answer the permission event that owns `event_fd`.
    fn answer(&self, event_fd: &OwnedFd, answer: Answer);

    /// Stop reporting the permission events in `mask` for the inode
    /// `event_fd` pins.
    ///
    /// # Errors
    /// Returns the error from installing the mark.
    fn mark_ignore(&self, event_fd: &OwnedFd, mask: u64) -> io::Result<()>;

    /// Remove every ignore mark, including those whose pathname changed.
    ///
    /// # Errors
    /// Returns the error from flushing the marks.
    fn flush_marks(&self) -> io::Result<()>;
}

/// Last resort when ignore marks cannot be revoked.
pub trait SandboxStop {
    /// Stop every process of the sandbox.
    ///
    /// # Errors
    /// Returns an error when the sandbox cannot be stopped.
    fn stop_sandbox(&self) -> io::Result<()>;

    /// Ask the monitor to exit; its marks end with its fanotify group.
    fn request_shutdown(&self);
}

/// One fanotify permission event, owned until its answer.
pub struct PermissionEvent {
    /// Event mask reported by the kernel.
    pub mask: u64,
    /// Thread id of the opener in the host pid namespace.
    pub pid: i32,
    /// Descriptor the kernel opened on the file being opened.
    pub event_fd: OwnedFd,
}

/// Maximum tracked ignore-marked paths.
pub const IGNORE_MARK_CAP: usize = 65536;

/// Ignore marks for statically allowed files the sandbox can never write.
///
/// A mark is a kernel grant, so marks exist only together with a way to stop
/// the sandbox when they cannot be revoked.
pub struct IgnoreMarks {
    readonly_devices: HashSet<u64>,
    stop: Box<dyn SandboxStop + Send + Sync>,
    marked: Mutex<HashSet<PathBuf>>,
    cap_warned: AtomicBool,
}

impl IgnoreMarks {
    /// Marks for regular files on `readonly_devices` and for root-owned ones,
    /// with `stop` as the fallback when they cannot be revoked.
    #[must_use]
    pub fn new(readonly_devices: HashSet<u64>, stop: Box<dyn SandboxStop + Send + Sync>) -> Self {
        Self {
            readonly_devices,
            stop,
            marked: Mutex::new(HashSet::new()),
            cap_warned: AtomicBool::new(false),
        }
    }
}

/// Decision counters. Relaxed atomics: workers bump them on the hot path
/// while the control loop samples them for the periodic log line.
#[derive(Debug, Default)]
struct Stats {
    events: AtomicU64,
    local_answers: AtomicU64,
    policyd_calls: AtomicU64,
    marks_added: AtomicU64,
    marks_flushed: AtomicU64,
}

/// A sample of the decision counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionCounts {
    /// Permission events handled.
    pub events: u64,
    /// Answers that needed no policyd call (fast path and static allows).
    pub local_answers: u64,
    /// Answers that called policyd.
    pub policyd_calls: u64,
    /// Ignore marks installed.
    pub marks_added: u64,
    /// Tracked paths released by a flush.
    pub marks_flushed: u64,
}

/// What a [`PermissionGate`] decides with.
pub struct GateSetup<K> {
    /// Kernel effects of the decisions.
    pub kernel: K,
    /// Pid of the monitor, whose own opens are always allowed.
    pub self_pid: i32,
    /// Cgroup of the sandbox; openers outside it are allowed unchecked.
    pub sandbox_cgroup: CgroupPath,
    /// Host procfs, for the pids fanotify reports.
    pub host_proc: HostProc,
    /// Request context sent with every policyd request.
    pub ctx: RequestContext,
    /// Path of the policyd socket.
    pub socket_path: PathBuf,
    /// Local copy of the sandbox's filesystem policy.
    pub policy: FilesystemReplica,
    /// Ignore marks, or `None` to keep every permission event flowing.
    pub ignore_marks: Option<IgnoreMarks>,
}

/// Decides the permission events of one sandbox.
///
/// A static allow is answered and marked under the policy read lock, and a
/// policy generation is replaced only under the write lock after the marks
/// are flushed, so no mark outlives the rules that granted it.
pub struct PermissionGate<K> {
    setup: GateSetup<K>,
    stats: Stats,
}

/// No event is answered from the policy, and no mark installed, until this
/// drops.
#[must_use]
pub struct GrantsRevoked<'gate> {
    _policy: RwLockWriteGuard<'gate, LocalFilesystem>,
}

struct RespondedEvent;

impl<K: Kernel> PermissionGate<K> {
    /// A gate deciding with `setup`.
    #[must_use]
    pub fn new(setup: GateSetup<K>) -> Self {
        Self {
            setup,
            stats: Stats::default(),
        }
    }

    /// The kernel adapter the gate answers through.
    pub const fn kernel(&self) -> &K {
        &self.setup.kernel
    }

    /// The decision counters as of now.
    #[must_use]
    pub fn counts(&self) -> DecisionCounts {
        let sample = |counter: &AtomicU64| counter.load(Ordering::Relaxed);

        DecisionCounts {
            events: sample(&self.stats.events),
            local_answers: sample(&self.stats.local_answers),
            policyd_calls: sample(&self.stats.policyd_calls),
            marks_added: sample(&self.stats.marks_added),
            marks_flushed: sample(&self.stats.marks_flushed),
        }
    }

    /// A worker with its own policyd connection, async runtime and sandbox
    /// membership cache.
    ///
    /// # Errors
    /// Returns the error from creating the worker's async runtime.
    pub fn worker(&self) -> io::Result<Worker<'_, K>> {
        Ok(Worker {
            gate: self,
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
            rpc: MonitorClient::new(self.setup.socket_path.clone()),
            sandbox_pids: HashSet::new(),
        })
    }

    /// Refetch the policy from policyd every [`REFRESH_INTERVAL`] until `stop`
    /// returns true, blocking the caller. A changed policy revokes the ignore
    /// marks before it answers any event.
    ///
    /// # Errors
    /// Returns the error from creating the snapshot source's async runtime.
    pub fn follow_policy(&self, stop: impl Fn() -> bool) -> io::Result<()> {
        let mut source = PolicydRpc::new(
            PersistentRpcClient::new(self.setup.socket_path.clone()),
            self.setup.ctx.clone(),
        )?;
        self.setup
            .policy
            .follow(&mut source, REFRESH_INTERVAL, stop, || {
                self.flush_or_stop_sandbox();
            });

        Ok(())
    }

    /// Revoke every ignore mark. No event is answered from the policy, and so
    /// no mark is installed, until the returned guard drops.
    pub fn revoke_grants(&self) -> GrantsRevoked<'_> {
        let policy = self.setup.policy.lock_exclusive();
        self.flush_or_stop_sandbox();

        GrantsRevoked { _policy: policy }
    }

    fn finish_event(&self, event_fd: &OwnedFd, answer: Answer) -> RespondedEvent {
        self.setup.kernel.answer(event_fd, answer);
        RespondedEvent
    }

    /// Allow an open that `policy` covers, then mark its inode. `policy`
    /// borrows the read guard, so the generation cannot be replaced, and its
    /// marks flushed, between the rule lookup and the mark.
    fn allow_statically(
        &self,
        policy: &LocalFilesystem,
        path: &EventPath,
        event_fd: &OwnedFd,
    ) -> RespondedEvent {
        let responded = self.finish_event(event_fd, Answer::Allow);
        self.maybe_mark_static_allow(policy.allow(), path, event_fd);
        self.stats.local_answers.fetch_add(1, Ordering::Relaxed);
        responded
    }

    /// Mark regular files the sandbox can never write: files on read-only
    /// superblocks, and root-owned files without group or other write bits
    /// (the unprivileged sandbox user cannot chmod them, and the group bits
    /// cap any ACL). Every hard link shares the content this open proved
    /// readable, and callers never mark a denied inode; a policy change
    /// flushes the marks.
    fn maybe_mark_static_allow(
        &self,
        static_allow: &StaticPolicyAllow,
        path: &EventPath,
        event_fd: &OwnedFd,
    ) {
        let Some(ignore) = &self.setup.ignore_marks else {
            return;
        };
        let Ok(stat) = fstat(event_fd) else {
            return;
        };
        let sandbox_read_only = ignore.readonly_devices.contains(&stat.st_dev)
            || (stat.st_uid == 0 && stat.st_mode & 0o022 == 0);
        if !SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFREG) || !sandbox_read_only {
            return;
        }
        let mut ignored = 0;
        if static_allow.allows(Path::new(&path.path), FileAccess::Read, path.resolution) {
            ignored |= FAN_OPEN_PERM;
        }
        if static_allow.allows(Path::new(&path.path), FileAccess::Execute, path.resolution) {
            ignored |= FAN_OPEN_EXEC_PERM;
        }
        if ignored == 0 {
            return;
        }

        let mut marked = ignore
            .marked
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let fs_path = Path::new(&path.path);
        if marked.contains(fs_path) {
            return;
        }
        if marked.len() >= IGNORE_MARK_CAP {
            if !ignore.cap_warned.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    cap = IGNORE_MARK_CAP,
                    "ignore-mark set full; no further paths will be marked"
                );
            }
            return;
        }

        // The event pins the inode even if its pathname changes.
        match self.setup.kernel.mark_ignore(event_fd, ignored) {
            Ok(()) => {
                marked.insert(fs_path.to_path_buf());
                drop(marked);
                self.stats.marks_added.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                drop(marked);
                tracing::debug!(path = %path.path, %error, "ignore mark failed; events for this path keep flowing");
            }
        }
    }

    /// Flush all inode marks, including those whose pathname changed. Runs
    /// under the policy write lock, which excludes new marks.
    fn flush_ignore_marks(&self, ignore: &IgnoreMarks) -> io::Result<()> {
        let mut marked = ignore
            .marked
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !marked.is_empty() {
            self.setup.kernel.flush_marks()?;
            let flushed = marked.len() as u64;
            marked.clear();
            drop(marked);
            self.stats
                .marks_flushed
                .fetch_add(flushed, Ordering::Relaxed);
        }
        Ok(())
    }

    /// An unremovable ignore mark must not survive as an unrevocable grant,
    /// so a failed flush stops the sandbox.
    fn flush_or_stop_sandbox(&self) {
        const MAX_FLUSH_STOP_ATTEMPTS: usize = 10;
        let Some(ignore) = &self.setup.ignore_marks else {
            return;
        };
        for _ in 0..MAX_FLUSH_STOP_ATTEMPTS {
            if let Err(error) = self.flush_ignore_marks(ignore) {
                tracing::error!(%error, "cannot revoke inode grants; stopping sandbox");
                match ignore.stop.stop_sandbox() {
                    Ok(()) => return,
                    Err(error) => {
                        tracing::error!(%error, "cannot stop sandbox after mark flush failure");
                    }
                }
                std::thread::sleep(REFRESH_INTERVAL);
            } else {
                return;
            }
        }
        tracing::error!("exhausted flush/stop retries; requesting monitor shutdown");
        ignore.stop.request_shutdown();
    }
}

/// One worker's decisions for a [`PermissionGate`].
pub struct Worker<'gate, K> {
    gate: &'gate PermissionGate<K>,
    runtime: tokio::runtime::Runtime,
    rpc: MonitorClient,
    sandbox_pids: HashSet<i32>,
}

impl<K: Kernel> Worker<'_, K> {
    /// Decide `event` and answer it through the kernel exactly once,
    /// installing an ignore mark for a statically allowed open. An
    /// unresolvable path, a policyd error and any reply but an allow are
    /// denied.
    pub fn decide(&mut self, event: PermissionEvent) {
        let _responded = self.respond(event);
    }

    fn respond(&mut self, event: PermissionEvent) -> RespondedEvent {
        let gate = self.gate;
        let setup = &gate.setup;
        let PermissionEvent {
            mask,
            pid,
            event_fd,
        } = event;

        gate.stats.events.fetch_add(1, Ordering::Relaxed);

        // The fast path answers from process identity (self pid, non-sandbox
        // cgroup), not from static policy, so no ignore mark applies here.
        match classify_fast_path(
            pid,
            setup.self_pid,
            &setup.sandbox_cgroup,
            &setup.host_proc,
            &mut self.sandbox_pids,
        ) {
            FastPathDecision::Allow => {
                gate.stats.local_answers.fetch_add(1, Ordering::Relaxed);
                return gate.finish_event(&event_fd, Answer::Allow);
            }
            FastPathDecision::Deny => {
                gate.stats.local_answers.fetch_add(1, Ordering::Relaxed);
                return gate.finish_event(&event_fd, Answer::Deny);
            }
            FastPathDecision::NeedsPolicy => {}
        }

        let Some(path) = resolve_blocked_open_path(&setup.host_proc, pid, &event_fd) else {
            tracing::warn!(pid, "path resolution failed, denying (fail-closed)");
            gate.stats.local_answers.fetch_add(1, Ordering::Relaxed);
            return gate.finish_event(&event_fd, Answer::Deny);
        };

        let access = {
            let policy = setup.policy.read();
            let inode_check = needs_inode_check(&event_fd, &policy);
            if !inode_check && !open_needs_access_lookup(mask, &path, policy.allow()) {
                return gate.allow_statically(&policy, &path, &event_fd);
            }
            let access = normalize_directory_traverse_access(
                Path::new(&path.path),
                mask_to_access(&setup.host_proc, mask, &event_fd, pid),
            );
            if !inode_check
                && policy
                    .allow()
                    .allows(Path::new(&path.path), access, path.resolution)
            {
                return gate.allow_statically(&policy, &path, &event_fd);
            }
            drop(policy);
            access
        };

        gate.stats.policyd_calls.fetch_add(1, Ordering::Relaxed);

        tracing::debug!(path = %path.path, ?access, pid, "filesystem check");
        let mut event_ctx = setup.ctx.clone();
        event_ctx.pid = u32::try_from(pid).ok();

        let reply = self.runtime.block_on(self.rpc.check_filesystem(
            Path::new(&path.path),
            access,
            event_ctx,
        ));

        let answer = match &reply {
            Ok(reply) if reply.verdict.allowed => Answer::Allow,
            _ => Answer::Deny,
        };

        if answer == Answer::Deny {
            tracing::info!(path = %path.path, ?access, "denied by policy");
        }

        gate.finish_event(&event_fd, answer)
    }
}

/// Whether the blocked open's access mode must be recovered from the tracee.
///
/// A static rule granting read-write (or all) access covers every access a
/// non-exec open can request, so the verdict is already known and
/// `/proc/<pid>/syscall` need not be read. Execute events and narrower grants
/// still need the real flags: a read-only grant must not admit a write.
fn open_needs_access_lookup(mask: u64, path: &EventPath, static_allow: &StaticPolicyAllow) -> bool {
    if mask & FAN_OPEN_EXEC_PERM != 0 {
        return true;
    }

    !static_allow.allows_literal(
        Path::new(&path.path),
        FileAccess::ReadWrite,
        path.resolution,
    )
}

/// Hard-linked regular files need policyd's deny-inode check when they alias
/// a denied inode, or when a link may postdate the denied inode set: `link`
/// updates the inode's ctime. Directory link counts describe subdirectories,
/// not file hard links.
fn needs_inode_check(event_fd: &OwnedFd, policy: &LocalFilesystem) -> bool {
    fstat(event_fd).map_or(true, |stat| {
        let changed_nanos =
            i128::from(stat.st_ctime) * 1_000_000_000 + i128::from(stat.st_ctime_nsec);
        SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFREG)
            && stat.st_nlink != 1
            && policy.hard_link_needs_policyd(
                &InodeIdentity {
                    inode: stat.st_ino,
                    device: stat.st_dev,
                },
                changed_nanos,
            )
    })
}

/// Fast-path allow checks that do not need a policyd RPC.
/// Returns `true` when the event was already handled.
///
/// `pid_cgroup_cache` remembers pids already proven to belong to the sandbox
/// cgroup. Every fanotify event otherwise costs two procfs reads (status for
/// the thread-group id, cgroup for membership). Both are immutable for the
/// lifetime of a process, and only sandbox-namespace processes can generate
/// events on the marked mounts, so only membership is cached: a reused pid
/// can only ever belong to another sandbox process, and a hypothetical host
/// process hitting a stale entry is still policy-mediated rather than
/// auto-allowed.
enum FastPathDecision {
    Allow,
    Deny,
    NeedsPolicy,
}

fn classify_fast_path(
    pid: i32,
    self_pid: i32,
    sandbox_cgroup: &CgroupPath,
    host_proc: &HostProc,
    pid_cgroup_cache: &mut HashSet<i32>,
) -> FastPathDecision {
    if pid == self_pid {
        return FastPathDecision::Allow;
    }

    if pid_cgroup_cache.insert(pid) {
        // First observation of this pid: classify its cgroup membership.
        let process_pid = host_proc.thread_group_id(pid).unwrap_or(pid);

        match sandbox_cgroup.contains(host_proc, process_pid) {
            Some(true) => {}

            Some(false) => {
                pid_cgroup_cache.remove(&pid);
                return FastPathDecision::Allow;
            }

            None => {
                pid_cgroup_cache.remove(&pid);
                return FastPathDecision::Deny;
            }
        }
    }

    FastPathDecision::NeedsPolicy
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::PathResolution;

    use super::*;

    fn static_allow(rule: &str) -> StaticPolicyAllow {
        let policy: agent_sandbox_core::Policy =
            serde_json::from_str(&format!("{{\"filesystem\": {{\"allow\": [{rule}]}}}}"))
                .expect("parse policy fixture");
        StaticPolicyAllow::from_policy(policy, None)
    }

    fn canonical(path: &str) -> EventPath {
        EventPath {
            path: path.to_owned(),
            resolution: PathResolution::Canonical,
        }
    }

    #[test]
    fn read_write_grant_skips_access_lookup_for_non_exec_opens_only() {
        let read_write = static_allow(r#"{"path": "/srv/project", "access": "read_write"}"#);
        assert!(!open_needs_access_lookup(
            FAN_OPEN_PERM,
            &canonical("/srv/project/file"),
            &read_write
        ));
        assert!(open_needs_access_lookup(
            FAN_OPEN_PERM,
            &canonical("/srv/elsewhere/file"),
            &read_write
        ));
        assert!(open_needs_access_lookup(
            FAN_OPEN_EXEC_PERM,
            &canonical("/srv/project/tool"),
            &read_write
        ));

        let all = static_allow(r#"{"path": "/srv/project", "access": "all"}"#);
        assert!(!open_needs_access_lookup(
            FAN_OPEN_PERM,
            &canonical("/srv/project/file"),
            &all
        ));

        let read_only = static_allow(r#"{"path": "/srv/project", "access": "read"}"#);
        assert!(
            open_needs_access_lookup(FAN_OPEN_PERM, &canonical("/srv/project/file"), &read_only),
            "a read-only grant must not admit a write without the tracee's flags"
        );
    }
}

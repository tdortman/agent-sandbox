//! Pause a sandbox's monotonic and boot-time clocks while its scope is frozen.
//!
//! A frozen cgroup stops running code but not `CLOCK_MONOTONIC`, so timeouts
//! inside the sandbox fire the moment it thaws. With the clock pause enabled
//! every sandbox runs in its own time namespace and, just before the thaw,
//! the `agent_sandbox_timens` kernel module subtracts the frozen time from
//! that namespace's offsets through `/dev/agent-sandbox-timens`. The request
//! names the scope's cgroup directory; the module refuses unless that cgroup
//! is frozen and holds every task of the namespace, so a pid that was
//! recycled into another sandbox between listing and opening cannot get that
//! sandbox rewound by this scope's frozen time.
//!
//! The rewound interval starts when the scope is seen frozen (`frozen 1` in
//! its `cgroup.events`, polled by a short-lived watcher) and ends just before
//! the thaw, so a clock inside the sandbox never moves back past the time
//! every task was stopped. The kernel can leave `frozen 0` there although
//! every task has stopped (a task waiting on a seccomp notification its
//! frozen broker already holds never does); then the interval starts
//! [`TRAP_GRACE`] after the freeze request, by which time every task has
//! stopped.
//!
//! Boot time is rewound by the same amount as monotonic time; a host suspend
//! during the freeze is not accounted for.

use std::{
    collections::HashSet,
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    thread,
    time::{Duration, Instant},
};

use tracing::{error, warn};

/// Control device of the `agent_sandbox_timens` kernel module.
const TIMENS_DEVICE: &str = "/dev/agent-sandbox-timens";

const OWN_TIME_NAMESPACE: &str = "/proc/self/ns/time";

/// How long after a freeze request every task of the scope is taken to have
/// stopped, whether or not `cgroup.events` says so.
const TRAP_GRACE: Duration = Duration::from_secs(1);

/// Interval at which the watcher reads `cgroup.events`; it bounds how late
/// the stop is noticed, and so how much of a freeze goes unrewound.
const TRAP_POLL: Duration = Duration::from_millis(5);

/// Longest rewind the module takes (`2^32` seconds).
const MAX_REWIND_NANOS: u64 = (1 << 32) * 1_000_000_000;

/// Most cgroups of a scope's tree whose processes are looked at for one
/// rewind.
const MAX_CGROUPS: usize = 256;

/// Most processes of a scope looked at for one rewind. A sandbox has one time
/// namespace, so a flood of processes only costs the thaw time.
const MAX_PIDS: usize = 16_384;

/// Mirror of the module's ioctl ABI (`agent_sandbox_timens.h`).
#[allow(
    unsafe_code,
    reason = "the ioctl wrapper nix generates is an unsafe fn"
)]
mod device {
    use std::{fs::File, io, os::fd::AsRawFd as _};

    /// `struct agent_sandbox_timens_rewind`.
    #[repr(C)]
    pub struct RewindRequest {
        pub ns_fd: i32,
        pub cgroup_fd: i32,
        pub flags: u32,
        pub reserved: u32,
        pub nanoseconds: u64,
    }

    nix::ioctl_write_ptr!(
        /// `AGENT_SANDBOX_TIMENS_REWIND`.
        timens_rewind,
        0xB7,
        2,
        RewindRequest
    );

    /// Subtract `nanoseconds` from the clocks of the time namespace
    /// `namespace` refers to. The module refuses unless `cgroup`, the frozen
    /// scope's directory, holds every task of that namespace.
    pub fn rewind(
        device: &File,
        namespace: &File,
        cgroup: &File,
        nanoseconds: u64,
    ) -> io::Result<()> {
        let request = RewindRequest {
            ns_fd: namespace.as_raw_fd(),
            cgroup_fd: cgroup.as_raw_fd(),
            flags: 0,
            reserved: 0,
            nanoseconds,
        };

        // SAFETY: `request` is a live `#[repr(C)]` mirror of the struct the
        // ioctl's request code sizes, and `device` is an open file.
        unsafe { timens_rewind(device.as_raw_fd(), &raw const request) }
            .map(drop)
            .map_err(io::Error::from)
    }
}

/// Identity of a namespace: the device and inode of its nsfs file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct NamespaceId {
    dev: u64,
    ino: u64,
}

impl NamespaceId {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}

/// Applies a rewind to one time namespace.
pub(super) trait TimeRewinder: Send + Sync {
    /// Subtract `nanoseconds` from the monotonic and boot-time clocks of
    /// `namespace`, which must have all its tasks in the frozen cgroup whose
    /// directory `cgroup` is.
    fn rewind(&self, namespace: &File, cgroup: &File, nanoseconds: u64) -> io::Result<()>;
}

struct TimensDevice {
    path: PathBuf,
}

impl TimeRewinder for TimensDevice {
    fn rewind(&self, namespace: &File, cgroup: &File, nanoseconds: u64) -> io::Result<()> {
        let device = File::options().read(true).write(true).open(&self.path)?;

        device::rewind(&device, namespace, cgroup, nanoseconds)
    }
}

/// Where a scope's unrewound frozen time starts: the instant every task is
/// known to have stopped, or the end of the last rewind when that is later.
#[derive(Clone)]
pub(super) struct FrozenSince {
    /// Latest instant by which every task is taken to have stopped.
    bound: Instant,
    /// When the watcher saw the scope frozen.
    stopped: Arc<Mutex<Option<Instant>>>,
    /// The end of the last successful rewind.
    rewound_to: Option<Instant>,
}

impl FrozenSince {
    /// Track a freeze requested on `scope` just now. A watcher thread polls
    /// the scope until it is frozen, the request is [`TRAP_GRACE`] old or
    /// this value and its clones are gone.
    pub(super) fn requested(scope: &Path) -> Self {
        let bound = Instant::now() + TRAP_GRACE;
        let stopped = Arc::new(Mutex::new(None));
        let watcher = Arc::clone(&stopped);
        let events = scope.join("cgroup.events");

        if let Err(error) = thread::Builder::new()
            .name("freeze-watch".to_owned())
            .spawn(move || watch_frozen(&events, &watcher, bound))
        {
            warn!(%error, "cannot watch a frozen scope; its clocks rewind from the grace bound");
        }

        Self {
            bound,
            stopped,
            rewound_to: None,
        }
    }

    /// A scope whose tasks stopped at `start`.
    #[cfg(test)]
    pub(super) fn at(start: Instant) -> Self {
        Self {
            bound: start,
            stopped: Arc::new(Mutex::new(Some(start))),
            rewound_to: None,
        }
    }

    /// Where the unrewound frozen time starts.
    pub(super) fn start(&self) -> Instant {
        let stopped = (*self.stopped.lock().unwrap_or_else(PoisonError::into_inner))
            .map_or(self.bound, |seen| seen.min(self.bound));

        self.rewound_to.map_or(stopped, |end| end.max(stopped))
    }

    /// Record that the frozen time up to `end` has been rewound.
    pub(super) const fn rewound_to(&mut self, end: Instant) {
        self.rewound_to = Some(end);
    }
}

/// Whether `cgroup.events` at `events` reports the cgroup frozen.
fn reports_frozen(events: &Path) -> bool {
    fs::read_to_string(events).is_ok_and(|text| text.lines().any(|line| line == "frozen 1"))
}

/// Record in `stopped` the instant `events` first reports the cgroup frozen,
/// stopping at `bound` or when the watcher holds the last reference.
fn watch_frozen(events: &Path, stopped: &Arc<Mutex<Option<Instant>>>, bound: Instant) {
    while Instant::now() < bound && Arc::strong_count(stopped) > 1 {
        if reports_frozen(events) {
            // Taken after the read, so the stop happened before it.
            *stopped.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());

            return;
        }

        thread::sleep(TRAP_POLL);
    }
}

pub(super) struct ClockPause {
    rewinder: Box<dyn TimeRewinder>,
    /// policyd's own time namespace, which is never rewound.
    own: Option<NamespaceId>,
}

impl ClockPause {
    /// Pause clocks through the kernel module's device. A missing device is
    /// logged once here; every later rewind then fails and is logged too, but
    /// never blocks a thaw.
    pub(super) fn open() -> Self {
        if !Path::new(TIMENS_DEVICE).exists() {
            error!(
                device = TIMENS_DEVICE,
                "clock pause is enabled but the agent_sandbox_timens kernel module is not loaded; \
                 sandboxes will see the frozen time on thaw"
            );
        }

        let own = fs::metadata(OWN_TIME_NAMESPACE)
            .map_err(|error| error!(%error, "cannot identify policyd's own time namespace"))
            .ok()
            .map(|metadata| NamespaceId::of(&metadata));

        Self::new(
            Box::new(TimensDevice {
                path: PathBuf::from(TIMENS_DEVICE),
            }),
            own,
        )
    }

    pub(super) fn new(rewinder: Box<dyn TimeRewinder>, own: Option<NamespaceId>) -> Self {
        Self { rewinder, own }
    }

    /// Rewind every time namespace in `scope` by the time it has been frozen
    /// since `since`, up to now, and return the instant that time ends at
    /// when a rewind succeeded (or there was nothing to rewind). A namespace
    /// whose rewind fails keeps its frozen time as elapsed time; rewinding
    /// the successful ones again later would move their clocks back past the
    /// freeze. Failures are logged; the caller thaws regardless.
    ///
    /// The directory scan runs first and the end of the interval is taken
    /// right before the first ioctl, so the scan's duration is rewound too.
    pub(super) fn rewind_frozen_time(&self, scope: &Path, since: &FrozenSince) -> Option<Instant> {
        let start = since.start();

        if Instant::now() <= start {
            return None;
        }

        let namespaces = match time_namespaces(scope, self.own) {
            Ok(namespaces) => namespaces,
            Err(error) => {
                warn!(
                    %error,
                    errno = ?error.raw_os_error(),
                    scope = %scope.display(),
                    "cannot list sandbox processes to rewind their clocks"
                );

                return None;
            }
        };

        // One directory handle per rewind: the module checks the namespaces
        // against this cgroup, not against the pids listed above.
        let cgroup = match File::open(scope) {
            Ok(cgroup) => cgroup,
            Err(error) => {
                warn!(
                    %error,
                    errno = ?error.raw_os_error(),
                    scope = %scope.display(),
                    "cannot open the scope cgroup to rewind sandbox clocks"
                );

                return None;
            }
        };

        let end = Instant::now();
        let nanoseconds = u64::try_from(end.saturating_duration_since(start).as_nanos())
            .map_or(MAX_REWIND_NANOS, |nanos| nanos.min(MAX_REWIND_NANOS));

        if nanoseconds == 0 {
            return None;
        }

        let mut rewound = namespaces.is_empty();

        for namespace in &namespaces {
            match self.rewinder.rewind(namespace, &cgroup, nanoseconds) {
                Ok(()) => rewound = true,
                Err(error) => warn!(
                    %error,
                    errno = ?error.raw_os_error(),
                    scope = %scope.display(),
                    nanoseconds,
                    "failed to rewind sandbox clocks; the thaw proceeds"
                ),
            }
        }

        rewound.then_some(end)
    }
}

/// The distinct time namespaces of the processes in `scope` and its
/// descendant cgroups (the first [`MAX_CGROUPS`] of them and the first
/// [`MAX_PIDS`] processes), leaving out `skip`. Processes that exit meanwhile
/// are skipped.
///
/// # Errors
///
/// Returns an error when the scope's own `cgroup.procs` cannot be read.
pub(super) fn time_namespaces(scope: &Path, skip: Option<NamespaceId>) -> io::Result<Vec<File>> {
    let mut pids = Vec::new();
    collect_pids(scope, &mut pids, &mut { MAX_CGROUPS })?;

    let mut seen: HashSet<NamespaceId> = skip.into_iter().collect();
    let mut namespaces = Vec::new();

    for pid in pids.into_iter().take(MAX_PIDS) {
        let Ok(file) = File::open(format!("/proc/{pid}/ns/time")) else {
            continue;
        };
        let Ok(metadata) = file.metadata() else {
            continue;
        };
        let id = NamespaceId::of(&metadata);

        if seen.insert(id) {
            namespaces.push(file);
        }
    }

    Ok(namespaces)
}

/// Appends the pids of `cgroup` and its descendants, visiting at most
/// `budget` cgroups: a sandbox that can create cgroups under its scope must
/// not make the thaw walk an arbitrarily large tree.
fn collect_pids(cgroup: &Path, pids: &mut Vec<u32>, budget: &mut usize) -> io::Result<()> {
    let procs = fs::read_to_string(cgroup.join("cgroup.procs"))?;
    *budget = budget.saturating_sub(1);
    pids.extend(
        procs
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok()),
    );

    for entry in fs::read_dir(cgroup)?.flatten() {
        if *budget == 0 {
            break;
        }

        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            // A child cgroup removed meanwhile has no processes left.
            let _ = collect_pids(&entry.path(), pids, budget);
        }
    }

    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use std::{
        process::{Child, Command},
        sync::{Arc, Mutex, PoisonError},
    };

    use tempfile::tempdir;

    use super::*;

    /// Records the nanoseconds and the cgroup directory (by inode) of every
    /// rewind and fails them all when `fail` is set.
    #[derive(Clone, Default)]
    pub(in crate::store) struct RecordingRewinder {
        pub(in crate::store) nanoseconds: Arc<Mutex<Vec<u64>>>,
        pub(in crate::store) cgroups: Arc<Mutex<Vec<u64>>>,
        pub(in crate::store) fail: bool,
    }

    impl RecordingRewinder {
        /// The length of every rewind, in the order they were asked for.
        pub(in crate::store) fn recorded(&self) -> Vec<Duration> {
            self.nanoseconds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .copied()
                .map(Duration::from_nanos)
                .collect()
        }

        fn recorded_cgroups(&self) -> Vec<u64> {
            self.cgroups
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl TimeRewinder for RecordingRewinder {
        fn rewind(&self, _namespace: &File, cgroup: &File, nanoseconds: u64) -> io::Result<()> {
            self.nanoseconds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(nanoseconds);
            self.cgroups
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(cgroup.metadata()?.ino());

            if self.fail {
                Err(io::Error::from_raw_os_error(nix::libc::EBUSY))
            } else {
                Ok(())
            }
        }
    }

    pub(in crate::store) fn own_namespace() -> NamespaceId {
        NamespaceId::of(&fs::metadata(OWN_TIME_NAMESPACE).expect("own time namespace"))
    }

    pub(in crate::store) fn sleeper() -> Child {
        Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("sleep process starts")
    }

    pub(in crate::store) fn write_procs(cgroup: &Path, pids: &[u32]) {
        let lines: Vec<String> = pids.iter().map(u32::to_string).collect();

        fs::write(cgroup.join("cgroup.procs"), lines.join("\n")).expect("cgroup.procs");
    }

    /// A scope whose tasks stopped `seconds` ago.
    pub(in crate::store) fn stopped_for(seconds: u64) -> FrozenSince {
        FrozenSince::at(
            Instant::now()
                .checked_sub(Duration::from_secs(seconds))
                .expect("the monotonic clock has run for a few seconds"),
        )
    }

    /// Whether `rewound` is `expected` plus at most the time the test itself
    /// took.
    pub(in crate::store) fn is_about(rewound: Duration, expected: Duration) -> bool {
        rewound >= expected && rewound < expected + Duration::from_millis(500)
    }

    fn pause_with(rewinder: &RecordingRewinder, own: Option<NamespaceId>) -> ClockPause {
        ClockPause::new(Box::new(rewinder.clone()), own)
    }

    /// Poll until the watcher has recorded the stop of `since`.
    fn wait_until_seen(since: &FrozenSince) {
        let deadline = Instant::now() + Duration::from_secs(5);

        while since
            .stopped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
        {
            assert!(Instant::now() < deadline, "the stop was never seen");
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn struct_matches_the_kernel_abi() {
        assert_eq!(size_of::<device::RewindRequest>(), 24);
        // _IOW(0xB7, 2, struct agent_sandbox_timens_rewind)
        assert_eq!(nix::request_code_write!(0xB7, 2, 24), 0x4018_B702);
        assert_eq!(MAX_REWIND_NANOS, 4_294_967_296_000_000_000);
    }

    #[test]
    fn the_cgroup_walk_is_bounded() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[]);

        for index in 0..MAX_CGROUPS + 5 {
            let child = dir.path().join(format!("child{index}"));

            fs::create_dir(&child).expect("child cgroup");
            write_procs(&child, &[1]);
        }

        let mut pids = Vec::new();
        collect_pids(dir.path(), &mut pids, &mut { MAX_CGROUPS }).expect("pids");

        assert_eq!(pids.len(), MAX_CGROUPS - 1);
    }

    #[test]
    fn namespaces_are_deduplicated_across_nested_cgroups_and_skip_vanished_pids() {
        let dir = tempdir().expect("temporary directory");
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).expect("nested cgroup");

        let mut child = sleeper();
        write_procs(dir.path(), &[std::process::id(), u32::MAX >> 1]);
        write_procs(&nested, &[child.id()]);

        let namespaces = time_namespaces(dir.path(), None).expect("namespaces");
        child.kill().expect("kill sleeper");
        child.wait().expect("reap sleeper");

        assert_eq!(namespaces.len(), 1);

        let collected = namespaces[0].metadata().expect("namespace metadata");

        assert_eq!(NamespaceId::of(&collected), own_namespace());
    }

    #[test]
    fn the_skipped_namespace_is_not_collected() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[std::process::id()]);

        let namespaces = time_namespaces(dir.path(), Some(own_namespace())).expect("namespaces");

        assert!(namespaces.is_empty());
    }

    #[test]
    fn the_rewind_is_the_exact_time_since_the_stop() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[std::process::id()]);
        let rewinder = RecordingRewinder::default();
        let since = stopped_for(10);
        let start = since.start();

        let end = pause_with(&rewinder, None)
            .rewind_frozen_time(dir.path(), &since)
            .expect("the rewind succeeded");

        let recorded = rewinder.recorded();

        assert_eq!(recorded.len(), 1);
        assert!(
            is_about(recorded[0], Duration::from_secs(10)),
            "{recorded:?}"
        );
        assert_eq!(recorded[0], end.duration_since(start));
        assert_eq!(rewinder.recorded_cgroups(), vec![
            fs::metadata(dir.path()).expect("scope metadata").ino()
        ]);
    }

    #[test]
    fn a_second_rewind_covers_only_the_time_after_the_first() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[std::process::id()]);
        let rewinder = RecordingRewinder::default();
        let mut since = stopped_for(10);
        let pause = pause_with(&rewinder, None);

        let first = pause
            .rewind_frozen_time(dir.path(), &since)
            .expect("first rewind");
        since.rewound_to(first);
        thread::sleep(Duration::from_millis(20));
        let second = pause
            .rewind_frozen_time(dir.path(), &since)
            .expect("second rewind");

        let recorded = rewinder.recorded();

        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[1], second.duration_since(first));
        assert!(recorded[1] >= Duration::from_millis(20));
        assert!(recorded[1] < Duration::from_millis(500), "{recorded:?}");
    }

    #[test]
    fn a_scope_not_yet_taken_to_be_stopped_is_not_rewound() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[std::process::id()]);
        fs::write(dir.path().join("cgroup.events"), "populated 1\nfrozen 0\n").expect("events");
        let rewinder = RecordingRewinder::default();
        let since = FrozenSince::requested(dir.path());

        let end = pause_with(&rewinder, None).rewind_frozen_time(dir.path(), &since);

        assert_eq!(end, None);
        assert_eq!(rewinder.recorded(), Vec::<Duration>::new());
    }

    #[test]
    fn a_scope_seen_frozen_counts_from_the_sighting() {
        let dir = tempdir().expect("temporary directory");
        fs::write(dir.path().join("cgroup.events"), "populated 1\nfrozen 1\n").expect("events");
        let requested = Instant::now();
        let since = FrozenSince::requested(dir.path());

        wait_until_seen(&since);

        assert!(since.start() < requested + TRAP_GRACE);
        assert!(since.start() < requested + Duration::from_millis(500));
        assert!(since.start() >= requested);
    }

    #[test]
    fn a_scope_that_never_reports_frozen_counts_from_the_grace_bound() {
        let dir = tempdir().expect("temporary directory");
        // The state the kernel shows while one task cannot stop: the freeze
        // is requested, yet `cgroup.events` never reports it.
        fs::write(dir.path().join("cgroup.events"), "populated 1\nfrozen 0\n").expect("events");
        let requested = Instant::now();
        let since = FrozenSince::requested(dir.path());

        let start = since.start();

        assert!(start >= requested + TRAP_GRACE);
        assert!(start < requested + TRAP_GRACE + Duration::from_millis(500));
    }

    #[test]
    fn a_sighting_after_the_grace_bound_does_not_start_the_interval_later() {
        let bound = Instant::now();
        let since = FrozenSince {
            bound,
            stopped: Arc::new(Mutex::new(Some(bound + Duration::from_secs(3)))),
            rewound_to: None,
        };

        assert_eq!(since.start(), bound);
    }

    #[test]
    fn the_end_of_a_rewind_is_a_floor_for_the_next_interval() {
        let mut since = stopped_for(10);
        let end = Instant::now();

        since.rewound_to(end);

        assert_eq!(since.start(), end);
    }

    #[test]
    fn the_own_namespace_is_never_rewound() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[std::process::id()]);
        let rewinder = RecordingRewinder::default();
        let since = stopped_for(10);

        pause_with(&rewinder, Some(own_namespace())).rewind_frozen_time(dir.path(), &since);

        assert_eq!(rewinder.recorded(), Vec::<Duration>::new());
    }

    #[test]
    fn a_failed_rewind_reports_nothing_rewound() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[std::process::id()]);
        let rewinder = RecordingRewinder {
            fail: true,
            ..RecordingRewinder::default()
        };
        let since = stopped_for(10);

        let end = pause_with(&rewinder, None).rewind_frozen_time(dir.path(), &since);

        assert_eq!(end, None);
        assert_eq!(rewinder.recorded().len(), 1);
    }
}

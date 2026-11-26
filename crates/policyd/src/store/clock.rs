//! Pause a sandbox's monotonic and boot-time clocks while its scope is frozen.
//!
//! A frozen cgroup stops running code but not `CLOCK_MONOTONIC`, so timeouts
//! inside the sandbox fire the moment it thaws. With the clock pause enabled
//! every sandbox runs in its own time namespace and, just before the thaw,
//! the `agent_sandbox_timens` kernel module subtracts the frozen time from
//! that namespace's offsets through `/dev/agent-sandbox-timens`.
//!
//! Only whole seconds are rewound and the last second of the freeze is never
//! counted. Tasks may still run briefly after the freeze request until they
//! trap, so rewinding the full elapsed time could move a clock backwards.

use std::{
    collections::HashSet,
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use tracing::{error, warn};

/// Control device of the `agent_sandbox_timens` kernel module.
const TIMENS_DEVICE: &str = "/dev/agent-sandbox-timens";

const OWN_TIME_NAMESPACE: &str = "/proc/self/ns/time";

/// Part of the freeze left out of every rewind.
const REWIND_MARGIN: Duration = Duration::from_secs(1);

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
        pub flags: u32,
        pub seconds: u64,
    }

    nix::ioctl_write_ptr!(
        /// `AGENT_SANDBOX_TIMENS_REWIND`.
        timens_rewind,
        0xB7,
        1,
        RewindRequest
    );

    /// Subtract `seconds` from the clocks of the time namespace `namespace`
    /// refers to.
    pub fn rewind(device: &File, namespace: &File, seconds: u64) -> io::Result<()> {
        let request = RewindRequest {
            ns_fd: namespace.as_raw_fd(),
            flags: 0,
            seconds,
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

/// An open `/proc/<pid>/ns/time`. The descriptor keeps the namespace alive
/// and is what the rewind ioctl takes.
pub(super) struct TimeNamespace {
    file: File,
}

/// Applies a rewind to one time namespace.
pub(super) trait TimeRewinder: Send + Sync {
    /// Subtract `seconds` from the monotonic and boot-time clocks of
    /// `namespace`.
    fn rewind(&self, namespace: &File, seconds: u64) -> io::Result<()>;
}

struct TimensDevice {
    path: PathBuf,
}

impl TimeRewinder for TimensDevice {
    fn rewind(&self, namespace: &File, seconds: u64) -> io::Result<()> {
        let device = File::options().read(true).write(true).open(&self.path)?;

        device::rewind(&device, namespace, seconds)
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

    /// Rewind every time namespace in `scope` by the whole seconds the scope
    /// has been frozen since `frozen_since`, less the margin, and restart the
    /// count from now when every rewind succeeded. Failures are logged; the
    /// caller thaws regardless.
    pub(super) fn rewind_frozen_time(&self, scope: &Path, frozen_since: &mut Instant) {
        let seconds = frozen_since
            .elapsed()
            .saturating_sub(REWIND_MARGIN)
            .as_secs();

        if seconds == 0 {
            return;
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

                return;
            }
        };

        let mut rewound = true;

        for namespace in &namespaces {
            if let Err(error) = self.rewinder.rewind(&namespace.file, seconds) {
                warn!(
                    %error,
                    errno = ?error.raw_os_error(),
                    scope = %scope.display(),
                    seconds,
                    "failed to rewind sandbox clocks; the thaw proceeds"
                );

                rewound = false;
            }
        }

        if rewound {
            *frozen_since = Instant::now();
        }
    }
}

/// The distinct time namespaces of the processes in `scope` and its
/// descendant cgroups, leaving out `skip`. Processes that exit meanwhile are
/// skipped.
///
/// # Errors
///
/// Returns an error when the scope's own `cgroup.procs` cannot be read.
pub(super) fn time_namespaces(
    scope: &Path,
    skip: Option<NamespaceId>,
) -> io::Result<Vec<TimeNamespace>> {
    let mut pids = Vec::new();
    collect_pids(scope, &mut pids)?;

    let mut seen: HashSet<NamespaceId> = skip.into_iter().collect();
    let mut namespaces = Vec::new();

    for pid in pids {
        let Ok(file) = File::open(format!("/proc/{pid}/ns/time")) else {
            continue;
        };
        let Ok(metadata) = file.metadata() else {
            continue;
        };
        let id = NamespaceId::of(&metadata);

        if seen.insert(id) {
            namespaces.push(TimeNamespace { file });
        }
    }

    Ok(namespaces)
}

fn collect_pids(cgroup: &Path, pids: &mut Vec<u32>) -> io::Result<()> {
    let procs = fs::read_to_string(cgroup.join("cgroup.procs"))?;
    pids.extend(
        procs
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok()),
    );

    for entry in fs::read_dir(cgroup)?.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            // A child cgroup removed meanwhile has no processes left.
            let _ = collect_pids(&entry.path(), pids);
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

    /// Records the seconds of every rewind and fails them all when `fail` is
    /// set.
    #[derive(Clone, Default)]
    pub(in crate::store) struct RecordingRewinder {
        pub(in crate::store) seconds: Arc<Mutex<Vec<u64>>>,
        pub(in crate::store) fail: bool,
    }

    impl RecordingRewinder {
        pub(in crate::store) fn recorded(&self) -> Vec<u64> {
            self.seconds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl TimeRewinder for RecordingRewinder {
        fn rewind(&self, _namespace: &File, seconds: u64) -> io::Result<()> {
            self.seconds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(seconds);

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

    fn frozen_for(seconds: u64) -> Instant {
        Instant::now()
            .checked_sub(Duration::from_secs(seconds))
            .expect("the monotonic clock has run for a few seconds")
    }

    fn pause_with(rewinder: &RecordingRewinder, own: Option<NamespaceId>) -> ClockPause {
        ClockPause::new(Box::new(rewinder.clone()), own)
    }

    #[test]
    fn struct_matches_the_kernel_abi() {
        assert_eq!(size_of::<device::RewindRequest>(), 16);
        // _IOW(0xB7, 1, struct agent_sandbox_timens_rewind)
        assert_eq!(nix::request_code_write!(0xB7, 1, 16), 0x4010_B701);
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

        let collected = namespaces[0].file.metadata().expect("namespace metadata");

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
    fn a_short_freeze_is_not_rewound() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[std::process::id()]);
        let rewinder = RecordingRewinder::default();
        let mut frozen_since = frozen_for(1);
        let before = frozen_since;

        pause_with(&rewinder, None).rewind_frozen_time(dir.path(), &mut frozen_since);

        assert_eq!(rewinder.recorded(), Vec::<u64>::new());
        assert_eq!(frozen_since, before);
    }

    #[test]
    fn a_long_freeze_rewinds_whole_seconds_less_the_margin_and_restarts_the_count() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[std::process::id()]);
        let rewinder = RecordingRewinder::default();
        let mut frozen_since = frozen_for(10);
        let before = frozen_since;

        pause_with(&rewinder, None).rewind_frozen_time(dir.path(), &mut frozen_since);

        assert_eq!(rewinder.recorded(), vec![9]);
        assert!(frozen_since > before);
    }

    #[test]
    fn the_own_namespace_is_never_rewound() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[std::process::id()]);
        let rewinder = RecordingRewinder::default();
        let mut frozen_since = frozen_for(10);

        pause_with(&rewinder, Some(own_namespace()))
            .rewind_frozen_time(dir.path(), &mut frozen_since);

        assert_eq!(rewinder.recorded(), Vec::<u64>::new());
    }

    #[test]
    fn a_failed_rewind_keeps_the_frozen_time_for_the_next_attempt() {
        let dir = tempdir().expect("temporary directory");
        write_procs(dir.path(), &[std::process::id()]);
        let rewinder = RecordingRewinder {
            fail: true,
            ..RecordingRewinder::default()
        };
        let mut frozen_since = frozen_for(10);
        let before = frozen_since;

        pause_with(&rewinder, None).rewind_frozen_time(dir.path(), &mut frozen_since);

        assert_eq!(rewinder.recorded(), vec![9]);
        assert_eq!(frozen_since, before);
    }
}

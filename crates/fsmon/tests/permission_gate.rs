//! Permission decisions through the monitor library's public interface.
//!
//! Only the kernel seam and the sandbox stop handle are recorded. Process
//! identity comes from the real `/proc`, event descriptors are real files in
//! a scratch directory, and policyd is a listener on a real unix socket.

use std::{
    collections::HashSet,
    fs,
    fs::File,
    io,
    io::{BufRead, BufReader, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            fs::MetadataExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::SystemTime,
};

use agent_sandbox_core::{
    FileAccess, FilesystemCheckReply, FilesystemReplica, FilesystemRule, FilesystemSection,
    FilesystemSnapshot, RequestContext, RpcMessage, RpcReply, RpcRequest, VerdictSource,
};
use agent_sandbox_fsmon::permission::{
    Answer, CgroupPath, GateSetup, HostProc, IGNORE_MARK_CAP, IgnoreMarks, Kernel, PermissionEvent,
    PermissionGate, SandboxStop,
};
use agent_sandbox_sysutil::FAN_OPEN_PERM;
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::{Mode, mkdirat},
};

/// One thing the gate asked of the kernel or of the sandbox stop handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Effect {
    Answered { answer: Answer },
    Marked { mask: u64 },
    Flushed,
    SandboxStopped,
    ShutdownRequested,
}

const ALLOWED: Effect = Effect::Answered {
    answer: Answer::Allow,
};
const DENIED: Effect = Effect::Answered {
    answer: Answer::Deny,
};
const MARKED_FOR_OPEN: Effect = Effect::Marked {
    mask: FAN_OPEN_PERM,
};

/// Effects in the order the gate caused them.
#[derive(Default)]
struct Log {
    effects: Mutex<Vec<Effect>>,
}

impl Log {
    fn push(&self, effect: Effect) {
        self.effects.lock().expect("effect log").push(effect);
    }

    fn effects(&self) -> Vec<Effect> {
        self.effects.lock().expect("effect log").clone()
    }
}

#[derive(Clone, Copy)]
enum Flush {
    Works,
    Fails,
}

struct RecordingKernel {
    log: Arc<Log>,
    flush: Flush,
}

impl Kernel for RecordingKernel {
    fn answer(&self, _event_fd: &OwnedFd, answer: Answer) {
        self.log.push(Effect::Answered { answer });
    }

    fn mark_ignore(&self, _event_fd: &OwnedFd, mask: u64) -> io::Result<()> {
        self.log.push(Effect::Marked { mask });
        Ok(())
    }

    fn flush_marks(&self) -> io::Result<()> {
        self.log.push(Effect::Flushed);
        match self.flush {
            Flush::Works => Ok(()),
            Flush::Fails => Err(io::Error::other("flush refused")),
        }
    }
}

struct RecordingStop {
    log: Arc<Log>,
}

impl SandboxStop for RecordingStop {
    fn stop_sandbox(&self) -> io::Result<()> {
        self.log.push(Effect::SandboxStopped);
        Ok(())
    }

    fn request_shutdown(&self) {
        self.log.push(Effect::ShutdownRequested);
    }
}

/// A directory, named as the kernel reports it, that is removed on drop.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "agent-sandbox-fsmon-gate-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).expect("create scratch directory");

        Self {
            dir: dir.canonicalize().expect("canonical scratch directory"),
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, b"x").expect("write fixture file");
        path
    }

    fn absent_socket(&self) -> PathBuf {
        self.dir.join("absent.sock")
    }

    /// A rule granting read-write access below the scratch directory.
    fn read_write_rule(&self) -> FilesystemRule {
        FilesystemRule::new(&self.dir, FileAccess::ReadWrite, "test")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

struct Fixture {
    log: Arc<Log>,
    gate: PermissionGate<RecordingKernel>,
}

fn own_pid() -> i32 {
    i32::try_from(std::process::id()).expect("pid fits pid_t")
}

/// A gate for a sandbox that is this test's cgroup, with ignore marks enabled
/// for the scratch directory's device.
fn gate(
    scratch: &Scratch,
    allow: Vec<FilesystemRule>,
    socket_path: PathBuf,
    flush: Flush,
) -> Fixture {
    let log = Arc::new(Log::default());
    let host_proc = HostProc::open().expect("open /proc");
    let sandbox_cgroup = CgroupPath::read(&host_proc, own_pid()).expect("own cgroup");
    let policy = FilesystemReplica::new(
        Some(FilesystemSnapshot {
            filesystem: FilesystemSection {
                allow,
                deny: Vec::new(),
            },
            denied_inodes: HashSet::new(),
        }),
        SystemTime::now(),
        None,
    );
    let scratch_device = fs::metadata(&scratch.dir)
        .expect("stat scratch directory")
        .dev();
    let gate = PermissionGate::new(GateSetup {
        kernel: RecordingKernel {
            log: Arc::clone(&log),
            flush,
        },
        self_pid: own_pid(),
        sandbox_cgroup,
        host_proc,
        ctx: RequestContext::default(),
        socket_path,
        policy,
        ignore_marks: Some(IgnoreMarks::new(
            HashSet::from([scratch_device]),
            Box::new(RecordingStop {
                log: Arc::clone(&log),
            }),
        )),
    });

    Fixture { log, gate }
}

/// Run `body` with the id of a thread that is not the process's main thread,
/// which stands for the sandboxed opener fanotify reports.
fn as_sandboxed_opener(body: impl FnOnce(i32) + Send) {
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let task = fs::read_link("/proc/thread-self").expect("own task link");
            let tid = task
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.parse().ok())
                .expect("thread id");
            body(tid);
        });
    });
}

fn open_event(path: &Path, pid: i32) -> PermissionEvent {
    PermissionEvent {
        mask: FAN_OPEN_PERM,
        pid,
        event_fd: File::open(path).expect("open event file").into(),
    }
}

/// A policyd stand-in on a real unix socket. It answers every filesystem
/// check with `verdict` and every other request with an empty rule snapshot.
fn fake_policyd(scratch: &Scratch, verdict: Answer) -> PathBuf {
    let socket = scratch.dir.join("policy.sock");
    let listener = UnixListener::bind(&socket).expect("bind policy socket");

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve(stream, verdict));
        }
    });

    socket
}

fn serve(stream: UnixStream, verdict: Answer) {
    let mut writer = stream.try_clone().expect("clone stream");

    for request in BufReader::new(stream).lines() {
        let Ok(request) = request else {
            return;
        };
        let request: RpcRequest = serde_json::from_str(&request).expect("policyd request");
        let reply = match request {
            RpcRequest::CheckFilesystem { path, access, .. } => {
                let source = VerdictSource::policy();
                RpcReply::FilesystemCheck(match verdict {
                    Answer::Allow => FilesystemCheckReply::allowed(source, path, access),
                    Answer::Deny => FilesystemCheckReply::denied(source, path, access),
                })
            }
            _ => RpcReply::FilesystemSnapshot {
                filesystem: FilesystemSection::default(),
                denied_inodes: HashSet::new(),
            },
        };
        if writer
            .write_all(RpcMessage::Reply(reply).to_string().as_bytes())
            .is_err()
        {
            return;
        }
    }
}

/// A regular file whose path is longer than `PATH_MAX`, which procfs cannot
/// report.
fn file_beyond_path_max(scratch: &Scratch) -> OwnedFd {
    let component = "d".repeat(200);
    let mut dir = OwnedFd::from(File::open(&scratch.dir).expect("open scratch directory"));

    for _ in 0..24 {
        mkdirat(&dir, component.as_str(), Mode::S_IRWXU).expect("create nested directory");
        dir = openat(
            &dir,
            component.as_str(),
            OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("open nested directory");
    }

    openat(
        &dir,
        "data",
        OFlag::O_CREAT | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::S_IRUSR,
    )
    .expect("create deep file")
}

#[test]
fn open_by_the_monitor_itself_is_allowed_without_asking_policyd() {
    let scratch = Scratch::new("self");
    let file = scratch.file("data");
    let fixture = gate(&scratch, Vec::new(), scratch.absent_socket(), Flush::Works);

    fixture
        .gate
        .worker()
        .expect("worker")
        .decide(open_event(&file, own_pid()));

    assert_eq!(fixture.log.effects(), [ALLOWED]);
    let counts = fixture.gate.counts();
    assert_eq!(counts.local_answers, 1);
    assert_eq!(counts.policyd_calls, 0);
}

#[test]
fn open_with_an_unresolvable_path_is_denied_locally() {
    let scratch = Scratch::new("deep");
    let event_fd = file_beyond_path_max(&scratch);
    assert!(
        fs::read_link(format!("/proc/self/fd/{}", event_fd.as_raw_fd())).is_err(),
        "the fixture path must be unresolvable"
    );
    let fixture = gate(
        &scratch,
        vec![scratch.read_write_rule()],
        fake_policyd(&scratch, Answer::Allow),
        Flush::Works,
    );

    as_sandboxed_opener(|tid| {
        fixture
            .gate
            .worker()
            .expect("worker")
            .decide(PermissionEvent {
                mask: FAN_OPEN_PERM,
                pid: tid,
                event_fd,
            });
    });

    assert_eq!(fixture.log.effects(), [DENIED]);
    let counts = fixture.gate.counts();
    assert_eq!(counts.local_answers, 1);
    assert_eq!(counts.policyd_calls, 0);
}

#[test]
fn statically_allowed_open_is_answered_before_its_ignore_mark() {
    let scratch = Scratch::new("static");
    let file = scratch.file("data");
    let fixture = gate(
        &scratch,
        vec![scratch.read_write_rule()],
        scratch.absent_socket(),
        Flush::Works,
    );

    as_sandboxed_opener(|tid| {
        fixture
            .gate
            .worker()
            .expect("worker")
            .decide(open_event(&file, tid));
    });

    assert_eq!(fixture.log.effects(), [ALLOWED, MARKED_FOR_OPEN]);
    let counts = fixture.gate.counts();
    assert_eq!(counts.policyd_calls, 0);
    assert_eq!(counts.marks_added, 1);
}

#[test]
fn hard_linked_file_goes_to_policyd_despite_a_static_allow() {
    let scratch = Scratch::new("link");
    let file = scratch.file("data");
    fs::hard_link(&file, scratch.dir.join("alias")).expect("hard link");
    let fixture = gate(
        &scratch,
        vec![scratch.read_write_rule()],
        fake_policyd(&scratch, Answer::Deny),
        Flush::Works,
    );

    as_sandboxed_opener(|tid| {
        fixture
            .gate
            .worker()
            .expect("worker")
            .decide(open_event(&file, tid));
    });

    assert_eq!(fixture.log.effects(), [DENIED]);
    assert_eq!(fixture.gate.counts().policyd_calls, 1);
}

#[test]
fn unreachable_policyd_denies_the_open() {
    let scratch = Scratch::new("unreachable");
    let file = scratch.file("data");
    let fixture = gate(&scratch, Vec::new(), scratch.absent_socket(), Flush::Works);

    as_sandboxed_opener(|tid| {
        fixture
            .gate
            .worker()
            .expect("worker")
            .decide(open_event(&file, tid));
    });

    assert_eq!(fixture.log.effects(), [DENIED]);
    assert_eq!(fixture.gate.counts().policyd_calls, 1);
}

/// The kernel effects of one open that only policyd can decide.
fn effects_of_policyd_verdict(name: &str, verdict: Answer) -> Vec<Effect> {
    let scratch = Scratch::new(name);
    let file = scratch.file("data");
    let fixture = gate(
        &scratch,
        Vec::new(),
        fake_policyd(&scratch, verdict),
        Flush::Works,
    );

    as_sandboxed_opener(|tid| {
        fixture
            .gate
            .worker()
            .expect("worker")
            .decide(open_event(&file, tid));
    });

    fixture.log.effects()
}

#[test]
fn policyd_allow_reply_allows_the_open_without_a_mark() {
    assert_eq!(effects_of_policyd_verdict("allow", Answer::Allow), [
        ALLOWED
    ]);
}

#[test]
fn policyd_deny_reply_denies_the_open() {
    assert_eq!(effects_of_policyd_verdict("deny", Answer::Deny), [DENIED]);
}

#[test]
fn ignore_mark_cap_stops_further_marks_but_not_answers() {
    let scratch = Scratch::new("cap");
    let fixture = gate(
        &scratch,
        vec![scratch.read_write_rule()],
        scratch.absent_socket(),
        Flush::Works,
    );

    as_sandboxed_opener(|tid| {
        let mut worker = fixture.gate.worker().expect("worker");
        let mut path = scratch.file("0");

        // Marks are tracked by path, so one inode under a new name counts as
        // a new mark.
        for name in 1..=IGNORE_MARK_CAP {
            worker.decide(open_event(&path, tid));
            let renamed = scratch.dir.join(name.to_string());
            fs::rename(&path, &renamed).expect("rename fixture file");
            path = renamed;
        }
        worker.decide(open_event(&path, tid));
    });

    let effects = fixture.log.effects();
    let marks = effects
        .iter()
        .filter(|effect| matches!(effect, Effect::Marked { .. }))
        .count();
    assert_eq!(marks, IGNORE_MARK_CAP);
    assert_eq!(effects.len(), 2 * IGNORE_MARK_CAP + 1);
    assert_eq!(effects.last(), Some(&ALLOWED));
}

#[test]
fn failed_flush_stops_the_sandbox() {
    let scratch = Scratch::new("flush");
    let file = scratch.file("data");
    let fixture = gate(
        &scratch,
        vec![scratch.read_write_rule()],
        scratch.absent_socket(),
        Flush::Fails,
    );

    as_sandboxed_opener(|tid| {
        fixture
            .gate
            .worker()
            .expect("worker")
            .decide(open_event(&file, tid));
    });
    drop(fixture.gate.revoke_grants());

    assert_eq!(fixture.log.effects(), [
        ALLOWED,
        MARKED_FOR_OPEN,
        Effect::Flushed,
        Effect::SandboxStopped,
    ]);
    assert_eq!(fixture.gate.counts().marks_flushed, 0);
}

#[test]
fn policy_change_flushes_marks_before_the_new_rules_answer() {
    let scratch = Scratch::new("follow");
    let file = scratch.file("data");
    let fixture = gate(
        &scratch,
        vec![scratch.read_write_rule()],
        fake_policyd(&scratch, Answer::Deny),
        Flush::Works,
    );

    as_sandboxed_opener(|tid| {
        let mut worker = fixture.gate.worker().expect("worker");
        worker.decide(open_event(&file, tid));

        let refetches = AtomicUsize::new(0);
        fixture
            .gate
            .follow_policy(|| refetches.fetch_add(1, Ordering::Relaxed) >= 1)
            .expect("snapshot source");

        worker.decide(open_event(&file, tid));
    });

    assert_eq!(fixture.log.effects(), [
        ALLOWED,
        MARKED_FOR_OPEN,
        Effect::Flushed,
        DENIED,
    ]);
    assert_eq!(fixture.gate.counts().marks_flushed, 1);
}

//! Per-session filesystem export for the syscall broker.
//!
//! The broker runs as the sandbox user and cannot ask policyd for the merged
//! policy, so policyd keeps one root-owned file per exported session in the
//! directory it shares with sandboxes, holding the filesystem rules merged
//! for that session's user, project and package. A session is exported only
//! once policyd has started its filesystem monitor: without one nothing
//! checks reads, and the agent could read the merged rules, which are secret
//! from it. The file is rewritten only when its bytes change and removed with
//! the session. The merged policy denies the whole export directory, and
//! [`PolicyStore::session_export_verdict`] lets only the session's own broker
//! read its own file.

use std::{
    collections::HashSet,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use agent_sandbox_core::{
    FileAccess, ProcessIds, REFRESH_INTERVAL, ResolvedRequestContext, SandboxPaths, Verdict,
    VerdictSource, is_descendant_of, session_export_path, session_export_root,
};

use super::{PolicyStore, context::read_proc_ppid, types::ExportReader};

const DIRECTORY_MODE: u32 = 0o755;
const FILE_MODE: u32 = 0o644;

/// Reap ended sandboxes and rewrite every monitored session's export each
/// [`REFRESH_INTERVAL`], so edits to policy files reach the broker without a
/// policyd request.
pub async fn run_session_export_ticker(store: Arc<PolicyStore>) {
    let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        store.reap_ended_sessions().await;
        PolicyStore::blocking(|| store.export_session_filesystems());
    }
}

impl PolicyStore {
    fn shared_dir(&self) -> Option<&Path> {
        self.args.sandbox_socket.parent()
    }

    /// Directory holding every session's export, or `None` when the sandbox
    /// socket has no directory to share it from.
    pub(crate) fn session_export_dir(&self) -> Option<PathBuf> {
        self.shared_dir().map(session_export_root)
    }

    /// Bring every monitored session's export up to date and remove the
    /// exports of sessions that are gone or have no monitor.
    pub(crate) fn export_session_filesystems(&self) {
        let Some(root) = self.session_export_dir() else {
            return;
        };

        let live: HashSet<String> = self
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(_, registration)| registration.export_reader.is_some())
            .map(|(id, _)| id.clone())
            .collect();

        for session_id in &live {
            self.export_session_filesystem(session_id);
        }

        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };

        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && !live.contains(name)
            {
                self.remove_session_filesystem_export(name);
            }
        }
    }

    /// Write `session_id`'s export when its merged rules changed. Failures
    /// are logged: the broker then keeps answering from its previous copy
    /// until the next tick or, once the file is gone, asks policyd. A session
    /// without a filesystem monitor is not written.
    pub(crate) fn export_session_filesystem(&self, session_id: &str) {
        let Some(path) = self
            .shared_dir()
            .and_then(|dir| session_export_path(dir, session_id))
        else {
            return;
        };
        let Some(ctx) = self.exported_session_context(session_id) else {
            return;
        };

        let result = serde_json::to_vec_pretty(&self.merged_for(&ctx).filesystem)
            .map_err(std::io::Error::other)
            .and_then(|bytes| write_if_changed(&path, &bytes));

        if let Err(error) = result {
            tracing::warn!(session_id, %error, "cannot write session filesystem export");
        }
    }

    /// Remove `session_id`'s export. Call when its registration goes away.
    pub(crate) fn remove_session_filesystem_export(&self, session_id: &str) {
        let Some(dir) = self
            .shared_dir()
            .and_then(|dir| session_export_path(dir, session_id))
            .and_then(|path| path.parent().map(Path::to_path_buf))
        else {
            return;
        };

        if let Err(error) = std::fs::remove_dir_all(&dir)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(session_id, %error, "cannot remove session filesystem export");
        }
    }

    /// Record the reader of `session_id`'s export after its filesystem
    /// monitor started, and export its rules without waiting for a tick.
    ///
    /// `peer_pid` is the process that armed the monitor. Its parent is the
    /// syscall broker when that gate is on and bwrap otherwise, either way a
    /// process the agent cannot replace. The parent is recorded only when it
    /// descends from the session's registered launcher.
    pub(crate) fn record_export_reader(&self, session_id: &str, peer_pid: u32) {
        let launcher_pid = self
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(session_id)
            .map(|registration| registration.launcher_pid);
        let reader = read_proc_ppid(peer_pid)
            .filter(|parent| launcher_pid.is_some_and(|pid| is_descendant_of(pid, *parent)))
            .and_then(ExportReader::of);

        if reader.is_none() {
            tracing::warn!(
                session_id,
                peer_pid,
                "filesystem monitor armed by a process outside the launcher; export disabled"
            );
            return;
        }

        self.set_export_reader(session_id, reader);
    }

    /// Set the export reader of `session_id` and write its export when there
    /// is one.
    pub(super) fn set_export_reader(&self, session_id: &str, reader: Option<ExportReader>) {
        self.update_registry(|sessions| {
            if let Some(registration) = sessions.get_mut(session_id) {
                registration.export_reader = reader;
            }
        });
        Self::blocking(|| self.export_session_filesystem(session_id));
    }

    /// The request context the session's own sandbox requests resolve to,
    /// or `None` when the session is unknown or has no export reader.
    fn exported_session_context(&self, session_id: &str) -> Option<ResolvedRequestContext> {
        let registration = self
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(session_id)
            .filter(|registration| registration.export_reader.is_some())
            .cloned()?;
        let project_root =
            Some(registration.project_root).filter(|root| !root.as_os_str().is_empty());

        Some(self.resolve_trusted_context(&ResolvedRequestContext::new(
            SandboxPaths::from_wire(None, None, project_root),
            ProcessIds::from_options(None, Some(registration.owner_uid)),
            Some(session_id.to_owned()),
        )))
    }

    /// The verdict for a path inside the export directory, or `None` for any
    /// other path.
    ///
    /// Only a read of the requesting session's own file is allowed, and only
    /// by the process recorded as the session's export reader. The opener's
    /// pid may be a thread id, so it is matched by thread group. The reader
    /// is the parent of the monitor's armer, which the agent cannot replace.
    pub(super) fn session_export_verdict(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        path.strip_prefix(self.session_export_dir()?).ok()?;

        let own_file = ctx
            .sandbox_session_id
            .as_deref()
            .zip(self.shared_dir())
            .and_then(|(id, dir)| session_export_path(dir, id));
        let readable = access == FileAccess::Read
            && own_file.as_deref() == Some(path)
            && self.is_export_reader(ctx);

        Some(if readable {
            Verdict::allowed(VerdictSource::Infrastructure)
        } else {
            Verdict::denied(VerdictSource::policy())
        })
    }

    fn is_export_reader(&self, ctx: &ResolvedRequestContext) -> bool {
        let (Some(id), Some(pid)) = (ctx.sandbox_session_id.as_deref(), ctx.ids.pid()) else {
            return false;
        };
        let reader = self
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .and_then(|registration| registration.export_reader);

        reader.is_some_and(|reader| reader.is_thread_of_reader(pid))
    }
}

/// Atomically replace `path` with `bytes` unless it already holds them.
fn write_if_changed(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if std::fs::read(path).is_ok_and(|current| current == bytes) {
        return Ok(());
    }

    let Some(dir) = path.parent() else {
        return Err(std::io::Error::other("export path has no directory"));
    };
    create_shared_dir(dir)?;

    let staged = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(&staged)?;
    file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(staged, path)
}

/// Create `dir` and its missing parents readable by every user, whatever the
/// daemon's umask.
fn create_shared_dir(dir: &Path) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut current = Some(dir);
    while let Some(candidate) = current.filter(|candidate| !candidate.exists()) {
        missing.push(candidate);
        current = candidate.parent();
    }

    for candidate in missing.into_iter().rev() {
        std::fs::DirBuilder::new()
            .mode(DIRECTORY_MODE)
            .create(candidate)?;
        std::fs::set_permissions(candidate, std::fs::Permissions::from_mode(DIRECTORY_MODE))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        process::Command,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU32, Ordering},
        },
        time::Duration,
    };

    use agent_sandbox_core::{
        FileAccess, FilesystemRule, FilesystemSection, Policy, ProcessIds, ResolvedRequestContext,
        SandboxPaths, Verdict, VerdictSource,
    };

    use crate::store::{
        PolicyStore,
        context::read_proc_ppid,
        test_args,
        types::{ExportReader, SandboxSessionRegistration},
    };

    struct Fixture {
        dir: tempfile::TempDir,
        store: PolicyStore,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let monitor = dir.path().join("fsmon");
            std::fs::write(&monitor, "#!/bin/sh\necho ready\n").expect("write monitor stand-in");
            std::fs::set_permissions(&monitor, std::fs::Permissions::from_mode(0o755))
                .expect("make monitor stand-in executable");

            let mut args = test_args(
                dir.path().join("host.sock"),
                dir.path().join("shared/sandbox.sock"),
                dir.path().join("declarative.json"),
                dir.path().join("export.json"),
                Duration::from_secs(30),
                true,
            );
            args.fs_monitor_cmd = Some(monitor);

            Self {
                dir,
                store: PolicyStore::new(args),
            }
        }

        fn declare(&self, allow: &[&str], deny: &[&str]) {
            let rule = |path: &&str| FilesystemRule::new(path, FileAccess::All, "test");
            let policy = Policy {
                filesystem: FilesystemSection {
                    allow: allow.iter().map(rule).collect(),
                    deny: deny.iter().map(rule).collect(),
                },
                ..Policy::default()
            };
            std::fs::write(
                self.dir.path().join("declarative.json"),
                serde_json::to_vec(&policy).expect("serialize policy"),
            )
            .expect("write declarative policy");
        }

        fn register(&self, id: &str, launcher_pid: u32, root_pid: u32) {
            self.store
                .sandbox_sessions
                .write()
                .expect("sessions")
                .insert(id.to_owned(), SandboxSessionRegistration {
                    root_pid,
                    owner_uid: nix::unistd::Uid::current().as_raw(),
                    project_root: PathBuf::new(),
                    package: None,
                    launcher_pid,
                    launcher_start_ticks: 1,
                    cgroup: None,
                    export_reader: ExportReader::of(std::process::id()),
                });
        }

        fn reader(&self, id: &str) -> Option<ExportReader> {
            self.store
                .sandbox_sessions
                .read()
                .expect("sessions")
                .get(id)
                .and_then(|registration| registration.export_reader)
        }

        fn export_dir(&self) -> PathBuf {
            self.dir.path().join("shared/sessions")
        }

        fn export_file(&self, id: &str) -> PathBuf {
            self.export_dir().join(id).join("filesystem.json")
        }

        async fn verdict(
            &self,
            path: &Path,
            session: &str,
            pid: u32,
            access: FileAccess,
        ) -> Option<Verdict> {
            self.store
                .filesystem_allow_source(path, access, &context(Some(session), pid))
                .await
        }

        fn exported(&self, id: &str) -> FilesystemSection {
            serde_json::from_slice(&std::fs::read(self.export_file(id)).expect("read export"))
                .expect("parse export")
        }
    }

    fn context(session: Option<&str>, pid: u32) -> ResolvedRequestContext {
        ResolvedRequestContext::new(
            SandboxPaths::default(),
            ProcessIds::from_options(Some(pid), None),
            session.map(str::to_owned),
        )
    }

    fn allows(section: &FilesystemSection, path: &str) -> bool {
        section
            .allow
            .iter()
            .any(|rule| rule.path == Path::new(path))
    }

    fn denies(section: &FilesystemSection, path: &str) -> bool {
        section.deny.iter().any(|rule| rule.path == Path::new(path))
    }

    #[test]
    fn export_follows_policy_layers_and_session_lifetime() {
        let fixture = Fixture::new();
        fixture.declare(&["/srv/project"], &[]);
        fixture.register("sess-1", std::process::id(), 0);

        fixture.store.export_session_filesystems();
        let first = fixture.exported("sess-1");
        assert!(allows(&first, "/srv/project"));
        assert!(!denies(&first, "/srv/project/secret"));
        let file = std::fs::metadata(fixture.export_file("sess-1")).expect("export metadata");
        assert_eq!(file.permissions().mode() & 0o777, 0o644);
        let dir = std::fs::metadata(fixture.export_dir()).expect("directory metadata");
        assert_eq!(dir.permissions().mode() & 0o777, 0o755);

        fixture.store.export_session_filesystems();
        let unchanged = std::fs::metadata(fixture.export_file("sess-1")).expect("metadata");
        assert_eq!(
            unchanged.ino(),
            file.ino(),
            "unchanged bytes are not rewritten"
        );

        fixture.declare(&["/srv/project"], &["/srv/project/secret"]);
        fixture.store.export_session_filesystems();
        let rewritten = fixture.exported("sess-1");
        assert!(denies(&rewritten, "/srv/project/secret"));
        let after = std::fs::metadata(fixture.export_file("sess-1")).expect("metadata");
        assert_ne!(after.ino(), file.ino());

        std::fs::create_dir_all(fixture.export_dir().join("stale")).expect("stale export");
        fixture.store.export_session_filesystems();
        assert!(!fixture.export_dir().join("stale").exists());

        fixture.store.remove_session_filesystem_export("sess-1");
        assert!(!fixture.export_dir().join("sess-1").exists());
    }

    #[test]
    fn registering_a_session_exports_without_waiting_for_a_tick() {
        let fixture = Fixture::new();
        fixture.declare(&["/srv/project"], &[]);
        fixture.register("sess-1", std::process::id(), 0);

        fixture.store.export_session_filesystem("sess-1");

        assert!(allows(&fixture.exported("sess-1"), "/srv/project"));
    }

    #[tokio::test]
    async fn session_is_exported_only_once_its_filesystem_monitor_runs() {
        let fixture = Fixture::new();
        fixture.declare(&["/srv/project"], &[]);
        let peer = std::process::id();
        let parent = read_proc_ppid(peer).expect("parent of the test process");
        let launcher = read_proc_ppid(parent).expect("grandparent of the test process");

        fixture.register("sess-1", launcher, 0);
        fixture.store.set_export_reader("sess-1", None);

        fixture.store.export_session_filesystem("sess-1");
        fixture.store.export_session_filesystems();
        assert!(
            !fixture.export_file("sess-1").exists(),
            "a session without a monitor is not exported"
        );

        let reply = fixture
            .store
            .start_filesystem_monitor(peer, context(Some("sess-1"), peer), Vec::new())
            .await;

        assert!(reply.active, "monitor did not start: {reply:?}");
        assert_eq!(fixture.reader("sess-1"), ExportReader::of(parent));
        assert!(allows(&fixture.exported("sess-1"), "/srv/project"));

        fixture.store.set_export_reader("sess-1", None);
        fixture.store.export_session_filesystems();
        assert!(
            !fixture.export_dir().join("sess-1").exists(),
            "a session that loses its reader is no longer exported"
        );
    }

    #[tokio::test]
    async fn monitor_armed_outside_the_launcher_records_no_reader() {
        let fixture = Fixture::new();
        fixture.declare(&["/srv/project"], &[]);
        let peer = std::process::id();
        let mut stranger = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn stand-in launcher");

        fixture.register("sess-1", stranger.id(), 0);
        fixture.store.set_export_reader("sess-1", None);

        let reply = fixture
            .store
            .start_filesystem_monitor(peer, context(Some("sess-1"), peer), Vec::new())
            .await;

        stranger.kill().expect("kill stand-in launcher");
        stranger.wait().expect("reap stand-in launcher");

        assert!(reply.active, "monitor did not start: {reply:?}");
        assert_eq!(fixture.reader("sess-1"), None);
        assert!(!fixture.export_file("sess-1").exists());
    }

    #[tokio::test]
    async fn merged_policy_denies_the_export_directory_to_the_agent() {
        let fixture = Fixture::new();
        fixture.declare(&["/run"], &[]);
        fixture.register("sess-1", std::process::id(), 0);
        fixture.store.export_session_filesystems();
        let file = fixture.export_file("sess-1");
        // The test process is the recorded reader, so the agent is another one.
        let agent = read_proc_ppid(std::process::id()).expect("parent of the test process");
        let session_ctx = context(Some("sess-1"), agent);

        let merged = fixture.store.merged_for(&session_ctx).filesystem;
        assert!(
            merged
                .deny
                .iter()
                .any(|rule| rule.matches(&file, FileAccess::Read, None)),
            "export directory is a deny rule even when an allow covers it"
        );

        let denied = Some(Verdict::denied(VerdictSource::policy()));
        for ctx in [&session_ctx, &context(None, agent)] {
            for access in [FileAccess::Read, FileAccess::Write, FileAccess::Execute] {
                assert_eq!(
                    fixture
                        .store
                        .filesystem_allow_source(&file, access, ctx)
                        .await,
                    denied,
                    "{access:?} by a process that is not the session's broker"
                );
            }
        }
        assert_eq!(
            fixture
                .store
                .filesystem_allow_source(&fixture.export_dir(), FileAccess::Read, &session_ctx)
                .await,
            denied
        );
    }

    /// Runs a thread of the test process until dropped.
    struct SpawnedThread {
        tid: u32,
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl SpawnedThread {
        fn start() -> Self {
            let tid = Arc::new(AtomicU32::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let handle = std::thread::spawn({
                let tid = Arc::clone(&tid);
                let stop = Arc::clone(&stop);

                move || {
                    tid.store(
                        u32::try_from(nix::unistd::gettid().as_raw()).expect("valid thread id"),
                        Ordering::SeqCst,
                    );

                    while !stop.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            });

            while tid.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }

            Self {
                tid: tid.load(Ordering::SeqCst),
                stop,
                handle: Some(handle),
            }
        }
    }

    impl Drop for SpawnedThread {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);

            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    #[tokio::test]
    async fn only_the_export_reader_reads_its_own_export() {
        let fixture = Fixture::new();
        fixture.declare(&[], &[]);

        let reader = std::process::id();
        let launcher = read_proc_ppid(reader).expect("parent of the test process");

        // The test process is the recorded reader.
        fixture.register("sess-1", launcher, 0);
        fixture.register("sess-2", launcher, 0);
        fixture.store.export_session_filesystems();

        let own = fixture.export_file("sess-1");
        let allowed = Some(Verdict::allowed(VerdictSource::Infrastructure));
        let denied = Some(Verdict::denied(VerdictSource::policy()));
        let thread = SpawnedThread::start();

        assert_ne!(thread.tid, reader, "the opener is a thread id");
        assert_eq!(
            fixture
                .verdict(&own, "sess-1", thread.tid, FileAccess::Read)
                .await,
            allowed,
            "a thread of the reader process"
        );
        assert_eq!(
            fixture
                .verdict(&own, "sess-1", reader, FileAccess::Read)
                .await,
            allowed
        );
        assert_eq!(
            fixture
                .verdict(&own, "sess-1", reader, FileAccess::Write)
                .await,
            denied
        );
        assert_eq!(
            fixture
                .verdict(&own, "sess-2", reader, FileAccess::Read)
                .await,
            denied,
            "another session's file"
        );
        assert_eq!(
            fixture
                .verdict(&own, "sess-1", launcher, FileAccess::Read)
                .await,
            denied,
            "the reader's parent"
        );

        let mut child = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn child of the reader");

        assert_eq!(
            fixture
                .verdict(&own, "sess-1", child.id(), FileAccess::Read)
                .await,
            denied,
            "a child of the reader"
        );

        child.kill().expect("kill child");
        child.wait().expect("reap child");
    }

    #[tokio::test]
    async fn reader_with_other_start_ticks_is_denied() {
        let fixture = Fixture::new();
        fixture.declare(&[], &[]);

        let reader = std::process::id();
        let launcher = read_proc_ppid(reader).expect("parent of the test process");

        fixture.register("sess-1", launcher, 0);
        fixture.store.export_session_filesystems();

        let own = fixture.export_file("sess-1");
        let recorded = ExportReader::of(reader).expect("reader identity");

        fixture.store.set_export_reader(
            "sess-1",
            Some(ExportReader {
                start_ticks: recorded.start_ticks + 1,
                ..recorded
            }),
        );

        assert_eq!(
            fixture
                .verdict(&own, "sess-1", reader, FileAccess::Read)
                .await,
            Some(Verdict::denied(VerdictSource::policy()))
        );
    }
}

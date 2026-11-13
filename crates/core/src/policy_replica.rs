//! Local copies of policyd decisions that enforcement gates answer from.
//!
//! A gate may answer a request itself only while its copy agrees with
//! policyd. This module owns every such copy and the contract that keeps it
//! honest:
//!
//! - **Filesystem rules** ([`FilesystemReplica`]): the syscall broker and the
//!   fanotify monitor answer opens from the merged filesystem rules of their
//!   sandbox. Each reads them through a [`SnapshotSource`]: the monitor runs as
//!   root and asks policyd over RPC ([`PolicydRpc`]); the broker runs as the
//!   sandbox user and reads the per-session export policyd keeps current
//!   ([`SessionExport`]). A follower thread refetches every
//!   [`REFRESH_INTERVAL`] and swaps the copy in, so a deny added or an allow
//!   removed after a gate started reaches its local answers within a bounded
//!   number of intervals. A failed fetch replaces the copy with an empty one,
//!   which sends every request to policyd.
//! - **Destination verdicts** ([`replayable_destination_verdict`]): which of
//!   policyd's network answers the packet gate may publish into its kernel
//!   cache. The per-source rule sits next to [`VerdictSource`], so a new source
//!   cannot be added without deciding whether it replays.
//!
//! Readers pay one uncontended `RwLock` read per request and no syscall.
//! Replacement takes the write lock.

use std::{
    collections::HashSet,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{Duration, SystemTime},
};

use crate::{
    FilesystemSection, InodeIdentity, PersistentRpcClient, Policy, RequestContext, RpcReply,
    RpcRequest, StaticPolicyAllow, VerdictSource,
    policy::FilesystemCheck,
    verdict_map::{VERDICT_ALLOW, VERDICT_DENY},
};

/// Interval between fetches of the current filesystem rules.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Timeout for one snapshot request.
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(1);

/// Filesystems stamp ctime from a coarse clock that can trail the realtime
/// clock, so a link made just after a snapshot request may carry an earlier
/// ctime. Only inodes changed this long before the request are trusted.
const CTIME_CLOCK_SLACK: Duration = Duration::from_secs(1);

/// Directory, below the directory shared with sandboxes, that holds one
/// subdirectory of exports per sandbox session.
pub const SESSION_EXPORT_DIR: &str = "sessions";

/// File name of a session's filesystem export.
pub const SESSION_EXPORT_FILE: &str = "filesystem.json";

/// Directory of every session's export below the shared directory.
#[must_use]
pub fn session_export_root(shared_dir: &Path) -> PathBuf {
    shared_dir.join(SESSION_EXPORT_DIR)
}

/// Path of one session's filesystem export, or `None` when `session_id` is
/// not a plain file name that cannot leave the export directory.
#[must_use]
pub fn session_export_path(shared_dir: &Path, session_id: &str) -> Option<PathBuf> {
    let plain = !session_id.is_empty()
        && !session_id.starts_with('.')
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));

    plain.then(|| {
        session_export_root(shared_dir)
            .join(session_id)
            .join(SESSION_EXPORT_FILE)
    })
}

/// Decide whether a policyd network answer may be replayed from a cache.
///
/// Denials of any source replay: they fail fast and are healed by the
/// cache's generation bump when grants change. Allows replay only when
/// [`VerdictSource::replayable_allow`] holds and the destination is an IP
/// literal (`hostname == dst_ip`), so no DNS mapping can change under the
/// entry. An answer without a source is a local fail-closed deny, a
/// transient error rather than a decision, and never replays.
///
/// Returns the verdict byte to publish.
#[must_use]
pub fn replayable_destination_verdict(
    allowed: bool,
    source: Option<&VerdictSource>,
    hostname: &str,
    dst_ip: &str,
) -> Option<u8> {
    let source = source?;
    if !allowed {
        return Some(VERDICT_DENY);
    }

    (source.replayable_allow() && hostname == dst_ip).then_some(VERDICT_ALLOW)
}

/// Policy state a gate answers filesystem requests from without asking
/// policyd.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FilesystemSnapshot {
    /// Merged filesystem allow and deny rules.
    pub filesystem: FilesystemSection,
    /// Inodes whose hard links policyd must still check.
    pub denied_inodes: HashSet<InodeIdentity>,
}

/// Where a gate obtains its filesystem snapshot.
pub trait SnapshotSource {
    /// The current snapshot, or `None` when it cannot be obtained.
    fn fetch(&mut self) -> Option<FilesystemSnapshot>;
}

/// Snapshots requested from policyd over RPC. Needs a peer policyd lets
/// request them, which is root.
pub struct PolicydRpc {
    runtime: tokio::runtime::Runtime,
    client: PersistentRpcClient,
    ctx: RequestContext,
}

impl PolicydRpc {
    /// A source that requests snapshots for `ctx` through `client`.
    ///
    /// # Errors
    /// Returns the error from creating the source's async runtime.
    pub fn new(client: PersistentRpcClient, ctx: RequestContext) -> std::io::Result<Self> {
        Ok(Self {
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
            client,
            ctx,
        })
    }
}

impl SnapshotSource for PolicydRpc {
    fn fetch(&mut self) -> Option<FilesystemSnapshot> {
        let reply = self.runtime.block_on(self.client.request(
            RpcRequest::FilesystemSnapshot {
                ctx: self.ctx.clone(),
            },
            SNAPSHOT_TIMEOUT,
        ));

        match reply {
            Ok(RpcReply::FilesystemSnapshot {
                filesystem,
                denied_inodes,
            }) => Some(FilesystemSnapshot {
                filesystem,
                denied_inodes,
            }),

            Ok(_) => {
                self.client.invalidate();
                tracing::warn!("unexpected reply to filesystem snapshot; disabling local grants");

                None
            }

            Err(error) => {
                tracing::warn!(%error, "filesystem snapshot unavailable; disabling local grants");

                None
            }
        }
    }
}

/// Identity of one version of an export file. Policyd replaces the file by
/// rename, so a rewrite changes the inode even when size and mtime repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    modified_secs: i64,
    modified_nanos: i64,
    len: u64,
}

enum ExportCache {
    Empty,
    Cached(ParsedExport),
}

/// Snapshots read from the per-session export policyd maintains.
///
/// The file is parsed again only when its [`FileStamp`] changes. A missing,
/// unreadable or malformed file yields no snapshot.
pub struct SessionExport {
    path: PathBuf,
    parsed: ExportCache,
}

/// The last parsed export and the stamp of the file it came from.
struct ParsedExport {
    stamp: FileStamp,
    snapshot: FilesystemSnapshot,
}

impl SessionExport {
    /// A source reading the export at `path`.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self {
            path,
            parsed: ExportCache::Empty,
        }
    }
}

impl SnapshotSource for SessionExport {
    fn fetch(&mut self) -> Option<FilesystemSnapshot> {
        let outcome = std::fs::metadata(&self.path).and_then(|metadata| {
            let stamp = FileStamp {
                device: metadata.dev(),
                inode: metadata.ino(),
                modified_secs: metadata.mtime(),
                modified_nanos: metadata.mtime_nsec(),
                len: metadata.len(),
            };

            match &self.parsed {
                ExportCache::Cached(parsed) if parsed.stamp == stamp => Ok(parsed.snapshot.clone()),
                ExportCache::Empty | ExportCache::Cached(_) => {
                    let filesystem: FilesystemSection =
                        serde_json::from_slice(&std::fs::read(&self.path)?)
                            .map_err(std::io::Error::other)?;
                    let snapshot = FilesystemSnapshot {
                        filesystem,
                        denied_inodes: HashSet::new(),
                    };
                    self.parsed = ExportCache::Cached(ParsedExport {
                        stamp,
                        snapshot: snapshot.clone(),
                    });

                    Ok(snapshot)
                }
            }
        });

        match outcome {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                self.parsed = ExportCache::Empty;
                tracing::warn!(
                    path = %self.path.display(),
                    %error,
                    "session filesystem export unavailable; disabling local grants"
                );

                None
            }
        }
    }
}

/// Whether hard-linked regular files can be trusted locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkTrust {
    Untrusted,
    SettledBefore(i128),
}

/// One immutable generation of the local filesystem policy.
pub struct LocalFilesystem {
    snapshot: FilesystemSnapshot,
    allow: StaticPolicyAllow,
    link_trust: LinkTrust,
}

impl LocalFilesystem {
    /// Build from the snapshot requested at `requested`. Without a snapshot
    /// no local grant applies and every hard-linked file goes to policyd.
    fn build(
        snapshot: Option<FilesystemSnapshot>,
        requested: SystemTime,
        project_root: Option<PathBuf>,
    ) -> Self {
        let link_trust = if snapshot.is_some() {
            links_settled_before(requested)
        } else {
            LinkTrust::Untrusted
        };
        let snapshot = snapshot.unwrap_or_default();
        let allow = StaticPolicyAllow::from_policy(
            Policy {
                filesystem: snapshot.filesystem.clone(),
                ..Policy::default()
            },
            project_root,
        );

        Self {
            snapshot,
            allow,
            link_trust,
        }
    }

    /// The allow and deny rules of this generation.
    #[must_use]
    pub const fn allow(&self) -> &StaticPolicyAllow {
        &self.allow
    }

    /// Whether the rules allow every path/access pair. An empty rule set
    /// allows nothing, so every request goes to policyd.
    #[must_use]
    pub fn allows_all(&self, checks: &[FilesystemCheck]) -> bool {
        !self.allow.is_empty() && self.allow.allows_all(checks)
    }

    /// Whether a hard-linked regular file must be checked by policyd: it
    /// aliases a denied inode, or a link may postdate the denied inode set
    /// because `link` updates the inode's ctime.
    #[must_use]
    pub fn hard_link_needs_policyd(&self, inode: &InodeIdentity, changed_nanos: i128) -> bool {
        let postdates = match self.link_trust {
            LinkTrust::Untrusted => true,
            LinkTrust::SettledBefore(cutoff) => changed_nanos >= cutoff,
        };
        postdates || self.snapshot.denied_inodes.contains(inode)
    }
}

/// Realtime nanoseconds before which a changed inode is covered by a
/// snapshot requested at `requested`.
fn links_settled_before(requested: SystemTime) -> LinkTrust {
    requested
        .checked_sub(CTIME_CLOCK_SLACK)
        .and_then(|settled| settled.duration_since(SystemTime::UNIX_EPOCH).ok())
        .and_then(|settled| i128::try_from(settled.as_nanos()).ok())
        .map_or(LinkTrust::Untrusted, LinkTrust::SettledBefore)
}

/// The local copy of one sandbox's filesystem policy.
///
/// Readers take [`read`](Self::read) for each answer. Replacement takes the
/// write lock, so a caller that must act before the old generation stops
/// answering (revoking kernel grants derived from it) does so inside
/// [`replace`](Self::replace)'s `revoke` hook, with no reader running.
pub struct FilesystemReplica {
    project_root: Option<PathBuf>,
    local: RwLock<LocalFilesystem>,
}

impl FilesystemReplica {
    /// A replica holding the snapshot requested at `requested`, or no local
    /// grants for `None`.
    #[must_use]
    pub fn new(
        snapshot: Option<FilesystemSnapshot>,
        requested: SystemTime,
        project_root: Option<PathBuf>,
    ) -> Self {
        Self {
            local: RwLock::new(LocalFilesystem::build(
                snapshot,
                requested,
                project_root.clone(),
            )),
            project_root,
        }
    }

    /// Fetch the first generation, blocking the caller. An unavailable source
    /// yields a replica without local grants.
    #[must_use]
    pub fn fetch(source: &mut impl SnapshotSource, project_root: Option<PathBuf>) -> Self {
        let requested = SystemTime::now();

        Self::new(source.fetch(), requested, project_root)
    }

    /// The current generation.
    pub fn read(&self) -> RwLockReadGuard<'_, LocalFilesystem> {
        self.local
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the current generation allows every path/access pair.
    #[must_use]
    pub fn allows_all(&self, checks: &[FilesystemCheck]) -> bool {
        self.read().allows_all(checks)
    }

    /// Exclude every reader and replacement until the guard drops.
    pub fn lock_exclusive(&self) -> RwLockWriteGuard<'_, LocalFilesystem> {
        self.local
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Install the generation built from `snapshot`.
    ///
    /// The generation is rebuilt even when the rules are unchanged, because
    /// deny rule symlink aliases are resolved once per build. `revoke` runs
    /// only when the rules or denied inodes changed, under the write lock and
    /// before the old generation is replaced.
    pub fn replace(
        &self,
        snapshot: Option<FilesystemSnapshot>,
        requested: SystemTime,
        revoke: impl FnOnce(),
    ) {
        let next = LocalFilesystem::build(snapshot, requested, self.project_root.clone());
        let changed = self.read().snapshot != next.snapshot;
        let mut local = self.lock_exclusive();
        if changed {
            revoke();
        }
        *local = next;
    }

    /// Refetch from `source` every `interval` until `stop` returns true,
    /// blocking the caller. A failed fetch installs a generation without
    /// local grants.
    pub fn follow(
        &self,
        source: &mut impl SnapshotSource,
        interval: Duration,
        stop: impl Fn() -> bool,
        mut revoke: impl FnMut(),
    ) {
        while !stop() {
            std::thread::sleep(interval);
            let requested = SystemTime::now();
            self.replace(source.fetch(), requested, &mut revoke);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixListener,
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, Instant, SystemTime},
    };

    use super::{
        FilesystemReplica, FilesystemSnapshot, PolicydRpc, REFRESH_INTERVAL, SessionExport,
        replayable_destination_verdict, session_export_path,
    };
    use crate::{
        ApprovalScope, FileAccess, FilesystemRule, FilesystemSection, InodeIdentity,
        PathResolution, PersistentRpcClient, RequestContext, RpcMessage, RpcReply, VerdictSource,
        verdict_map::{VERDICT_ALLOW, VERDICT_DENY},
    };

    const FAST_REFRESH: Duration = Duration::from_millis(10);
    const BOUND: Duration = Duration::from_secs(5);

    /// A policyd stand-in on a real unix socket that answers every
    /// `FilesystemSnapshot` request with the rules it currently holds.
    struct FakePolicyd {
        socket: PathBuf,
        rules: Arc<Mutex<FilesystemSection>>,
        _dir: tempfile::TempDir,
    }

    impl FakePolicyd {
        fn start(initial: FilesystemSection) -> Self {
            let dir = tempfile::tempdir().expect("socket directory");
            let socket = dir.path().join("policy.sock");
            let listener = UnixListener::bind(&socket).expect("bind policy socket");
            let rules = Arc::new(Mutex::new(initial));
            let served = Arc::clone(&rules);

            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let served = Arc::clone(&served);
                    std::thread::spawn(move || serve(stream, &served));
                }
            });

            Self {
                socket,
                rules,
                _dir: dir,
            }
        }

        fn set(&self, rules: FilesystemSection) {
            *self.rules.lock().expect("rules") = rules;
        }

        fn source(&self) -> PolicydRpc {
            PolicydRpc::new(
                PersistentRpcClient::new(self.socket.clone()),
                RequestContext::default(),
            )
            .expect("runtime")
        }
    }

    fn serve(stream: std::os::unix::net::UnixStream, rules: &Mutex<FilesystemSection>) {
        let mut writer = stream.try_clone().expect("clone stream");
        for request in BufReader::new(stream).lines() {
            if request.is_err() {
                return;
            }
            let reply = RpcMessage::Reply(RpcReply::FilesystemSnapshot {
                filesystem: rules.lock().expect("rules").clone(),
                denied_inodes: Default::default(),
            });
            if writer.write_all(reply.to_string().as_bytes()).is_err() {
                return;
            }
        }
    }

    fn rules(allow: &[&str], deny: &[&str]) -> FilesystemSection {
        FilesystemSection {
            allow: allow
                .iter()
                .map(|path| FilesystemRule::new(path, FileAccess::All, "test"))
                .collect(),
            deny: deny
                .iter()
                .map(|path| FilesystemRule::new(path, FileAccess::All, "test"))
                .collect(),
        }
    }

    fn allows(replica: &FilesystemReplica, path: &str) -> bool {
        replica.read().allow().allows(
            Path::new(path),
            FileAccess::Read,
            PathResolution::Unresolved,
        )
    }

    fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + BOUND;
        while !condition() {
            assert!(Instant::now() < deadline, "{what} within {BOUND:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn deny_added_and_allow_removed_after_start_reach_local_answers() {
        let policyd = FakePolicyd::start(rules(&["/srv/project"], &[]));
        let replica = Arc::new(FilesystemReplica::fetch(&mut policyd.source(), None));
        assert!(allows(&replica, "/srv/project/secret"));
        assert!(allows(&replica, "/srv/project/file"));

        let stop = Arc::new(AtomicBool::new(false));
        let revocations = Arc::new(AtomicUsize::new(0));
        let follower = {
            let replica = Arc::clone(&replica);
            let stop = Arc::clone(&stop);
            let revocations = Arc::clone(&revocations);
            let mut source = policyd.source();
            std::thread::spawn(move || {
                replica.follow(
                    &mut source,
                    FAST_REFRESH,
                    || stop.load(Ordering::Relaxed),
                    || {
                        revocations.fetch_add(1, Ordering::Relaxed);
                    },
                );
            })
        };

        policyd.set(rules(&["/srv/project"], &["/srv/project/secret"]));
        wait_until("new deny honoured", || {
            !allows(&replica, "/srv/project/secret")
        });
        assert!(allows(&replica, "/srv/project/file"));

        policyd.set(rules(&[], &["/srv/project/secret"]));
        wait_until("removed allow honoured", || {
            !allows(&replica, "/srv/project/file")
        });

        stop.store(true, Ordering::Relaxed);
        follower.join().expect("follower thread");
        assert_eq!(
            revocations.load(Ordering::Relaxed),
            2,
            "revoke runs once per rule change, not once per refetch"
        );
    }

    #[test]
    fn unreachable_policyd_leaves_no_local_grants() {
        let dir = tempfile::tempdir().expect("socket directory");
        let mut source = PolicydRpc::new(
            PersistentRpcClient::new(dir.path().join("absent.sock")),
            RequestContext::default(),
        )
        .expect("runtime");
        let replica = FilesystemReplica::fetch(&mut source, None);

        assert!(replica.read().allow().is_empty());
        assert!(replica.read().hard_link_needs_policyd(
            &InodeIdentity {
                inode: 1,
                device: 1
            },
            0
        ));
    }

    #[test]
    fn follower_drops_grants_when_policyd_goes_away() {
        let policyd = FakePolicyd::start(rules(&["/srv/project"], &[]));
        let replica = FilesystemReplica::fetch(&mut policyd.source(), None);
        assert!(allows(&replica, "/srv/project/file"));

        std::fs::remove_file(&policyd.socket).expect("remove socket");
        let polls = AtomicUsize::new(0);
        replica.follow(
            &mut policyd.source(),
            FAST_REFRESH,
            || polls.fetch_add(1, Ordering::Relaxed) >= 1,
            || {},
        );

        assert!(!allows(&replica, "/srv/project/file"));
    }

    fn write_export(path: &Path, rules: &FilesystemSection) {
        let staged = path.with_extension("tmp");
        std::fs::write(&staged, serde_json::to_vec(rules).expect("serialize rules"))
            .expect("write export");
        std::fs::rename(staged, path).expect("replace export");
    }

    #[test]
    fn session_export_rewrite_is_honoured_by_the_follower() {
        let dir = tempfile::tempdir().expect("export directory");
        let export = dir.path().join("filesystem.json");
        write_export(&export, &rules(&["/srv/project"], &[]));
        let mut source = SessionExport::new(export.clone());
        let replica = Arc::new(FilesystemReplica::fetch(&mut source, None));
        assert!(allows(&replica, "/srv/project/secret"));

        let stop = Arc::new(AtomicBool::new(false));
        let follower = {
            let replica = Arc::clone(&replica);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                replica.follow(
                    &mut source,
                    FAST_REFRESH,
                    || stop.load(Ordering::Relaxed),
                    || {},
                );
            })
        };

        write_export(&export, &rules(&["/srv/project"], &["/srv/project/secret"]));
        wait_until("new deny honoured", || {
            !allows(&replica, "/srv/project/secret")
        });
        assert!(allows(&replica, "/srv/project/file"));

        std::fs::remove_file(&export).expect("remove export");
        wait_until("removed export drops grants", || {
            !allows(&replica, "/srv/project/file")
        });

        write_export(&export, &rules(&["/srv/project"], &[]));
        wait_until("restored export grants again", || {
            allows(&replica, "/srv/project/secret")
        });

        stop.store(true, Ordering::Relaxed);
        follower.join().expect("follower thread");
    }

    #[test]
    fn malformed_session_export_leaves_no_local_grants() {
        let dir = tempfile::tempdir().expect("export directory");
        let export = dir.path().join("filesystem.json");
        std::fs::write(&export, "{").expect("write export");

        let replica = FilesystemReplica::fetch(&mut SessionExport::new(export), None);

        assert!(replica.read().allow().is_empty());
    }

    #[test]
    fn session_export_path_rejects_ids_that_leave_the_directory() {
        let shared = Path::new("/run/agent-sandbox/shared");

        assert_eq!(
            session_export_path(shared, "7f3a-b2.c_d"),
            Some(PathBuf::from(
                "/run/agent-sandbox/shared/sessions/7f3a-b2.c_d/filesystem.json"
            ))
        );
        for id in ["", ".", "..", ".hidden", "a/b", "../x", "a\0b", "sp ace"] {
            assert_eq!(session_export_path(shared, id), None, "{id:?}");
        }
    }

    #[test]
    fn hard_links_need_policyd_when_denied_or_possibly_newer_than_the_snapshot() {
        let denied = InodeIdentity {
            inode: 7,
            device: 1,
        };
        let other = InodeIdentity {
            inode: 8,
            device: 1,
        };
        let requested = SystemTime::now();
        let replica = FilesystemReplica::new(
            Some(FilesystemSnapshot {
                denied_inodes: [denied].into(),
                ..FilesystemSnapshot::default()
            }),
            requested,
            None,
        );
        let nanos = |time: SystemTime| {
            i128::try_from(
                time.duration_since(SystemTime::UNIX_EPOCH)
                    .expect("after epoch")
                    .as_nanos(),
            )
            .expect("fits")
        };
        let needs_policyd = |inode: &InodeIdentity, ctime: i128| {
            replica.read().hard_link_needs_policyd(inode, ctime)
        };

        assert!(needs_policyd(&denied, 0));
        assert!(!needs_policyd(
            &other,
            nanos(requested - 2 * REFRESH_INTERVAL)
        ));
        assert!(
            needs_policyd(&other, nanos(requested - REFRESH_INTERVAL / 2)),
            "a ctime inside the clock slack may hide a newer link"
        );
        assert!(needs_policyd(&other, nanos(requested)));
    }

    #[test]
    fn destination_replay_table() {
        let scopes = [
            ApprovalScope::Once,
            ApprovalScope::Session,
            ApprovalScope::ProjectPackage,
            ApprovalScope::Project,
            ApprovalScope::GlobalPackage,
            ApprovalScope::Global,
        ];
        let static_layers = [
            VerdictSource::policy(),
            VerdictSource::policy_with_comment("rule"),
            VerdictSource::Static,
            VerdictSource::Infrastructure,
        ];
        let denials = static_layers.iter().cloned().chain([
            VerdictSource::User,
            VerdictSource::Blocked,
            VerdictSource::PortZero,
        ]);
        let ip = "192.0.2.7";

        for source in denials {
            for hostname in [ip, "example.test"] {
                assert_eq!(
                    replayable_destination_verdict(false, Some(&source), hostname, ip),
                    Some(VERDICT_DENY),
                    "denial from {source}"
                );
            }
        }

        for source in &static_layers {
            assert_eq!(
                replayable_destination_verdict(true, Some(source), ip, ip),
                Some(VERDICT_ALLOW),
                "IP-literal allow from {source}"
            );
            assert_eq!(
                replayable_destination_verdict(true, Some(source), "example.test", ip),
                None,
                "hostname allow from {source} can follow DNS"
            );
        }

        for scope in scopes {
            let source = VerdictSource::Scope(scope);
            for hostname in [ip, "example.test"] {
                assert_eq!(
                    replayable_destination_verdict(true, Some(&source), hostname, ip),
                    None,
                    "{source} approvals are not replayed"
                );
            }
        }

        for allowed in [true, false] {
            assert_eq!(replayable_destination_verdict(allowed, None, ip, ip), None);
        }
    }
}

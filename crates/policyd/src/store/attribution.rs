//! Policy store: project attribution.
//!
//! Decides which registered sandbox instance, and therefore which package, a
//! request belongs to. [`attribute_trusted`] serves policyd-side callers that
//! may name the session themselves; [`attribute_peer`] serves a sandbox peer
//! whose wire claims are not believed. Both are pure over [`ProcFacts`] and the
//! registrations; [`HostProcfs`] is the adapter that reads `/proc` and caches
//! what it read for the length of one resolution.

use std::{cell::RefCell, collections::HashMap, path::PathBuf};

use agent_sandbox_core::{
    ProcContext, is_path_descendant, peer_context, sandbox_session_id_from_pid,
};

use super::{
    context::read_proc_ppid,
    lifecycle::process_cgroup,
    types::{PolicyStore, SandboxSessionRegistration, TrustedPeer},
};

/// Registered sandbox instances by session id.
pub(super) type Registrations = HashMap<String, SandboxSessionRegistration>;

/// Longest parent chain walked when deciding ancestry.
const MAX_ANCESTRY_DEPTH: usize = 256;

/// Process facts attribution depends on. Every read is on behalf of one
/// resolution.
pub(super) trait ProcFacts {
    /// `AGENT_SANDBOX_SESSION_ID` from the process environment.
    fn session_id(&self, pid: u32) -> Option<String>;

    /// Whether `pid` is `ancestor` or one of its descendants in the host pid
    /// namespace.
    fn is_descendant_of(&self, ancestor: u32, pid: u32) -> bool;

    /// The cgroup directory `pid` belongs to.
    fn cgroup(&self, pid: u32) -> Option<PathBuf>;

    /// Launcher-claimed cwd and project root of `pid`, with the cwd falling
    /// back to `/proc/<pid>/cwd`.
    fn paths(&self, pid: u32, uid: Option<u32>) -> ProcContext;
}

/// Authoritative attribution evidence that tied a request to a registered
/// sandbox instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Evidence {
    /// A policyd-side caller named the session; the registration is trusted.
    TrustedCaller,

    /// The process descends from the registered session anchor (root, else
    /// launcher).
    Ancestry,

    /// The process left the anchor's tree but shares the agent scope of
    /// exactly one session.
    AgentScope,

    /// The authenticated peer owns the registration and is the session root
    /// or one of its descendants.
    SessionTree,

    /// The authenticated peer is the syscall broker, an ancestor of the
    /// session root inside the launcher's tree.
    BrokerAncestor,
}

/// Outcome of attributing one request.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Attribution {
    /// Session id the request carries or was adopted into. Not authoritative
    /// unless [`Self::evidence`] is set.
    pub session_id: Option<String>,

    /// Package of the registration, set only together with `evidence`.
    pub package: Option<String>,

    /// What established the attribution; `None` for an unregistered or
    /// unverified session id.
    pub evidence: Option<Evidence>,
}

/// Verified sandbox peer paths, constrained to the registered project root.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PeerPaths {
    pub cwd: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
}

/// A sandbox peer's request, before its wire claims are believed.
pub(super) struct PeerRequest<'a> {
    /// Session id the wire context claims.
    pub wire_session_id: Option<&'a str>,

    /// Tracee pid the wire context claims.
    pub wire_pid: Option<u32>,

    /// Authenticated peer; its uid is never root.
    pub peer: TrustedPeer,
}

/// Outcome of attributing a sandbox peer.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PeerAttribution {
    /// Pid the request is verified to come from: the wire tracee when it is
    /// the peer or one of its descendants, else the peer itself.
    pub verified_pid: Option<u32>,

    /// Session id and package; see [`Attribution`].
    pub attribution: Attribution,

    /// Paths read from the verified process, empty unless it stands inside
    /// the sandbox (or its session is unregistered).
    pub paths: PeerPaths,
}

/// Attribute a request from a policyd-side or root caller. `claim` is the
/// wire session id, else the process environment names one, else the process
/// is adopted by ancestry or agent scope. The package comes from the
/// registration by session id alone: there is no peer uid to check.
pub(super) fn attribute_trusted(
    procs: &impl ProcFacts,
    sessions: &Registrations,
    claim: Option<String>,
    pid: Option<u32>,
    uid: Option<u32>,
) -> Attribution {
    let mut session_id = claim;
    let mut adopted = None;

    if session_id.is_none()
        && let Some(pid) = pid
    {
        session_id = procs.session_id(pid);
    }

    // Sandbox children that run with a filtered environment drop
    // AGENT_SANDBOX_SESSION_ID and are attributed by process ancestry
    // against the registered session launcher/root instead.
    if session_id.is_none()
        && let Some(pid) = pid
        && let Some(found) = adopt_by_process(procs, sessions, pid, uid)
    {
        session_id = Some(found.id);
        adopted = Some(found.evidence);
    }

    let registration = session_id.as_ref().and_then(|id| sessions.get(id));

    Attribution {
        package: registration.and_then(|reg| reg.package.clone()),
        evidence: adopted.or_else(|| registration.map(|_| Evidence::TrustedCaller)),
        session_id,
    }
}

/// Attribute a sandbox peer. The wire session id is attacker-controlled, so
/// the package is adopted only when the peer owns the registration and the
/// verified pid stands inside the session; peer paths need only the latter.
pub(super) fn attribute_peer(
    procs: &impl ProcFacts,
    sessions: &Registrations,
    request: &PeerRequest<'_>,
) -> PeerAttribution {
    let peer = request.peer;

    // syscall-arm: the broker parent connects on behalf of the tracee during
    // emulated connects; prefer the wire tracee pid when it is the peer or a
    // direct descendant (fs-arm after fork).
    let verified_pid = match request.wire_pid.filter(|&pid| pid > 0) {
        Some(wire) if procs.is_descendant_of(peer.pid, wire) => Some(wire),
        _ if peer.pid > 0 => Some(peer.pid),
        _ => None,
    };

    let session_id = request
        .wire_session_id
        .map(str::to_owned)
        .or_else(|| verified_pid.and_then(|pid| procs.session_id(pid)));

    let mut result = PeerAttribution {
        verified_pid,
        attribution: Attribution {
            session_id,
            package: None,
            evidence: None,
        },
        paths: PeerPaths::default(),
    };

    let Some(pid) = verified_pid else {
        return result;
    };

    let Some(reg) = result
        .attribution
        .session_id
        .as_ref()
        .and_then(|id| sessions.get(id))
    else {
        result.paths = peer_paths(procs, pid, peer.uid, None);
        return result;
    };

    let Some(evidence) = peer_standing(procs, reg, peer.pid, pid) else {
        return result;
    };

    if reg.owner_uid == peer.uid {
        result.attribution.package.clone_from(&reg.package);
        result.attribution.evidence = Some(evidence);
    }

    result.paths = peer_paths(procs, pid, peer.uid, Some(reg));
    result
}

impl PolicyStore {
    /// The registered owner uid of a session.
    pub(crate) fn session_owner_uid(&self, session_id: &str) -> Option<u32> {
        self.with_registrations(|sessions| sessions.get(session_id).map(|reg| reg.owner_uid))
    }

    /// Run `f` over the registrations. A poisoned lock reads as no
    /// registrations.
    pub(super) fn with_registrations<T>(&self, f: impl FnOnce(&Registrations) -> T) -> T {
        match self.sandbox_sessions.read() {
            Ok(sessions) => f(&sessions),
            Err(_) => f(&Registrations::new()),
        }
    }
}

/// A session adopted by process, with how.
struct Adopted {
    id: String,
    evidence: Evidence,
}

/// A registration's anchor: the pid (root, else launcher) a member descends
/// from.
struct Anchor<'a> {
    id: &'a str,
    pid: u32,
    cgroup: Option<&'a PathBuf>,
}

/// Adopt the sandbox session whose launcher or root pid is an ancestor of
/// `pid`. Adoption requires the owner uid to match the process uid. For
/// nested sandboxes the innermost matching anchor wins. A pid outside every
/// anchor's tree falls back to the session whose agent scope it shares, when
/// exactly one session claims that scope.
fn adopt_by_process(
    procs: &impl ProcFacts,
    sessions: &Registrations,
    pid: u32,
    uid: Option<u32>,
) -> Option<Adopted> {
    // A registration with neither a root nor a launcher has no process tree
    // to anchor on, so it adopts nothing.
    let anchors: Vec<Anchor<'_>> = sessions
        .iter()
        .filter(|(_, reg)| reg.owner_uid == 0 || Some(reg.owner_uid) == uid)
        .filter_map(|(id, reg)| {
            Some(Anchor {
                id,
                pid: reg.root.pid().or_else(|| reg.launcher.pid())?,
                cgroup: reg.cgroup.as_ref(),
            })
        })
        .collect();

    let candidates: Vec<&Anchor<'_>> = anchors
        .iter()
        .filter(|anchor| procs.is_descendant_of(anchor.pid, pid))
        .collect();

    let innermost = candidates.iter().find(|candidate| {
        !candidates.iter().any(|other| {
            other.pid != candidate.pid && procs.is_descendant_of(candidate.pid, other.pid)
        })
    });

    if let Some(anchor) = innermost {
        return Some(Adopted {
            id: anchor.id.to_owned(),
            evidence: Evidence::Ancestry,
        });
    }

    let cgroup = procs.cgroup(pid)?;
    let mut scoped = anchors
        .iter()
        .filter(|anchor| anchor.cgroup == Some(&cgroup));
    let anchor = scoped.next()?;

    scoped.next().is_none().then(|| Adopted {
        id: anchor.id.to_owned(),
        evidence: Evidence::AgentScope,
    })
}

/// How the verified pid stands in a registered session, or `None` when it
/// stands outside: then it inherits neither package nor paths.
///
/// Only a peer inside the sandbox's own process tree (a strict descendant of
/// the recorded launcher) qualifies, so the launcher itself and same-uid host
/// processes above it (the user's shell, the agent client that spawned the
/// sandbox) stay excluded and a forged session id cannot claim a foreign
/// package.
fn peer_standing(
    procs: &impl ProcFacts,
    reg: &SandboxSessionRegistration,
    peer_pid: u32,
    pid: u32,
) -> Option<Evidence> {
    let launcher = reg.launcher.pid()?;
    let root = reg.root.pid()?;

    if peer_pid == launcher || !procs.is_descendant_of(launcher, peer_pid) {
        return None;
    }

    if procs.is_descendant_of(root, pid) {
        return Some(Evidence::SessionTree);
    }

    // The syscall broker is the parent of the session root (the fs-arm entry
    // process), never its descendant, and its CheckResource carries the
    // tracee pid, which lives beside the root rather than under it, so
    // neither root-based check can pass. The authenticated peer's host pid is
    // the broker: accept it when it is an ancestor of the adopted root.
    procs
        .is_descendant_of(peer_pid, root)
        .then_some(Evidence::BrokerAncestor)
}

/// Read the launcher env vars and `/proc` paths for a verified sandbox peer,
/// then hold the project root to the registered one.
fn peer_paths(
    procs: &impl ProcFacts,
    pid: u32,
    uid: u32,
    registration: Option<&SandboxSessionRegistration>,
) -> PeerPaths {
    let proc = procs.paths(pid, Some(uid));
    let registered = registration
        .map(|reg| &reg.project_root)
        .filter(|root| !root.as_os_str().is_empty());

    // Session members whose environment lacks the claim (tools such as an
    // agent's Python kernel start with a scrubbed env) or names a root
    // outside the session get the session's own root.
    let project_root = match registered {
        Some(root) => Some(
            proc.project_root
                .filter(|claimed| is_path_descendant(claimed, root))
                .unwrap_or_else(|| root.clone()),
        ),
        None => proc.project_root,
    };

    PeerPaths {
        cwd: proc.cwd,
        project_root,
    }
}

/// The adapter over the host's `/proc`. Parent chains are walked only as far
/// as a question needs and then reused, so each process is read once per
/// resolution however many registrations ask about it.
#[derive(Default)]
pub(super) struct HostProcfs {
    lineages: RefCell<HashMap<u32, Lineage>>,
}

/// Parent chain of one pid, walked on demand.
#[derive(Default)]
struct Lineage {
    parents: Vec<u32>,
    complete: bool,
}

impl Lineage {
    /// Read the next parent of `pid`, returning it, or mark the chain
    /// complete at the root of the tree, an unreadable process or the depth
    /// bound.
    fn step(&mut self, pid: u32) -> Option<u32> {
        let current = self.parents.last().copied().unwrap_or(pid);

        let parent = if self.parents.len() >= MAX_ANCESTRY_DEPTH {
            None
        } else {
            read_proc_ppid(current)
        };

        match parent {
            Some(parent) => {
                self.complete = parent <= 1;
                self.parents.push(parent);
            }
            None => self.complete = true,
        }

        parent
    }
}

impl ProcFacts for HostProcfs {
    fn session_id(&self, pid: u32) -> Option<String> {
        sandbox_session_id_from_pid(pid)
    }

    fn is_descendant_of(&self, ancestor: u32, pid: u32) -> bool {
        if ancestor == 0 || pid == 0 {
            return false;
        }

        if ancestor == pid {
            return true;
        }

        let mut lineages = self.lineages.borrow_mut();
        let lineage = lineages.entry(pid).or_default();

        if lineage.parents.contains(&ancestor) {
            return true;
        }

        while !lineage.complete {
            if lineage.step(pid) == Some(ancestor) {
                return true;
            }
        }

        false
    }

    fn cgroup(&self, pid: u32) -> Option<PathBuf> {
        process_cgroup(pid).ok()
    }

    fn paths(&self, pid: u32, uid: Option<u32>) -> ProcContext {
        peer_context(pid, uid)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::store::types::{LauncherBinding, RootAdoption};

    /// Process facts for one fixture: parent links, environments, cgroups and
    /// launcher path claims by pid.
    #[derive(Default)]
    struct FixtureProcs {
        parents: HashMap<u32, u32>,
        session_ids: HashMap<u32, String>,
        cgroups: HashMap<u32, PathBuf>,
        claims: HashMap<u32, ProcContext>,
    }

    impl FixtureProcs {
        fn with_chain(mut self, chain: &[u32]) -> Self {
            for pair in chain.windows(2) {
                self.parents.insert(pair[1], pair[0]);
            }

            self
        }
    }

    impl ProcFacts for FixtureProcs {
        fn session_id(&self, pid: u32) -> Option<String> {
            self.session_ids.get(&pid).cloned()
        }

        fn is_descendant_of(&self, ancestor: u32, pid: u32) -> bool {
            let mut current = pid;

            while ancestor != 0 && current != 0 {
                if current == ancestor {
                    return true;
                }

                let Some(&parent) = self.parents.get(&current) else {
                    return false;
                };

                current = parent;
            }

            false
        }

        fn cgroup(&self, pid: u32) -> Option<PathBuf> {
            self.cgroups.get(&pid).cloned()
        }

        fn paths(&self, pid: u32, _uid: Option<u32>) -> ProcContext {
            self.claims.get(&pid).cloned().unwrap_or_default()
        }
    }

    const OWNER: u32 = 1000;
    const LAUNCHER: u32 = 100;
    const ROOT: u32 = 200;

    fn registration() -> SandboxSessionRegistration {
        SandboxSessionRegistration {
            root: RootAdoption::Adopted { pid: ROOT },
            owner_uid: OWNER,
            project_root: PathBuf::from("/work/project"),
            package: Some("codex".into()),
            launcher: LauncherBinding::Bound {
                pid: LAUNCHER,
                start_ticks: 1,
            },
            cgroup: None,
            export_reader: None,
        }
    }

    fn session(id: &str, registration: SandboxSessionRegistration) -> Registrations {
        Registrations::from([(id.to_owned(), registration)])
    }

    /// init -> launcher -> broker -> root -> shell -> tool, with a tracee 160
    /// under the broker beside the root and an unrelated host process 900.
    fn tree() -> FixtureProcs {
        FixtureProcs::default()
            .with_chain(&[1, LAUNCHER, 150, ROOT, 300, 400])
            .with_chain(&[150, 160])
            .with_chain(&[1, 900])
    }

    struct TrustedCase {
        name: &'static str,
        procs: FixtureProcs,
        sessions: Registrations,
        claim: Option<&'static str>,
        pid: Option<u32>,
        uid: Option<u32>,
        expect_id: Option<&'static str>,
        expect_package: Option<&'static str>,
        expect_evidence: Option<Evidence>,
    }

    fn trusted_cases() -> Vec<TrustedCase> {
        let one = || session("s", registration());
        let case = |name, pid, uid, expect_id, expect_evidence| TrustedCase {
            name,
            procs: tree(),
            sessions: one(),
            claim: None,
            pid: Some(pid),
            uid,
            expect_id,
            expect_package: expect_id.map(|_| "codex"),
            expect_evidence,
        };

        let mut scoped = registration();
        scoped.cgroup = Some("/sys/fs/cgroup/agent.scope".into());
        let mut scoped_procs = tree();
        scoped_procs
            .cgroups
            .insert(900, "/sys/fs/cgroup/agent.scope".into());

        let mut inner = registration();
        inner.root = RootAdoption::Adopted { pid: 300 };
        inner.package = Some("inner".into());

        vec![
            case(
                "direct root",
                ROOT,
                Some(OWNER),
                Some("s"),
                Some(Evidence::Ancestry),
            ),
            case(
                "descendant",
                400,
                Some(OWNER),
                Some("s"),
                Some(Evidence::Ancestry),
            ),
            case("outside the tree", 900, Some(OWNER), None, None),
            case("foreign uid", 400, Some(OWNER + 1), None, None),
            TrustedCase {
                name: "reparented daemon by scope",
                procs: scoped_procs,
                sessions: session("s", scoped.clone()),
                ..case("", 900, Some(OWNER), Some("s"), Some(Evidence::AgentScope))
            },
            TrustedCase {
                name: "ambiguous scope",
                procs: {
                    let mut procs = tree();
                    procs
                        .cgroups
                        .insert(900, "/sys/fs/cgroup/agent.scope".into());
                    procs
                },
                sessions: session("a", scoped.clone())
                    .into_iter()
                    .chain(session("b", scoped))
                    .collect(),
                ..case("", 900, Some(OWNER), None, None)
            },
            TrustedCase {
                name: "innermost nested anchor wins",
                sessions: session("outer", registration())
                    .into_iter()
                    .chain(session("inner", inner))
                    .collect(),
                expect_package: Some("inner"),
                ..case(
                    "",
                    400,
                    Some(OWNER),
                    Some("inner"),
                    Some(Evidence::Ancestry),
                )
            },
            TrustedCase {
                name: "bare tracee reads the environment id first",
                procs: {
                    let mut procs = tree();
                    procs.session_ids.insert(400, "s".into());
                    procs
                },
                ..case("", 400, None, Some("s"), Some(Evidence::TrustedCaller))
            },
            TrustedCase {
                name: "trusted caller adopts the package by id alone",
                claim: Some("s"),
                pid: None,
                ..case("", 0, None, Some("s"), Some(Evidence::TrustedCaller))
            },
            TrustedCase {
                name: "unregistered claim is unattributed",
                claim: Some("ghost"),
                expect_package: None,
                ..case("", 400, Some(OWNER), Some("ghost"), None)
            },
        ]
    }

    #[test]
    fn trusted_attribution_table() {
        for case in trusted_cases() {
            let got = attribute_trusted(
                &case.procs,
                &case.sessions,
                case.claim.map(str::to_owned),
                case.pid,
                case.uid,
            );

            assert_eq!(
                got,
                Attribution {
                    session_id: case.expect_id.map(str::to_owned),
                    package: case.expect_package.map(str::to_owned),
                    evidence: case.expect_evidence,
                },
                "{}",
                case.name
            );
        }
    }

    struct PeerCase {
        name: &'static str,
        procs: FixtureProcs,
        registration: SandboxSessionRegistration,
        wire_pid: Option<u32>,
        peer: TrustedPeer,
        expect_verified: Option<u32>,
        expect_evidence: Option<Evidence>,
        expect_paths: bool,
    }

    fn peer_cases() -> Vec<PeerCase> {
        let peer = |pid| TrustedPeer { pid, uid: OWNER };
        let case = |name, wire_pid, peer: TrustedPeer, verified, evidence, paths| PeerCase {
            name,
            procs: tree(),
            registration: registration(),
            wire_pid,
            peer,
            expect_verified: verified,
            expect_evidence: evidence,
            expect_paths: paths,
        };

        vec![
            case(
                "root itself",
                None,
                peer(ROOT),
                Some(ROOT),
                Some(Evidence::SessionTree),
                true,
            ),
            case(
                "descendant",
                None,
                peer(400),
                Some(400),
                Some(Evidence::SessionTree),
                true,
            ),
            case(
                "wire tracee below the peer is preferred",
                Some(400),
                peer(ROOT),
                Some(400),
                Some(Evidence::SessionTree),
                true,
            ),
            case(
                "launcher itself is excluded",
                None,
                peer(LAUNCHER),
                Some(LAUNCHER),
                None,
                false,
            ),
            case(
                "host process above the launcher",
                None,
                peer(1),
                Some(1),
                None,
                false,
            ),
            case(
                "same-uid process outside the tree",
                None,
                peer(900),
                Some(900),
                None,
                false,
            ),
            case(
                "broker ancestor with an unresolvable wire pid",
                Some(2_147_483_647),
                peer(150),
                Some(150),
                Some(Evidence::BrokerAncestor),
                true,
            ),
            case(
                "broker tracee beside the root",
                Some(160),
                peer(150),
                Some(160),
                Some(Evidence::BrokerAncestor),
                true,
            ),
            PeerCase {
                name: "owner uid mismatch keeps paths but no package",
                peer: TrustedPeer {
                    pid: 400,
                    uid: OWNER + 1,
                },
                ..case("", None, peer(400), Some(400), None, true)
            },
            PeerCase {
                name: "registration without a launcher grants nothing",
                registration: SandboxSessionRegistration {
                    launcher: LauncherBinding::Unbound,
                    ..registration()
                },
                ..case("", None, peer(400), Some(400), None, false)
            },
        ]
    }

    #[test]
    fn peer_attribution_table() {
        for case in peer_cases() {
            let sessions = session("s", case.registration.clone());

            let got = attribute_peer(&case.procs, &sessions, &PeerRequest {
                wire_session_id: Some("s"),
                wire_pid: case.wire_pid,
                peer: case.peer,
            });

            assert_eq!(got.verified_pid, case.expect_verified, "{}", case.name);
            assert_eq!(
                got.attribution.evidence, case.expect_evidence,
                "{}",
                case.name
            );

            assert_eq!(
                got.attribution.package.as_deref(),
                case.expect_evidence.map(|_| "codex"),
                "{}",
                case.name
            );

            assert_eq!(
                got.attribution.session_id.as_deref(),
                Some("s"),
                "{}: the claimed id is kept",
                case.name
            );

            assert_eq!(
                got.paths.project_root.is_some(),
                case.expect_paths,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn bare_tracee_uses_registered_root() {
        let sessions = session("s", registration());
        let procs = tree();

        let got = attribute_peer(&procs, &sessions, &PeerRequest {
            wire_session_id: Some("s"),
            wire_pid: None,
            peer: TrustedPeer {
                pid: 400,
                uid: OWNER,
            },
        });

        assert_eq!(
            got.paths.project_root.as_deref(),
            Some(Path::new("/work/project"))
        );
    }

    #[test]
    fn project_root_claim_is_held_to_the_registered_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("project");
        let inside = root.join("sub");
        let outside = tmp.path().join("elsewhere");

        for dir in [&inside, &outside] {
            std::fs::create_dir_all(dir).expect("create dir");
        }

        let mut reg = registration();
        reg.project_root.clone_from(&root);
        let sessions = session("s", reg);

        let claimed = |project_root: &Path| {
            let mut procs = tree();

            procs.claims.insert(400, ProcContext {
                project_root: Some(project_root.to_path_buf()),
                ..ProcContext::default()
            });

            attribute_peer(&procs, &sessions, &PeerRequest {
                wire_session_id: Some("s"),
                wire_pid: None,
                peer: TrustedPeer {
                    pid: 400,
                    uid: OWNER,
                },
            })
            .paths
            .project_root
        };

        assert_eq!(claimed(&inside).as_deref(), Some(inside.as_path()));
        assert_eq!(claimed(&outside).as_deref(), Some(root.as_path()));
    }

    #[test]
    fn peer_of_unregistered_session_reads_paths_without_package() {
        let procs = tree();

        let got = attribute_peer(&procs, &Registrations::new(), &PeerRequest {
            wire_session_id: Some("ghost"),
            wire_pid: None,
            peer: TrustedPeer {
                pid: 900,
                uid: OWNER,
            },
        });

        assert_eq!(got.attribution.package, None);
        assert_eq!(got.attribution.evidence, None);
        assert_eq!(got.attribution.session_id.as_deref(), Some("ghost"));
        assert_eq!(got.verified_pid, Some(900));
    }
}

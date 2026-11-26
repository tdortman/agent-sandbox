//! Policy store: project attribution.
//!
//! Decides which registered sandbox instance, and therefore which package, a
//! request belongs to. [`attribute_trusted`] serves policyd-side and root
//! callers, whose requests about a process are attributed from the process
//! itself; [`attribute_peer`] serves a sandbox peer
//! whose wire claims are not believed. Both are pure over [`ProcFacts`] and the
//! registrations; [`HostProcfs`] is the adapter that reads `/proc` and caches
//! what it read for the length of one resolution.

use std::{cell::RefCell, collections::HashMap, path::PathBuf};

use agent_sandbox_core::{ProcContext, peer_context, sandbox_session_id_from_pid};

use super::{
    context::read_proc_ppid,
    lifecycle::{process_cgroup, process_uid},
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

    /// The real uid `pid` runs as, from `/proc/<pid>/status`.
    fn uid(&self, pid: u32) -> Option<u32>;

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
    /// Session id the request was adopted into, or that a policyd-side
    /// caller that names no process gave. Session ids are not secret, so a
    /// claim by a process is never carried over unverified.
    pub session_id: Option<String>,

    /// Package of the registration, set only together with `evidence`.
    pub package: Option<String>,

    /// What established the attribution; `None` for a session id a
    /// policyd-side caller named that no registration backs.
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

/// Attribute a request from a policyd-side or root caller.
///
/// A request that names a subject process is attributed by that process
/// alone: its ancestry against the registered anchors, else its agent scope.
/// The wire session id and the process environment are controlled by the
/// sandbox, so they never establish attribution. A claim that disagrees with
/// the adopted session is ignored, and a claim no process evidence supports
/// yields no session at all, as session ids are not secret. A request that
/// names a process but no uid, as the filesystem monitor's events do, is held
/// to the uid the process runs as. A request that names no process comes from
/// a policyd-side caller naming its own session; the registration is trusted
/// by id alone.
pub(super) fn attribute_trusted(
    procs: &impl ProcFacts,
    sessions: &Registrations,
    claim: Option<String>,
    pid: Option<u32>,
    uid: Option<u32>,
) -> Attribution {
    let Some(pid) = pid else {
        return claim.map_or_default(|id| registered(sessions, id, Evidence::TrustedCaller));
    };
    let uid = uid.or_else(|| procs.uid(pid));

    // The claim is only a hint for the caller's own bookkeeping: a request
    // that names a process carries a session id only when the process was
    // adopted into that session.
    adopt_by_process(procs, sessions, pid, uid).map_or_else(Attribution::default, |found| {
        registered(sessions, found.id, found.evidence)
    })
}

/// The attribution of `id` when `evidence` established it: the package of
/// its registration, if there is one.
fn registered(sessions: &Registrations, id: String, evidence: Evidence) -> Attribution {
    let registration = sessions.get(&id);

    Attribution {
        package: registration.and_then(|reg| reg.package.clone()),
        evidence: registration.map(|_| evidence),
        session_id: Some(id),
    }
}

/// Attribute a sandbox peer. The wire session id is attacker-controlled and
/// session ids are not secret, so the result carries a session id only when
/// the claimed session is registered to the peer's uid and the verified pid
/// stands inside it. The package and the registered project root are adopted
/// only for a launcher-bound registration.
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

    let mut result = PeerAttribution {
        verified_pid,
        attribution: Attribution::default(),
        paths: PeerPaths::default(),
    };

    let Some(pid) = verified_pid else {
        return result;
    };

    let claimed = request
        .wire_session_id
        .map(str::to_owned)
        .or_else(|| procs.session_id(pid));

    let standing = claimed.and_then(|id| {
        let reg = sessions.get(&id)?;

        if reg.owner_uid != peer.uid {
            return None;
        }

        let evidence = peer_standing(procs, reg, peer.pid, pid)?;

        Some((id, reg, evidence))
    });

    let Some((id, reg, evidence)) = standing else {
        result.paths = peer_paths(procs, pid, peer.uid, None);
        return result;
    };

    let bound = reg.launcher.pid().is_some();

    result.attribution = Attribution {
        session_id: Some(id),
        package: reg.package.clone().filter(|_| bound),
        evidence: Some(evidence),
    };

    result.paths = peer_paths(procs, pid, peer.uid, bound.then_some(reg));
    result
}

impl PolicyStore {
    /// The registered owner uid of a session.
    pub(crate) fn session_owner_uid(&self, session_id: &str) -> Option<u32> {
        self.with_registrations(|sessions| sessions.get(session_id).map(|reg| reg.owner_uid))
    }

    /// Run `f` over the current registrations snapshot.
    pub(super) fn with_registrations<T>(&self, f: impl FnOnce(&Registrations) -> T) -> T {
        f(&self.sandbox_sessions.snapshot())
    }
}

/// A session adopted by process, with how.
struct Adopted {
    id: String,
    evidence: Evidence,
}

/// A registration's anchor: a pid a member descends from.
struct Anchor<'a> {
    id: &'a str,
    pid: u32,
    cgroup: Option<&'a PathBuf>,

    /// Whether the anchor process itself is outside the session.
    strict: bool,

    /// Whether the trusted launcher registered the session.
    bound: bool,
}

impl Anchor<'_> {
    fn contains(&self, procs: &impl ProcFacts, pid: u32) -> bool {
        procs.is_descendant_of(self.pid, pid) && !(self.strict && self.pid == pid)
    }
}

/// The anchors of a registration: its root, and for a launcher-bound
/// registration the launcher itself for the processes beside the root. Without
/// a root the launcher is the anchor. A registration without a launcher was
/// recorded by requests from its own sandbox, not by the trusted launcher, so
/// its root anchors only below every launcher-bound anchor: a sandbox cannot
/// register a session of its own to shadow the launcher's registration.
fn anchors_of<'a>(id: &'a str, reg: &'a SandboxSessionRegistration) -> Vec<Anchor<'a>> {
    let anchor = |pid, strict, bound| Anchor {
        id,
        pid,
        cgroup: reg.cgroup.as_ref(),
        strict,
        bound,
    };

    match (reg.launcher.pid(), reg.root.pid()) {
        (Some(launcher), Some(root)) => {
            vec![anchor(root, false, true), anchor(launcher, true, true)]
        }
        (Some(launcher), None) => vec![anchor(launcher, false, true)],
        (None, Some(root)) => vec![anchor(root, false, false)],
        (None, None) => Vec::new(),
    }
}

/// Adopt the sandbox session whose root (else launcher) pid is an ancestor
/// of `pid`, or whose launcher is a strict ancestor of it: the syscall
/// broker and its tracee live beside the root, under the launcher. Adoption
/// requires the owner uid to match the process uid. For nested sandboxes the
/// innermost matching anchor wins. A pid outside every anchor's tree falls
/// back to the session whose agent scope it shares, when exactly one session
/// claims that scope.
fn adopt_by_process(
    procs: &impl ProcFacts,
    sessions: &Registrations,
    pid: u32,
    uid: Option<u32>,
) -> Option<Adopted> {
    let anchors: Vec<Anchor<'_>> = sessions
        .iter()
        .filter(|(_, reg)| reg.owner_uid == 0 || Some(reg.owner_uid) == uid)
        .flat_map(|(id, reg)| anchors_of(id, reg))
        .collect();

    let mut candidates: Vec<&Anchor<'_>> = anchors
        .iter()
        .filter(|anchor| anchor.contains(procs, pid))
        .collect();

    if candidates.iter().any(|anchor| anchor.bound) {
        candidates.retain(|anchor| anchor.bound);
    }

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

    let mut sharing: Vec<&Anchor<'_>> = anchors
        .iter()
        .filter(|anchor| anchor.cgroup == Some(&cgroup))
        .collect();

    if sharing.iter().any(|anchor| anchor.bound) {
        sharing.retain(|anchor| anchor.bound);
    }

    let mut scoped: Vec<&str> = sharing.iter().map(|anchor| anchor.id).collect();

    scoped.sort_unstable();
    scoped.dedup();

    match scoped.as_slice() {
        [id] => Some(Adopted {
            id: (*id).to_owned(),
            evidence: Evidence::AgentScope,
        }),
        _ => None,
    }
}

/// How the verified pid stands in a registered session, or `None` when it
/// stands outside: then it inherits neither package nor paths.
///
/// Only a peer inside the sandbox's own process tree (a strict descendant of
/// the recorded launcher, or of the root for a session without one) qualifies,
/// so the launcher itself and same-uid host processes above it (the user's
/// shell, the agent client that spawned the sandbox) stay excluded and a forged
/// session id cannot claim a foreign package.
fn peer_standing(
    procs: &impl ProcFacts,
    reg: &SandboxSessionRegistration,
    peer_pid: u32,
    pid: u32,
) -> Option<Evidence> {
    let root = reg.root.pid()?;

    // A session its own sandbox registered has no launcher; its members are
    // the root and what descends from it.
    let Some(launcher) = reg.launcher.pid() else {
        return procs
            .is_descendant_of(root, pid)
            .then_some(Evidence::SessionTree);
    };

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

/// Read the cwd of a verified sandbox peer and pair it with the registered
/// project root. The peer's environment never names the project: a session
/// without a registered root, and a peer without a registration, have none.
fn peer_paths(
    procs: &impl ProcFacts,
    pid: u32,
    uid: u32,
    registration: Option<&SandboxSessionRegistration>,
) -> PeerPaths {
    let project_root = registration
        .map(|reg| reg.project_root.clone())
        .filter(|root| !root.as_os_str().is_empty());

    PeerPaths {
        cwd: procs.paths(pid, Some(uid)).cwd,
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

    fn uid(&self, pid: u32) -> Option<u32> {
        process_uid(pid).ok()
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
        uids: HashMap<u32, u32>,
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

        fn uid(&self, pid: u32) -> Option<u32> {
            self.uids.get(&pid).copied()
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

        let mut other = registration();
        other.root = RootAdoption::Adopted { pid: 900 };

        other.launcher = LauncherBinding::Bound {
            pid: 900,
            start_ticks: 1,
        };

        other.package = Some("other".into());

        let mut unbound = registration();
        unbound.root = RootAdoption::Adopted { pid: 400 };
        unbound.launcher = LauncherBinding::Unbound;
        unbound.package = None;

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
                name: "forged environment id and wire claim name another session",
                procs: {
                    let mut procs = tree();
                    procs.session_ids.insert(400, "other".into());
                    procs
                },
                sessions: session("s", registration())
                    .into_iter()
                    .chain(session("other", other))
                    .collect(),
                claim: Some("other"),
                ..case("", 400, Some(OWNER), Some("s"), Some(Evidence::Ancestry))
            },
            TrustedCase {
                name: "environment id alone adopts nothing",
                procs: {
                    let mut procs = tree();
                    procs.session_ids.insert(900, "s".into());
                    procs
                },
                ..case("", 900, Some(OWNER), None, None)
            },
            TrustedCase {
                name: "claim of a registered session without adoption",
                claim: Some("s"),
                ..case("", 900, Some(OWNER), None, None)
            },
            TrustedCase {
                name: "event without a uid is held to the process owner",
                procs: {
                    let mut procs = tree();
                    procs.uids.insert(400, OWNER);
                    procs
                },
                claim: Some("s"),
                ..case("", 400, None, Some("s"), Some(Evidence::Ancestry))
            },
            TrustedCase {
                name: "event without a uid from another user's process",
                procs: {
                    let mut procs = tree();
                    procs.uids.insert(400, OWNER + 1);
                    procs
                },
                claim: Some("s"),
                ..case("", 400, None, None, None)
            },
            TrustedCase {
                name: "event without a uid from an unreadable process",
                claim: Some("s"),
                ..case("", 400, None, None, None)
            },
            TrustedCase {
                name: "tracee beside the root is adopted by the launcher",
                ..case("", 160, Some(OWNER), Some("s"), Some(Evidence::Ancestry))
            },
            case(
                "the launcher is no member",
                LAUNCHER,
                Some(OWNER),
                None,
                None,
            ),
            TrustedCase {
                name: "session recorded without a launcher adopts its own members",
                sessions: session("u", unbound.clone()),
                expect_package: None,
                ..case("", 400, Some(OWNER), Some("u"), Some(Evidence::Ancestry))
            },
            TrustedCase {
                name: "session recorded without a launcher does not shadow a registered one",
                sessions: session("s", registration())
                    .into_iter()
                    .chain(session("rogue", unbound))
                    .collect(),
                ..case("", 400, Some(OWNER), Some("s"), Some(Evidence::Ancestry))
            },
            TrustedCase {
                name: "trusted caller adopts the package by id alone",
                claim: Some("s"),
                pid: None,
                ..case("", 0, None, Some("s"), Some(Evidence::TrustedCaller))
            },
            TrustedCase {
                name: "unregistered claim of a process is dropped",
                claim: Some("ghost"),
                expect_package: None,
                ..case("", 900, Some(OWNER), None, None)
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
                name: "owner uid mismatch has no standing",
                peer: TrustedPeer {
                    pid: 400,
                    uid: OWNER + 1,
                },
                ..case("", None, peer(400), Some(400), None, false)
            },
            PeerCase {
                name: "registration without a launcher gives its members the session only",
                registration: SandboxSessionRegistration {
                    launcher: LauncherBinding::Unbound,
                    ..registration()
                },
                ..case(
                    "",
                    None,
                    peer(400),
                    Some(400),
                    Some(Evidence::SessionTree),
                    false,
                )
            },
            PeerCase {
                name: "registration without a launcher excludes outsiders",
                registration: SandboxSessionRegistration {
                    launcher: LauncherBinding::Unbound,
                    ..registration()
                },
                ..case("", None, peer(900), Some(900), None, false)
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
                case.registration
                    .launcher
                    .pid()
                    .and(case.expect_evidence)
                    .map(|_| "codex"),
                "{}",
                case.name
            );

            assert_eq!(
                got.attribution.session_id.as_deref(),
                case.expect_evidence.map(|_| "s"),
                "{}: only a verified session id is carried",
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

    /// The project root of a peer whose pid 400 claims `project_root` in its
    /// environment.
    fn claimed_project_root(
        sessions: &Registrations,
        wire_session_id: &str,
        project_root: &str,
    ) -> Option<PathBuf> {
        let mut procs = tree();

        procs.claims.insert(400, ProcContext {
            project_root: Some(PathBuf::from(project_root)),
            ..ProcContext::default()
        });

        attribute_peer(&procs, sessions, &PeerRequest {
            wire_session_id: Some(wire_session_id),
            wire_pid: None,
            peer: TrustedPeer {
                pid: 400,
                uid: OWNER,
            },
        })
        .paths
        .project_root
    }

    #[test]
    fn project_root_claim_never_replaces_or_narrows_the_registered_root() {
        let sessions = session("s", registration());

        for claim in ["/work/project/sub", "/work/elsewhere", "/"] {
            assert_eq!(
                claimed_project_root(&sessions, "s", claim).as_deref(),
                Some(Path::new("/work/project")),
                "{claim}"
            );
        }
    }

    #[test]
    fn project_root_claim_selects_nothing_without_a_registered_root() {
        let mut reg = registration();
        reg.project_root = PathBuf::new();

        assert_eq!(
            claimed_project_root(&session("s", reg), "s", "/work/project"),
            None
        );
    }

    #[test]
    fn peer_of_unregistered_session_has_no_session_package_or_project() {
        let mut procs = tree();

        procs.claims.insert(900, ProcContext {
            project_root: Some(PathBuf::from("/work/project")),
            ..ProcContext::default()
        });

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
        assert_eq!(got.attribution.session_id, None);
        assert_eq!(got.verified_pid, Some(900));
        assert_eq!(got.paths.project_root, None);
    }
}

use std::{future::Future, io, path::Path, time::Duration};

use agent_sandbox_core::{FileAccess, FilesystemCheckReply, ResourceCheckReply, VerdictSource};
use agent_sandbox_syscall_broker::{
    FilesystemTarget, NetworkTarget, PersistentPolicyClient, ResourceTarget, SeccompNotif,
    SyscallTarget, target_from_notification,
};

/// Facts extracted from a raw seccomp notification before policy evaluation.
#[derive(Debug)]
pub enum NormalizedNotification {
    Target { target: SyscallTarget },
    Continue,
    Deny { errno: i32 },
    ClassificationFailure { error: io::Error, transient: bool },
}

impl NormalizedNotification {
    #[cfg(test)]
    pub const fn target(target: SyscallTarget) -> Self {
        Self::Target { target }
    }

    #[cfg(test)]
    pub const fn continue_() -> Self {
        Self::Continue
    }

    #[cfg(test)]
    pub const fn deny(errno: i32) -> Self {
        Self::Deny { errno }
    }

    pub const fn classification_failure(error: io::Error, transient: bool) -> Self {
        Self::ClassificationFailure { error, transient }
    }
}

/// Convert a kernel notification into policy-independent facts.
pub fn normalize(notif: &SeccompNotif) -> Result<NormalizedNotification, io::Error> {
    target_from_notification(notif).map(|target| match target {
        None => NormalizedNotification::Continue,
        Some(SyscallTarget::Errno(errno)) => NormalizedNotification::Deny { errno },
        Some(target) => NormalizedNotification::Target { target },
    })
}

/// Semantic actions emitted by policy routing.
#[derive(Debug)]
pub enum ResponsePlan {
    Continue,

    DenyErrno {
        errno: i32,
    },

    EmulateResource {
        target: ResourceTarget,
    },

    EmulateFilesystem {
        target: FilesystemTarget,
    },

    ResourcePolicyDenied {
        target: ResourceTarget,
        source: VerdictSource,
        error: Option<String>,
    },

    ResourceRpcFailure {
        target: ResourceTarget,
        error: String,
    },

    FilesystemPolicyDenied {
        path: std::path::PathBuf,
        access: FileAccess,
        source: VerdictSource,
        error: Option<String>,
    },

    FilesystemRpcFailure {
        path: std::path::PathBuf,
        access: FileAccess,
        error: String,
    },
}

impl ResponsePlan {
    pub const fn deny(errno: i32) -> Self {
        Self::DenyErrno { errno }
    }

    pub const fn emulate_resource(target: ResourceTarget) -> Self {
        Self::EmulateResource { target }
    }

    pub const fn emulate_filesystem(target: FilesystemTarget) -> Self {
        Self::EmulateFilesystem { target }
    }
}

/// The policy surface `decide` needs: one query per gated syscall kind.
///
/// [`PersistentPolicyClient`] is the production adapter; tests drive an
/// in-memory fake so response semantics and fail-closed behaviour run
/// without a policyd socket.
pub trait PolicyQuery {
    /// Query the network gate. Every failure mode denies.
    fn check_network(
        &mut self,
        target: &NetworkTarget,
        sandbox_session_id: Option<String>,
        pid: u32,
        timeout: Duration,
    ) -> impl Future<Output = bool> + Send;

    /// Query the resource gate. RPC failures surface as `Err`.
    fn check_resource(
        &mut self,
        target: &ResourceTarget,
        sandbox_session_id: Option<String>,
        pid: u32,
        timeout: Duration,
    ) -> impl Future<Output = io::Result<ResourceCheckReply>> + Send;

    /// Query one filesystem path/access pair. RPC failures surface as `Err`.
    fn check_filesystem(
        &mut self,
        path: &Path,
        access: FileAccess,
        sandbox_session_id: Option<String>,
        pid: u32,
        timeout: Duration,
    ) -> impl Future<Output = io::Result<FilesystemCheckReply>> + Send;
}

impl PolicyQuery for PersistentPolicyClient {
    fn check_network(
        &mut self,
        target: &NetworkTarget,
        sandbox_session_id: Option<String>,
        pid: u32,
        timeout: Duration,
    ) -> impl Future<Output = bool> + Send {
        Self::check_target(self, target, sandbox_session_id, pid, timeout)
    }

    fn check_resource(
        &mut self,
        target: &ResourceTarget,
        sandbox_session_id: Option<String>,
        pid: u32,
        timeout: Duration,
    ) -> impl Future<Output = io::Result<ResourceCheckReply>> + Send {
        Self::check_resource(self, target, sandbox_session_id, pid, timeout)
    }

    fn check_filesystem(
        &mut self,
        path: &Path,
        access: FileAccess,
        sandbox_session_id: Option<String>,
        pid: u32,
        timeout: Duration,
    ) -> impl Future<Output = io::Result<FilesystemCheckReply>> + Send {
        Self::check_filesystem(self, path, access, sandbox_session_id, pid, timeout)
    }
}

pub async fn decide(
    client: &mut impl PolicyQuery,
    sandbox_session_id: Option<&str>,
    pid: u32,
    timeout: Duration,
    facts: NormalizedNotification,
) -> ResponsePlan {
    match facts {
        NormalizedNotification::Continue
        | NormalizedNotification::ClassificationFailure {
            transient: true, ..
        } => ResponsePlan::Continue,

        NormalizedNotification::Deny { errno } => ResponsePlan::deny(errno),

        // `normalize` maps `SyscallTarget::Errno` to `Deny`, so a `Target`
        // carrying `Errno` cannot reach `decide`.
        NormalizedNotification::Target {
            target: SyscallTarget::Errno(_),
        } => {
            unreachable!("normalize maps SyscallTarget::Errno to Deny")
        }

        NormalizedNotification::ClassificationFailure {
            transient: false, ..
        } => ResponsePlan::deny(libc::EACCES),

        NormalizedNotification::Target {
            target: SyscallTarget::Network(target),
        } => ResponsePlan::plan_network(
            client
                .check_network(&target, sandbox_session_id.map(str::to_owned), pid, timeout)
                .await,
        ),

        NormalizedNotification::Target {
            target: SyscallTarget::Resource(target),
        } => resource_plan(
            target.clone(),
            client
                .check_resource(&target, sandbox_session_id.map(str::to_owned), pid, timeout)
                .await,
        ),

        NormalizedNotification::Target {
            target: SyscallTarget::Filesystem(target),
        } => {
            for (path, access) in &target.checks {
                if let Some(plan) = filesystem_plan(
                    path,
                    *access,
                    client
                        .check_filesystem(
                            path,
                            *access,
                            sandbox_session_id.map(str::to_owned),
                            pid,
                            timeout,
                        )
                        .await,
                ) {
                    return plan;
                }
            }
            ResponsePlan::emulate_filesystem(target)
        }
    }
}

fn resource_plan(target: ResourceTarget, reply: io::Result<ResourceCheckReply>) -> ResponsePlan {
    match reply {
        Ok(reply) if reply.allowed => ResponsePlan::emulate_resource(target),

        Ok(reply) => ResponsePlan::ResourcePolicyDenied {
            target,
            source: reply.source,
            error: reply.error,
        },

        Err(error) => ResponsePlan::ResourceRpcFailure {
            target,
            error: error.to_string(),
        },
    }
}

fn filesystem_plan(
    path: &Path,
    access: FileAccess,
    reply: io::Result<FilesystemCheckReply>,
) -> Option<ResponsePlan> {
    match reply {
        Ok(reply) if reply.allowed => None,

        Ok(reply) => Some(ResponsePlan::FilesystemPolicyDenied {
            path: reply.path,
            access: reply.access,
            source: reply.source,
            error: reply.error,
        }),

        Err(error) => Some(ResponsePlan::FilesystemRpcFailure {
            path: path.to_path_buf(),
            access,
            error: error.to_string(),
        }),
    }
}

impl ResponsePlan {
    const fn plan_network(allowed: bool) -> Self {
        if allowed {
            Self::Continue
        } else {
            Self::deny(libc::EACCES)
        }
    }
}

pub fn normalize_or_failure(notif: &SeccompNotif) -> NormalizedNotification {
    match normalize(notif) {
        Ok(facts) => facts,

        Err(error) => {
            let transient = agent_sandbox_syscall_broker::is_transient_tracee_io_err(&error);
            NormalizedNotification::classification_failure(error, transient)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io, os::fd::OwnedFd, path::Path, time::Duration};

    use agent_sandbox_core::{
        DeviceAccess, FileAccess, FilesystemCheckReply, ResourceAccess, ResourceCheckReply,
        ResourceKind, VerdictSource,
    };
    use agent_sandbox_syscall_broker::{
        FilesystemMutation, FilesystemTarget, NetworkTarget, PersistentPolicyClient,
        ResourceTarget, SyscallTarget,
    };

    use super::{
        NormalizedNotification, PolicyQuery, ResponsePlan, decide, filesystem_plan, resource_plan,
    };

    fn resource_target() -> ResourceTarget {
        ResourceTarget {
            kind: ResourceKind::Device,
            path: "/dev/example".into(),
            access: ResourceAccess::Device(DeviceAccess::Read),
            raw: Vec::new(),
            open_flags: 0,
            open_mode: 0,
        }
    }

    fn filesystem_target() -> FilesystemTarget {
        FilesystemTarget {
            checks: vec![("/tmp/example".into(), FileAccess::Write)],
            operation: FilesystemMutation::Ftruncate {
                fd: OwnedFd::from(std::fs::File::open("/dev/null").expect("dev null exists")),
                len: 0,
            },
        }
    }

    fn filesystem_target_with_two_checks() -> FilesystemTarget {
        FilesystemTarget {
            checks: vec![
                ("/tmp/example-a".into(), FileAccess::Write),
                ("/tmp/example-b".into(), FileAccess::Read),
            ],
            operation: FilesystemMutation::Ftruncate {
                fd: OwnedFd::from(std::fs::File::open("/dev/null").expect("dev null exists")),
                len: 0,
            },
        }
    }

    fn network_target() -> NetworkTarget {
        NetworkTarget {
            host: "example.com".into(),
            port: 443,
            scheme: "https".into(),
        }
    }

    #[derive(Default)]
    struct FakePolicy {
        network_allowed: bool,
        network_calls: u32,
        resource_reply: Option<io::Result<ResourceCheckReply>>,
        filesystem_replies: VecDeque<io::Result<FilesystemCheckReply>>,
        filesystem_calls: u32,
    }

    impl FakePolicy {
        fn with_replies(replies: Vec<io::Result<FilesystemCheckReply>>) -> Self {
            Self {
                filesystem_replies: replies.into(),
                ..Self::default()
            }
        }

        fn allowed_filesystem_reply(path: &Path, access: FileAccess) -> FilesystemCheckReply {
            FilesystemCheckReply {
                ok: true,
                allowed: true,
                source: VerdictSource::User,
                path: path.to_path_buf(),
                access,
                error: None,
            }
        }

        fn denied_filesystem_reply(path: &Path, access: FileAccess) -> FilesystemCheckReply {
            FilesystemCheckReply {
                ok: true,
                allowed: false,
                source: VerdictSource::User,
                path: path.to_path_buf(),
                access,
                error: Some("blocked".into()),
            }
        }
    }

    impl PolicyQuery for FakePolicy {
        fn check_network(
            &mut self,
            _target: &NetworkTarget,
            _sandbox_session_id: Option<String>,
            _pid: u32,
            _timeout: Duration,
        ) -> impl Future<Output = bool> + Send {
            self.network_calls += 1;
            std::future::ready(self.network_allowed)
        }

        fn check_resource(
            &mut self,
            _target: &ResourceTarget,
            _sandbox_session_id: Option<String>,
            _pid: u32,
            _timeout: Duration,
        ) -> impl Future<Output = io::Result<ResourceCheckReply>> + Send {
            std::future::ready(
                self.resource_reply
                    .take()
                    .expect("a resource reply is configured for every resource check"),
            )
        }

        fn check_filesystem(
            &mut self,
            _path: &Path,
            _access: FileAccess,
            _sandbox_session_id: Option<String>,
            _pid: u32,
            _timeout: Duration,
        ) -> impl Future<Output = io::Result<FilesystemCheckReply>> + Send {
            self.filesystem_calls += 1;
            std::future::ready(
                self.filesystem_replies
                    .pop_front()
                    .expect("a filesystem reply is queued for every filesystem check"),
            )
        }
    }

    #[tokio::test]
    async fn decision_routes_policy_independent_facts() {
        let mut client = PersistentPolicyClient::new("/tmp/agent-sandbox-test-policy.sock");

        assert!(matches!(
            decide(
                &mut client,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::continue_(),
            )
            .await,
            ResponsePlan::Continue
        ));

        assert!(matches!(
            decide(
                &mut client,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::deny(libc::ENOSYS),
            )
            .await,
            ResponsePlan::DenyErrno {
                errno: libc::ENOSYS
            }
        ));

        assert!(matches!(
            decide(
                &mut client,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::classification_failure(
                    io::Error::from_raw_os_error(libc::EINVAL),
                    false,
                ),
            )
            .await,
            ResponsePlan::DenyErrno {
                errno: libc::EACCES
            }
        ));
    }

    #[test]
    fn network_verdict_maps_to_plan() {
        assert!(matches!(
            ResponsePlan::plan_network(true),
            ResponsePlan::Continue
        ));
        assert!(matches!(
            ResponsePlan::plan_network(false),
            ResponsePlan::DenyErrno {
                errno: libc::EACCES
            }
        ));
    }

    #[test]
    fn resource_verdict_maps_to_plan() {
        let target = resource_target();

        let allowed = ResourceCheckReply {
            ok: true,
            allowed: true,
            source: VerdictSource::User,
            kind: target.kind,
            path: target.path.clone(),
            access: target.access,
            error: None,
        };

        assert!(matches!(
            resource_plan(target.clone(), Ok(allowed)),
            ResponsePlan::EmulateResource { .. }
        ));

        let denied = ResourceCheckReply {
            ok: true,
            allowed: false,
            source: VerdictSource::Policy {
                comment: Some("blocked".into()),
            },
            kind: target.kind,
            path: target.path.clone(),
            access: target.access,
            error: Some("blocked".into()),
        };

        assert!(matches!(
            resource_plan(target.clone(), Ok(denied)),
            ResponsePlan::ResourcePolicyDenied { .. }
        ));

        assert!(matches!(
            resource_plan(
                target,
                Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
            ),
            ResponsePlan::ResourceRpcFailure { .. }
        ));
    }

    #[test]
    fn filesystem_verdict_maps_to_plan() {
        let target = filesystem_target();
        let (path, access) = &target.checks[0];

        let allowed = FilesystemCheckReply {
            ok: true,
            allowed: true,
            source: VerdictSource::User,
            path: path.clone(),
            access: *access,
            error: None,
        };

        assert!(filesystem_plan(path, *access, Ok(allowed)).is_none());

        let denied = FilesystemCheckReply {
            ok: true,
            allowed: false,
            source: VerdictSource::Policy {
                comment: Some("blocked".into()),
            },
            path: path.clone(),
            access: *access,
            error: Some("blocked".into()),
        };

        assert!(matches!(
            filesystem_plan(path, *access, Ok(denied)),
            Some(ResponsePlan::FilesystemPolicyDenied { .. })
        ));

        assert!(matches!(
            filesystem_plan(
                Path::new("/tmp/example"),
                FileAccess::Write,
                Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
            ),
            Some(ResponsePlan::FilesystemRpcFailure { .. })
        ));
    }

    #[tokio::test]
    async fn decide_asks_the_policy_query_for_network_targets() {
        let mut allowed = FakePolicy {
            network_allowed: true,
            ..FakePolicy::default()
        };

        assert!(matches!(
            decide(
                &mut allowed,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::target(SyscallTarget::Network(network_target())),
            )
            .await,
            ResponsePlan::Continue
        ));

        let mut denied = FakePolicy::default();

        assert!(matches!(
            decide(
                &mut denied,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::target(SyscallTarget::Network(network_target())),
            )
            .await,
            ResponsePlan::DenyErrno {
                errno: libc::EACCES
            }
        ));

        assert_eq!(allowed.network_calls, 1);
        assert_eq!(denied.network_calls, 1);
    }

    #[tokio::test]
    async fn decide_maps_resource_replies_fail_closed() {
        let target = resource_target();
        let mut store = FakePolicy {
            resource_reply: Some(Ok(ResourceCheckReply {
                ok: true,
                allowed: true,
                source: VerdictSource::User,
                kind: target.kind,
                path: target.path.clone(),
                access: target.access,
                error: None,
            })),
            ..FakePolicy::default()
        };

        assert!(matches!(
            decide(
                &mut store,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::target(SyscallTarget::Resource(target.clone())),
            )
            .await,
            ResponsePlan::EmulateResource { .. }
        ));

        let mut failing = FakePolicy {
            resource_reply: Some(Err(io::Error::new(io::ErrorKind::TimedOut, "timeout"))),
            ..FakePolicy::default()
        };

        assert!(matches!(
            decide(
                &mut failing,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::target(SyscallTarget::Resource(target)),
            )
            .await,
            ResponsePlan::ResourceRpcFailure { .. }
        ));
    }

    #[tokio::test]
    async fn decide_short_circuits_filesystem_checks_on_first_deny() {
        let target = filesystem_target_with_two_checks();
        let replies = vec![
            Ok(FakePolicy::denied_filesystem_reply(
                &target.checks[0].0,
                target.checks[0].1,
            )),
            Ok(FakePolicy::allowed_filesystem_reply(
                &target.checks[1].0,
                target.checks[1].1,
            )),
        ];
        let mut store = FakePolicy::with_replies(replies);

        assert!(matches!(
            decide(
                &mut store,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::target(SyscallTarget::Filesystem(target)),
            )
            .await,
            ResponsePlan::FilesystemPolicyDenied { .. }
        ));

        assert_eq!(store.filesystem_calls, 1, "the second check must not run");
    }

    #[tokio::test]
    async fn decide_short_circuits_filesystem_checks_on_rpc_failure() {
        let target = filesystem_target_with_two_checks();
        let second = {
            let (path, access) = &target.checks[1];
            Ok(FakePolicy::allowed_filesystem_reply(path, *access))
        };
        let mut store = FakePolicy::with_replies(vec![
            Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
            second,
        ]);

        assert!(matches!(
            decide(
                &mut store,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::target(SyscallTarget::Filesystem(target)),
            )
            .await,
            ResponsePlan::FilesystemRpcFailure { .. }
        ));

        assert_eq!(store.filesystem_calls, 1, "the second check must not run");
    }

    #[tokio::test]
    async fn decide_emulates_filesystem_when_every_check_passes() {
        let target = filesystem_target_with_two_checks();
        let replies = target
            .checks
            .iter()
            .map(|(path, access)| Ok(FakePolicy::allowed_filesystem_reply(path, *access)))
            .collect();
        let mut store = FakePolicy::with_replies(replies);

        assert!(matches!(
            decide(
                &mut store,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::target(SyscallTarget::Filesystem(target)),
            )
            .await,
            ResponsePlan::EmulateFilesystem { .. }
        ));

        assert_eq!(store.filesystem_calls, 2);
    }
}

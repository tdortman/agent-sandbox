use std::{io, path::Path, time::Duration};

use agent_sandbox_core::{FileAccess, FilesystemCheckReply, ResourceCheckReply, VerdictSource};
use agent_sandbox_syscall_broker::{
    FilesystemTarget, PersistentPolicyClient, ResourceTarget, SeccompNotif, SyscallTarget,
    target_from_notification,
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
        Some(SyscallTarget::None) | None => NormalizedNotification::Continue,
        Some(SyscallTarget::Errno(errno)) => NormalizedNotification::Deny { errno },
        Some(target) => NormalizedNotification::Target { target },
    })
}

/// Semantic actions emitted by policy routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponsePlan {
    Continue,
    DenyErrno {
        errno: i32,
    },
    EmulateResource {
        target: ResourceTarget,
    },
    RevalidateFilesystemThenContinue {
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
        errno: i32,
        path: std::path::PathBuf,
        access: FileAccess,
        source: VerdictSource,
        error: Option<String>,
    },
    FilesystemRpcFailure {
        errno: i32,
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

    pub const fn revalidate_filesystem(target: FilesystemTarget) -> Self {
        Self::RevalidateFilesystemThenContinue { target }
    }
}

pub async fn decide(
    client: &PersistentPolicyClient,
    sandbox_session_id: Option<&str>,
    pid: u32,
    timeout: Duration,
    facts: NormalizedNotification,
) -> ResponsePlan {
    match facts {
        NormalizedNotification::Continue
        | NormalizedNotification::Target {
            target: SyscallTarget::None,
        }
        | NormalizedNotification::ClassificationFailure {
            transient: true, ..
        } => ResponsePlan::Continue,
        NormalizedNotification::Deny { errno }
        | NormalizedNotification::Target {
            target: SyscallTarget::Errno(errno),
        } => ResponsePlan::deny(errno),
        NormalizedNotification::ClassificationFailure {
            transient: false, ..
        } => ResponsePlan::deny(libc::EACCES),
        NormalizedNotification::Target {
            target: SyscallTarget::Network(target),
        } => ResponsePlan::plan_network(
            client
                .check_target(&target, sandbox_session_id.map(str::to_owned), pid, timeout)
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
            ResponsePlan::revalidate_filesystem(target)
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
            errno: libc::EACCES,
            path: reply.path,
            access: reply.access,
            source: reply.source,
            error: reply.error,
        }),
        Err(error) => Some(ResponsePlan::FilesystemRpcFailure {
            errno: libc::EACCES,
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
    use std::{io, path::Path, time::Duration};

    use agent_sandbox_core::{
        FileAccess, FilesystemCheckReply, ResourceAccess, ResourceCheckReply, ResourceKind,
        VerdictSource,
    };
    use agent_sandbox_syscall_broker::{FilesystemTarget, PersistentPolicyClient, ResourceTarget};

    use super::{NormalizedNotification, ResponsePlan, decide, filesystem_plan, resource_plan};

    fn resource_target() -> ResourceTarget {
        ResourceTarget {
            kind: ResourceKind::Device,
            path: "/dev/example".into(),
            access: ResourceAccess::Device(agent_sandbox_core::DeviceAccess::Read),
            raw: Vec::new(),
            open_flags: 0,
            open_mode: 0,
        }
    }

    fn filesystem_target() -> FilesystemTarget {
        FilesystemTarget {
            checks: vec![("/tmp/example".into(), FileAccess::Write)],
        }
    }

    #[tokio::test]
    async fn decision_routes_policy_independent_facts() {
        let client = PersistentPolicyClient::new("/tmp/agent-sandbox-test-policy.sock");
        assert_eq!(
            decide(
                &client,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::continue_(),
            )
            .await,
            ResponsePlan::Continue
        );
        assert_eq!(
            decide(
                &client,
                None,
                0,
                Duration::from_secs(1),
                NormalizedNotification::deny(libc::ENOSYS),
            )
            .await,
            ResponsePlan::DenyErrno {
                errno: libc::ENOSYS
            }
        );
        assert_eq!(
            decide(
                &client,
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
        );
    }

    #[test]
    fn network_verdict_maps_to_plan() {
        assert_eq!(ResponsePlan::plan_network(true), ResponsePlan::Continue);
        assert_eq!(ResponsePlan::plan_network(false), ResponsePlan::DenyErrno {
            errno: libc::EACCES
        });
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
        assert_eq!(
            resource_plan(target.clone(), Ok(allowed)),
            ResponsePlan::EmulateResource {
                target: target.clone()
            }
        );

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
        assert_eq!(
            resource_plan(target.clone(), Ok(denied)),
            ResponsePlan::ResourcePolicyDenied {
                target: target.clone(),
                source: VerdictSource::Policy {
                    comment: Some("blocked".into())
                },
                error: Some("blocked".into()),
            }
        );
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
}

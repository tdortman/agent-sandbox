use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use agent_sandbox_core::{FileAccess, FilesystemCheckReply, ResourceCheckReply, VerdictSource};
use agent_sandbox_syscall_broker::{
    FilesystemTarget, NetworkTarget, ResourceTarget, SeccompNotif, SyscallTarget,
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

/// Policy backend used by the decision layer. Implementations may be RPC or in-memory.
pub trait PolicyAdapter {
    fn network<'a>(
        &'a self,
        target: &'a NetworkTarget,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
    fn resource<'a>(
        &'a self,
        target: &'a ResourceTarget,
    ) -> Pin<Box<dyn Future<Output = io::Result<ResourceCheckReply>> + Send + 'a>>;
    fn filesystem<'a>(
        &'a self,
        path: &'a Path,
        access: FileAccess,
    ) -> Pin<Box<dyn Future<Output = io::Result<FilesystemCheckReply>> + Send + 'a>>;
    fn preserve_diagnostics(&self) -> bool {
        false
    }
}

/// Configuration for the production policy adapter.
#[derive(Debug, Clone, Copy)]
pub struct RpcPolicyAdapter<'a> {
    pub policy_socket: &'a Path,
    pub sandbox_session_id: Option<&'a str>,
    pub pid: u32,
    pub timeout: Duration,
}

impl PolicyAdapter for RpcPolicyAdapter<'_> {
    fn network<'a>(
        &'a self,
        target: &'a NetworkTarget,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(agent_sandbox_syscall_broker::check_target(
            self.policy_socket,
            target,
            self.sandbox_session_id.map(str::to_owned),
            self.pid,
            self.timeout,
        ))
    }
    fn resource<'a>(
        &'a self,
        target: &'a ResourceTarget,
    ) -> Pin<Box<dyn Future<Output = io::Result<ResourceCheckReply>> + Send + 'a>> {
        Box::pin(agent_sandbox_syscall_broker::check_resource(
            self.policy_socket,
            target,
            self.sandbox_session_id.map(str::to_owned),
            self.pid,
            self.timeout,
        ))
    }
    fn filesystem<'a>(
        &'a self,
        path: &'a Path,
        access: FileAccess,
    ) -> Pin<Box<dyn Future<Output = io::Result<FilesystemCheckReply>> + Send + 'a>> {
        Box::pin(agent_sandbox_syscall_broker::check_filesystem(
            self.policy_socket,
            path,
            access,
            self.sandbox_session_id.map(str::to_owned),
            self.pid,
            self.timeout,
        ))
    }
    fn preserve_diagnostics(&self) -> bool {
        true
    }
}

/// Deterministic adapter useful for decision tests.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub struct InMemoryPolicyAdapter {
    pub network_allowed: bool,
    pub resource_allowed: bool,
    pub filesystem_allowed: bool,
}

#[cfg(test)]
impl PolicyAdapter for InMemoryPolicyAdapter {
    fn network<'a>(
        &'a self,
        _target: &'a NetworkTarget,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        let allowed = self.network_allowed;
        Box::pin(async move { allowed })
    }
    fn resource<'a>(
        &'a self,
        target: &'a ResourceTarget,
    ) -> Pin<Box<dyn Future<Output = io::Result<ResourceCheckReply>> + Send + 'a>> {
        let reply = ResourceCheckReply {
            ok: true,
            allowed: self.resource_allowed,
            source: agent_sandbox_core::VerdictSource::User,
            kind: target.kind,
            path: target.path.clone(),
            access: target.access,
            error: None,
        };
        Box::pin(async move { Ok(reply) })
    }
    fn filesystem<'a>(
        &'a self,
        path: &'a Path,
        access: FileAccess,
    ) -> Pin<Box<dyn Future<Output = io::Result<FilesystemCheckReply>> + Send + 'a>> {
        let reply = FilesystemCheckReply {
            ok: true,
            allowed: self.filesystem_allowed,
            source: agent_sandbox_core::VerdictSource::User,
            path: path.to_path_buf(),
            access,
            error: None,
        };
        Box::pin(async move { Ok(reply) })
    }
}

pub async fn decide<A: PolicyAdapter + Sync + ?Sized>(
    adapter: &A,
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
        } => ResponsePlan::plan_network(adapter.network(&target).await),
        NormalizedNotification::Target {
            target: SyscallTarget::Resource(target),
        } => match adapter.resource(&target).await {
            Ok(reply) if reply.allowed => ResponsePlan::emulate_resource(target),
            Ok(reply) if adapter.preserve_diagnostics() => ResponsePlan::ResourcePolicyDenied {
                target,
                source: reply.source,
                error: reply.error,
            },
            Err(error) if adapter.preserve_diagnostics() => ResponsePlan::ResourceRpcFailure {
                target,
                error: error.to_string(),
            },
            Ok(_) | Err(_) => ResponsePlan::deny(libc::EACCES),
        },
        NormalizedNotification::Target {
            target: SyscallTarget::Filesystem(target),
        } => {
            for (path, access) in &target.checks {
                match adapter.filesystem(path, *access).await {
                    Ok(reply) if reply.allowed => {}
                    Ok(reply) if adapter.preserve_diagnostics() => {
                        return ResponsePlan::FilesystemPolicyDenied {
                            errno: libc::EACCES,
                            path: reply.path,
                            access: reply.access,
                            source: reply.source,
                            error: reply.error,
                        };
                    }
                    Err(error) if adapter.preserve_diagnostics() => {
                        return ResponsePlan::FilesystemRpcFailure {
                            errno: libc::EACCES,
                            path: path.clone(),
                            access: *access,
                            error: error.to_string(),
                        };
                    }
                    _ => return ResponsePlan::deny(libc::EACCES),
                }
            }
            ResponsePlan::revalidate_filesystem(target)
        }
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
    use super::{InMemoryPolicyAdapter, NormalizedNotification, ResponsePlan, decide};
    use agent_sandbox_core::{FileAccess, ResourceAccess, ResourceKind};
    use agent_sandbox_syscall_broker::{
        FilesystemTarget, NetworkTarget, ResourceTarget, SyscallTarget,
    };
    use std::io;
    use std::path::PathBuf;

    fn network_target() -> NetworkTarget {
        NetworkTarget {
            host: "example.test".to_owned(),
            connect_host: "example.test".to_owned(),
            port: 443,
            scheme: "https".to_owned(),
        }
    }

    fn resource_target() -> ResourceTarget {
        ResourceTarget {
            kind: ResourceKind::Device,
            path: PathBuf::from("/dev/example"),
            access: ResourceAccess::OpenRead,
            raw: Vec::new(),
            open_flags: 0,
            open_mode: 0,
        }
    }

    fn filesystem_target() -> FilesystemTarget {
        FilesystemTarget {
            checks: vec![(PathBuf::from("/tmp/example"), FileAccess::Write)],
        }
    }

    fn adapter(
        network_allowed: bool,
        resource_allowed: bool,
        filesystem_allowed: bool,
    ) -> InMemoryPolicyAdapter {
        InMemoryPolicyAdapter {
            network_allowed,
            resource_allowed,
            filesystem_allowed,
        }
    }

    #[tokio::test]
    async fn decision_routes_normalized_facts_to_semantic_plans() {
        let network = network_target();
        let resource = resource_target();
        let filesystem = filesystem_target();
        let cases = [
            (
                "continue fact",
                NormalizedNotification::continue_(),
                true,
                true,
                true,
                ResponsePlan::Continue,
            ),
            (
                "errno fact",
                NormalizedNotification::deny(libc::ENOSYS),
                true,
                true,
                true,
                ResponsePlan::DenyErrno {
                    errno: libc::ENOSYS,
                },
            ),
            (
                "network allowed",
                NormalizedNotification::target(SyscallTarget::Network(network.clone())),
                true,
                true,
                true,
                ResponsePlan::Continue,
            ),
            (
                "network denied",
                NormalizedNotification::target(SyscallTarget::Network(network)),
                false,
                true,
                true,
                ResponsePlan::DenyErrno {
                    errno: libc::EACCES,
                },
            ),
            (
                "resource allowed",
                NormalizedNotification::target(SyscallTarget::Resource(resource.clone())),
                true,
                true,
                true,
                ResponsePlan::EmulateResource {
                    target: resource.clone(),
                },
            ),
            (
                "resource denied",
                NormalizedNotification::target(SyscallTarget::Resource(resource)),
                true,
                false,
                true,
                ResponsePlan::DenyErrno {
                    errno: libc::EACCES,
                },
            ),
            (
                "filesystem allowed",
                NormalizedNotification::target(SyscallTarget::Filesystem(filesystem.clone())),
                true,
                true,
                true,
                ResponsePlan::RevalidateFilesystemThenContinue {
                    target: filesystem.clone(),
                },
            ),
            (
                "filesystem denied",
                NormalizedNotification::target(SyscallTarget::Filesystem(filesystem)),
                true,
                true,
                false,
                ResponsePlan::DenyErrno {
                    errno: libc::EACCES,
                },
            ),
        ];

        for (name, facts, network_allowed, resource_allowed, filesystem_allowed, expected) in cases
        {
            let actual = decide(
                &adapter(network_allowed, resource_allowed, filesystem_allowed),
                facts,
            )
            .await;
            assert_eq!(actual, expected, "case {name}");
        }
    }

    #[tokio::test]
    async fn classification_failures_preserve_transient_continuation_boundary() {
        let transient = NormalizedNotification::classification_failure(
            io::Error::from_raw_os_error(libc::ESRCH),
            true,
        );
        let permanent = NormalizedNotification::classification_failure(
            io::Error::from_raw_os_error(libc::EINVAL),
            false,
        );
        let policy = adapter(true, true, true);

        assert_eq!(decide(&policy, transient).await, ResponsePlan::Continue);
        assert_eq!(
            decide(&policy, permanent).await,
            ResponsePlan::DenyErrno {
                errno: libc::EACCES
            }
        );
    }
}

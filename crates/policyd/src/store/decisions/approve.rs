//! Apply pending network or elevation decisions.
use std::path::{Path, PathBuf};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, DbusRule, ElevateReply, FileAccess, FilesystemRule,
    NetworkRuleKey, ResourceAccess, ResourceKind, ResourceRule, RpcReply, ScopeActionReply,
    SudoRule, VerdictSource, host_pattern_matches,
};

use super::super::types::{
    NetworkVerdictKey, Pending, PendingDbus, PendingElevation, PendingFilesystem, PendingNetwork,
    PendingResource, PolicyStore,
};
use super::DecisionAction;
use crate::error::PolicydError;
use crate::wire::{NetworkScopeOp, PendingDecision, ResourceScopeOp, SudoScopeOp};

impl PolicyStore {
    pub async fn approve(&self, decision: PendingDecision) -> RpcReply {
        self.apply_pending_decision(decision, DecisionAction::Approve)
            .await
    }

    pub(crate) async fn apply_pending_decision(
        &self,
        decision: PendingDecision,
        action: DecisionAction,
    ) -> RpcReply {
        let decision = match self.take_pending_decision(decision).await {
            Ok(value) => value,
            Err(err) => return err,
        };
        match decision.pending {
            Pending::Network(net) => {
                self.apply_pending_network_decision(
                    net,
                    decision.wire,
                    decision.scope,
                    decision.target.as_ref(),
                    action,
                )
                .await
            }
            Pending::Elevation(elev) => {
                self.apply_pending_sudo_decision(
                    elev,
                    decision.wire,
                    decision.scope,
                    decision.target.as_ref(),
                    action,
                )
                .await
            }
            Pending::Filesystem(fs) => {
                self.apply_pending_filesystem_decision(
                    fs,
                    decision.wire,
                    decision.scope,
                    decision.target.as_ref(),
                    action,
                )
                .await
            }
            Pending::Resource(res) => {
                self.apply_pending_resource_decision(
                    res,
                    decision.wire,
                    decision.scope,
                    decision.target.as_ref(),
                    action,
                )
                .await
            }
            Pending::Dbus(dbus) => {
                self.apply_pending_dbus_decision(
                    dbus,
                    decision.wire,
                    decision.scope,
                    decision.target.as_ref(),
                    action,
                )
                .await
            }
            Pending::Http(http) => {
                let target = match decision.target {
                    Some(ApprovalTarget::Http { target }) => Some(target),
                    None => None,
                    Some(_) => {
                        return RpcReply::from(crate::error::PolicydError::InvalidDecisionTarget);
                    }
                };
                self.apply_pending_http(
                    http,
                    decision.scope,
                    target,
                    decision.wire,
                    action == DecisionAction::Approve,
                )
                .await
                .map_or_else(RpcReply::from, RpcReply::ScopeAction)
            }
        }
    }

    async fn apply_pending_network_decision(
        &self,
        net: PendingNetwork,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = net.id.clone();
        let resolved = match Self::resolve_pending_network_target(&net, scope, target) {
            Ok(value) => value,
            Err(err) => {
                self.inner
                    .lock()
                    .await
                    .insert_pending(Pending::Network(net));
                return err.into();
            }
        };

        if action == DecisionAction::Approve && scope == ApprovalScope::Once {
            Self::audit(
                action.audit_verb(),
                Some(&resolved.host),
                Some(resolved.port),
                scope.as_str(),
            );
            self.finish_network(
                &pending_id,
                true,
                VerdictSource::Scope(ApprovalScope::Once),
                Some(NetworkVerdictKey {
                    host: resolved.host.clone(),
                    port: resolved.port,
                }),
            )
            .await;
            return RpcReply::ScopeAction(ScopeActionReply::ok_network(
                resolved.host,
                resolved.port,
                scope,
                None,
            ));
        }

        let result = self
            .apply_network_scope(
                NetworkScopeOp {
                    host: resolved.host.clone(),
                    port: resolved.port,
                    scope,
                    wire: Self::scope_wire_for_pending_network(wire, &net),
                },
                action,
            )
            .await;

        if result.scope_succeeded() {
            match action {
                DecisionAction::Approve => {
                    let source = VerdictSource::from(scope);
                    self.finish_network(
                        &pending_id,
                        true,
                        source,
                        Some(NetworkVerdictKey {
                            host: resolved.host.clone(),
                            port: resolved.port,
                        }),
                    )
                    .await;
                }
                DecisionAction::Deny => {
                    self.finish_network(
                        &pending_id,
                        false,
                        VerdictSource::User,
                        Some(NetworkVerdictKey {
                            host: resolved.host.clone(),
                            port: resolved.port,
                        }),
                    )
                    .await;
                }
            }
        } else if action == DecisionAction::Approve {
            self.finish_network(
                &pending_id,
                false,
                VerdictSource::Blocked,
                Some(NetworkVerdictKey {
                    host: resolved.host.clone(),
                    port: resolved.port,
                }),
            )
            .await;
        } else {
            self.inner
                .lock()
                .await
                .insert_pending(Pending::Network(net));
        }
        result
    }

    async fn apply_pending_sudo_decision(
        &self,
        elev: PendingElevation,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = elev.id.clone();
        let argv = match Self::resolve_pending_sudo_target(&elev, scope, target) {
            Ok(value) => value,
            Err(err) => {
                self.inner
                    .lock()
                    .await
                    .insert_pending(Pending::Elevation(elev));
                return err.into();
            }
        };
        let scope_wire = Self::scope_wire_for_pending_elevation(wire, &elev);

        if action == DecisionAction::Deny {
            if scope == ApprovalScope::Once {
                let detail = format!("id={pending_id} argv={argv:?}");
                Self::audit(action.audit_verb(), None, None, &detail);
                self.finish_elevation(&pending_id, ElevateReply::denied())
                    .await;
                return RpcReply::ScopeAction(ScopeActionReply::ok_sudo(argv, scope, None));
            }
            let result = self
                .apply_sudo_scope(
                    SudoScopeOp {
                        argv: argv.clone(),
                        scope,
                        wire: scope_wire,
                    },
                    action,
                )
                .await;
            if result.scope_succeeded() {
                self.finish_elevation(&pending_id, ElevateReply::denied())
                    .await;
            } else {
                self.inner
                    .lock()
                    .await
                    .insert_pending(Pending::Elevation(elev));
            }
            return result;
        }

        let saved_path = if scope == ApprovalScope::Once {
            None
        } else {
            let scope_result = self
                .apply_sudo_scope(
                    SudoScopeOp {
                        argv: argv.clone(),
                        scope,
                        wire: scope_wire.clone(),
                    },
                    action,
                )
                .await;
            if !scope_result.scope_succeeded() {
                self.inner
                    .lock()
                    .await
                    .insert_pending(Pending::Elevation(elev));
                return scope_result;
            }
            scope_result.scope_path()
        };

        let detail = format!("id={pending_id} argv={argv:?}");
        Self::audit(action.audit_verb(), None, None, &detail);
        let elevation = match self
            .exec_elevation(
                &argv,
                elev.cwd.as_deref().or_else(|| scope_wire.paths.cwd()),
                elev.home.as_deref().or_else(|| scope_wire.paths.home()),
            )
            .await
        {
            Ok(reply) => reply,
            Err(err) => {
                self.inner
                    .lock()
                    .await
                    .insert_pending(Pending::Elevation(elev));
                return err.into();
            }
        };
        self.finish_elevation(&pending_id, elevation).await;
        RpcReply::ScopeAction(ScopeActionReply::ok_elevation_approve(
            scope,
            saved_path.map(PathBuf::from),
        ))
    }

    async fn apply_pending_filesystem_decision(
        &self,
        fs: PendingFilesystem,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = fs.id.clone();
        let path = match Self::resolve_pending_filesystem_target(
            &fs,
            scope,
            target,
            wire.paths.project_root().or(fs.project_root.as_deref()),
        ) {
            Ok(value) => value,
            Err(err) => {
                self.inner
                    .lock()
                    .await
                    .insert_pending(Pending::Filesystem(fs));
                return err.into();
            }
        };

        if action == DecisionAction::Approve && scope == ApprovalScope::Once {
            let detail = format!(
                "id={pending_id} path={} access={:?}",
                path.display(),
                fs.access
            );
            Self::audit(action.audit_verb(), None, None, &detail);
            self.finish_filesystem(
                &pending_id,
                path.clone(),
                fs.access,
                true,
                VerdictSource::Scope(ApprovalScope::Once),
            )
            .await;
            return RpcReply::ScopeAction(ScopeActionReply::ok_filesystem(
                path.clone(),
                fs.access,
                scope,
                None,
            ));
        }

        let scope_wire = self
            .filesystem_scope_wire_for_pending(wire, &fs, scope)
            .await;

        if action == DecisionAction::Deny && scope == ApprovalScope::Once {
            let detail = format!("id={pending_id} path={}", path.display());
            Self::audit(action.audit_verb(), None, None, &detail);
            self.finish_filesystem(
                &pending_id,
                path.clone(),
                fs.access,
                false,
                VerdictSource::User,
            )
            .await;
            return RpcReply::ScopeAction(ScopeActionReply::ok_filesystem(
                path.clone(),
                fs.access,
                scope,
                None,
            ));
        }

        let result = self
            .apply_filesystem_scope(
                crate::wire::FilesystemScopeOp {
                    path: path.clone(),
                    access: fs.access,
                    scope,
                    wire: scope_wire,
                },
                action,
            )
            .await;

        if result.scope_succeeded() {
            let source = VerdictSource::from(scope);
            self.finish_filesystem(
                &pending_id,
                path.clone(),
                fs.access,
                action == DecisionAction::Approve,
                source,
            )
            .await;
        } else if action == DecisionAction::Approve {
            self.finish_filesystem(&pending_id, path, fs.access, false, VerdictSource::Blocked)
                .await;
        } else {
            self.inner
                .lock()
                .await
                .insert_pending(Pending::Filesystem(fs));
        }
        result
    }

    async fn filesystem_scope_wire_for_pending(
        &self,
        wire: crate::wire::ScopeWire,
        fs: &PendingFilesystem,
        scope: ApprovalScope,
    ) -> crate::wire::ScopeWire {
        let mut scope_wire = Self::scope_wire_for_pending_filesystem(wire, fs);
        if scope != ApprovalScope::Session {
            return scope_wire;
        }

        let session_ids = self.standalone_session_ids_for_filesystem_pending(fs).await;
        if scope_wire
            .session_id
            .as_ref()
            .is_some_and(|session_id| session_ids.contains(session_id))
        {
            return scope_wire;
        }
        if let Some(session_id) = session_ids.into_iter().min() {
            scope_wire.session_id = Some(session_id);
        }
        scope_wire
    }

    fn resolve_pending_filesystem_target(
        pending: &PendingFilesystem,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        project_root: Option<&Path>,
    ) -> Result<PathBuf, PolicydError> {
        let pending_path = &pending.path;
        let project_root = project_root.or(pending.project_root.as_deref());
        let path = match target {
            None => pending_path.clone(),
            Some(ApprovalTarget::FilesystemPath { path }) => path.clone(),
            Some(_) => return Err(PolicydError::InvalidDecisionTarget),
        };

        // For Once scope, only exact match is allowed.
        if scope == ApprovalScope::Once {
            if path != *pending_path {
                return Err(PolicydError::InvalidDecisionTarget);
            }
            return Ok(path);
        }

        // For broader scopes, accept exact match or ancestor path (with boundary).
        if path == *pending_path {
            return Ok(path);
        }

        if FilesystemRule::new(path.clone(), FileAccess::Read, "")
            .path_matches(pending_path.as_path(), project_root)
        {
            return Ok(path);
        }

        Err(PolicydError::InvalidDecisionTarget)
    }

    async fn apply_pending_dbus_decision(
        &self,
        res: PendingDbus,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        action: DecisionAction,
    ) -> RpcReply {
        let dbus_target = match target {
            None => res.target.clone(),
            Some(ApprovalTarget::Dbus { target }) => {
                if !DbusRule::new(target.clone(), "").matches(&res.target) {
                    self.inner.lock().await.insert_pending(Pending::Dbus(res));
                    return PolicydError::InvalidDecisionTarget.into();
                }
                target.clone()
            }
            Some(_) => {
                self.inner.lock().await.insert_pending(Pending::Dbus(res));
                return PolicydError::InvalidDecisionTarget.into();
            }
        };
        let allowed = action == DecisionAction::Approve;
        let source = if allowed {
            VerdictSource::Scope(scope)
        } else {
            VerdictSource::User
        };
        let path = res.path.clone();
        if scope == ApprovalScope::Once {
            self.finish_resource(
                &res.id,
                ResourceKind::UnixSocket,
                path,
                ResourceAccess::default(),
                allowed,
                source,
            )
            .await;
            return RpcReply::ScopeAction(ScopeActionReply::ok_dbus(dbus_target, scope, None));
        }

        let scope_wire = Self::scope_wire_for_pending_dbus(wire, &res);
        let result = self
            .apply_dbus_scope(dbus_target, scope, scope_wire, action)
            .await;
        if result.scope_succeeded() {
            self.finish_resource(
                &res.id,
                ResourceKind::UnixSocket,
                path,
                ResourceAccess::default(),
                allowed,
                source,
            )
            .await;
        } else {
            self.inner.lock().await.insert_pending(Pending::Dbus(res));
        }
        result
    }

    async fn apply_pending_resource_decision(
        &self,
        res: PendingResource,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = res.id.clone();
        let path = match Self::resolve_pending_resource_target(
            &res,
            scope,
            target,
            wire.paths.project_root().or(res.project_root.as_deref()),
        ) {
            Ok(value) => value,
            Err(err) => {
                self.inner
                    .lock()
                    .await
                    .insert_pending(Pending::Resource(res));
                return err.into();
            }
        };

        if scope == ApprovalScope::Once {
            let allowed = matches!(action, DecisionAction::Approve);
            let source = if allowed {
                VerdictSource::Scope(ApprovalScope::Once)
            } else {
                VerdictSource::User
            };
            let detail = if allowed {
                format!(
                    "id={pending_id} kind={:?} path={} access={:?}",
                    res.kind,
                    path.display(),
                    res.access
                )
            } else {
                format!(
                    "id={pending_id} kind={:?} path={}",
                    res.kind,
                    path.display()
                )
            };
            Self::audit(action.audit_verb(), None, None, &detail);
            self.finish_resource(
                &pending_id,
                res.kind,
                path.clone(),
                res.access,
                allowed,
                source,
            )
            .await;
            return RpcReply::ScopeAction(ScopeActionReply::ok_resource(
                res.kind, path, res.access, scope, None,
            ));
        }

        let scope_wire = self
            .resource_scope_wire_for_pending(wire, &res, scope)
            .await;

        let result = self
            .apply_resource_scope(
                ResourceScopeOp {
                    kind: res.kind,
                    path: path.clone(),
                    access: res.access,
                    scope,
                    wire: scope_wire,
                },
                action,
            )
            .await;

        if result.scope_succeeded() {
            let source = VerdictSource::from(scope);
            self.finish_resource(
                &pending_id,
                res.kind,
                path.clone(),
                res.access,
                action == DecisionAction::Approve,
                source,
            )
            .await;
        } else if action == DecisionAction::Approve {
            self.finish_resource(
                &pending_id,
                res.kind,
                path,
                res.access,
                false,
                VerdictSource::Blocked,
            )
            .await;
        } else {
            self.inner
                .lock()
                .await
                .insert_pending(Pending::Resource(res));
        }
        result
    }

    async fn resource_scope_wire_for_pending(
        &self,
        wire: crate::wire::ScopeWire,
        res: &PendingResource,
        scope: ApprovalScope,
    ) -> crate::wire::ScopeWire {
        let mut scope_wire = Self::scope_wire_for_pending_resource(wire, res);
        if scope != ApprovalScope::Session {
            return scope_wire;
        }

        let session_ids = self.standalone_session_ids_for_resource_pending(res).await;
        if scope_wire
            .session_id
            .as_ref()
            .is_some_and(|session_id| session_ids.contains(session_id))
        {
            return scope_wire;
        }
        if let Some(session_id) = session_ids.into_iter().min() {
            scope_wire.session_id = Some(session_id);
        }
        scope_wire
    }

    fn resolve_pending_resource_target(
        pending: &PendingResource,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        project_root: Option<&Path>,
    ) -> Result<PathBuf, PolicydError> {
        let pending_path = &pending.path;
        let project_root = project_root.or(pending.project_root.as_deref());
        let (kind, path) = match target {
            None => (pending.kind, pending_path.clone()),
            Some(ApprovalTarget::ResourcePath {
                resource_kind,
                path,
            }) => {
                if *resource_kind != pending.kind {
                    return Err(PolicydError::InvalidDecisionTarget);
                }
                (*resource_kind, path.clone())
            }
            Some(_) => return Err(PolicydError::InvalidDecisionTarget),
        };
        let _ = kind;

        // For Once scope, only exact match is allowed.
        if scope == ApprovalScope::Once {
            if path != *pending_path {
                return Err(PolicydError::InvalidDecisionTarget);
            }
            return Ok(path);
        }

        // For broader scopes, accept exact match or ancestor path (with boundary).
        if path == *pending_path {
            return Ok(path);
        }

        if ResourceRule::new(
            pending.kind,
            path.clone(),
            ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
            "",
        )
        .path_matches(pending_path.as_path(), project_root)
        {
            return Ok(path);
        }

        Err(PolicydError::InvalidDecisionTarget)
    }

    fn resolve_pending_network_target(
        pending: &PendingNetwork,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
    ) -> Result<NetworkRuleKey, PolicydError> {
        let pending_host = &pending.host;
        let pending_port = pending.port;
        let host = match target {
            None => pending_host.clone(),
            Some(ApprovalTarget::NetworkHost { host }) => host.clone(),
            Some(_) => {
                return Err(PolicydError::InvalidDecisionTarget);
            }
        };
        let valid_host = host_pattern_matches(&host, pending_host);
        if !valid_host {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        if scope == ApprovalScope::Once && host != *pending_host {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        Ok(NetworkRuleKey::new(host, pending_port))
    }

    fn resolve_pending_sudo_target(
        pending: &PendingElevation,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
    ) -> Result<Vec<String>, PolicydError> {
        let pending_argv = &pending.argv;
        let argv = match target {
            None => pending_argv.clone(),
            Some(ApprovalTarget::SudoCommand { argv }) => argv.clone(),
            Some(_) => {
                return Err(PolicydError::InvalidDecisionTarget);
            }
        };
        let valid_argv = SudoRule::approval_prefixes(pending_argv)
            .into_iter()
            .any(|candidate| candidate == argv);
        if !valid_argv {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        if scope == ApprovalScope::Once && argv != *pending_argv {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        Ok(argv)
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use agent_sandbox_core::{
        ApprovalScope, ApprovalTarget, DbusMessageKind, DbusTarget, FileAccess, NetworkRuleKey,
        PendingSummary, ProcessIds, ResourceAccess, ResourceKind, RpcReply, SandboxPaths,
        load_policy,
    };
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;

    use crate::store::types::{PendingDbus, UiClient, UiSessionContext};
    use crate::store::{
        Pending, PendingElevation, PendingFilesystem, PendingNetwork, PendingResource, PolicyStore,
        PolicydArgs,
    };
    use crate::wire::{PendingDecision, ScopeWire};

    #[test]
    fn network_target_accepts_parent_domain_patterns() {
        let pending = Pending::Network(PendingNetwork {
            id: "p1".into(),
            created_at: 0.0,
            host: "foo.bar.baz.com".into(),
            port: 443,
            scheme: "https".into(),
            url: "https://foo.bar.baz.com".into(),
            aliases: Vec::new(),
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::NetworkHost {
            host: "*.baz.com".into(),
        };
        assert_eq!(
            PolicyStore::resolve_pending_network_target(
                match &pending {
                    Pending::Network(net) => net,
                    _ => panic!("expected Network"),
                },
                ApprovalScope::Project,
                Some(&target),
            )
            .expect("resolve pending network target"),
            NetworkRuleKey::new("*.baz.com", 443)
        );
    }

    #[test]
    fn network_target_accepts_user_defined_glob() {
        let pending = PendingNetwork {
            id: "p1".into(),
            created_at: 0.0,
            host: "api.v1.example.com".into(),
            port: 443,
            scheme: "https".into(),
            url: "https://api.v1.example.com".into(),
            aliases: Vec::new(),
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        };
        let target = ApprovalTarget::NetworkHost {
            host: "api.*.example.com".into(),
        };
        assert_eq!(
            PolicyStore::resolve_pending_network_target(
                &pending,
                ApprovalScope::Project,
                Some(&target),
            )
            .expect("resolve custom network glob"),
            NetworkRuleKey::new("api.*.example.com", 443)
        );
    }
    #[test]
    fn sudo_target_accepts_command_prefixes() {
        let pending = Pending::Elevation(PendingElevation {
            id: "p1".into(),
            created_at: 0.0,
            argv: vec!["foo".into(), "bar".into(), "baz".into()],
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::SudoCommand {
            argv: vec!["foo".into(), "bar".into()],
        };
        assert_eq!(
            PolicyStore::resolve_pending_sudo_target(
                match &pending {
                    Pending::Elevation(elev) => elev,
                    _ => panic!("expected Elevation"),
                },
                ApprovalScope::Session,
                Some(&target),
            )
            .expect("resolve pending sudo target"),
            vec!["foo".to_string(), "bar".to_string()]
        );
    }

    #[test]
    fn filesystem_target_rejects_mismatch() {
        let pending = Pending::Filesystem(PendingFilesystem {
            id: "fs1".into(),
            created_at: 0.0,
            path: "/home/user/projects/foo/src/main.rs".into(),
            access: FileAccess::Read,
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::FilesystemPath {
            path: "/other/path".into(),
        };
        assert!(
            PolicyStore::resolve_pending_filesystem_target(
                match &pending {
                    Pending::Filesystem(fs) => fs,
                    _ => panic!("expected Filesystem"),
                },
                ApprovalScope::Session,
                Some(&target),
                None,
            )
            .is_err(),
            "unrelated path should be rejected"
        );
    }

    #[test]
    fn filesystem_target_accepts_ancestor_path() {
        let pending = Pending::Filesystem(PendingFilesystem {
            id: "fs1".into(),
            created_at: 0.0,
            path: "/home/user/projects/foo/src/main.rs".into(),
            access: FileAccess::Read,
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::FilesystemPath {
            path: "/home/user/projects/foo".into(),
        };
        assert_eq!(
            PolicyStore::resolve_pending_filesystem_target(
                match &pending {
                    Pending::Filesystem(fs) => fs,
                    _ => panic!("expected Filesystem"),
                },
                ApprovalScope::Session,
                Some(&target),
                None,
            )
            .expect("resolve pending filesystem target"),
            PathBuf::from("/home/user/projects/foo")
        );
    }

    #[test]
    fn filesystem_target_exact_once_scope() {
        let pending = Pending::Filesystem(PendingFilesystem {
            id: "fs1".into(),
            created_at: 0.0,
            path: "/home/user/file.txt".into(),
            access: FileAccess::Read,
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        });
        // Once scope: exact match is valid
        assert!(
            PolicyStore::resolve_pending_filesystem_target(
                match &pending {
                    Pending::Filesystem(fs) => fs,
                    _ => panic!("expected Filesystem"),
                },
                ApprovalScope::Once,
                None,
                None,
            )
            .is_ok()
        );

        // Ancestor path with Once scope should be rejected
        let ancestor_target = ApprovalTarget::FilesystemPath {
            path: "/home/user".into(),
        };
        assert!(
            PolicyStore::resolve_pending_filesystem_target(
                match &pending {
                    Pending::Filesystem(fs) => fs,
                    _ => panic!("expected Filesystem"),
                },
                ApprovalScope::Once,
                Some(&ancestor_target),
                None,
            )
            .is_err(),
            "ancestor target should be rejected for Once scope"
        );
    }

    #[test]
    fn filesystem_target_accepts_project_relative_path() {
        let pending = Pending::Filesystem(PendingFilesystem {
            id: "fs1".into(),
            created_at: 0.0,
            path: "/home/user/repo/.gitattributes".into(),
            access: FileAccess::Read,
            cwd: None,
            home: Some("/home/user".into()),
            project_root: Some("/home/user/repo".into()),
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::FilesystemPath {
            path: "./.gitattributes".into(),
        };
        assert_eq!(
            PolicyStore::resolve_pending_filesystem_target(
                match &pending {
                    Pending::Filesystem(fs) => fs,
                    _ => panic!("expected Filesystem"),
                },
                ApprovalScope::Session,
                Some(&target),
                None,
            )
            .expect("project-relative target should resolve"),
            PathBuf::from("./.gitattributes")
        );
    }

    #[test]
    fn resource_target_accepts_project_relative_path() {
        let pending = Pending::Resource(PendingResource {
            id: "rs1".into(),
            created_at: 0.0,
            kind: ResourceKind::UnixSocket,
            path: "/home/user/repo/.sock".into(),
            access: ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
            cwd: None,
            home: Some("/home/user".into()),
            project_root: Some("/home/user/repo".into()),
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::ResourcePath {
            resource_kind: ResourceKind::UnixSocket,
            path: "./.sock".into(),
        };
        assert_eq!(
            PolicyStore::resolve_pending_resource_target(
                match &pending {
                    Pending::Resource(rs) => rs,
                    _ => panic!("expected Resource"),
                },
                ApprovalScope::Session,
                Some(&target),
                None,
            )
            .expect("project-relative resource target should resolve"),
            PathBuf::from("./.sock")
        );
    }

    #[test]
    fn filesystem_target_accepts_project_relative_from_wire_project_root() {
        let pending = Pending::Filesystem(PendingFilesystem {
            id: "fs1".into(),
            created_at: 0.0,
            path: "/home/user/repo/.git/config".into(),
            access: FileAccess::ReadWrite,
            cwd: None,
            home: Some("/home/user".into()),
            project_root: None,
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::FilesystemPath {
            path: "./.git".into(),
        };
        assert_eq!(
            PolicyStore::resolve_pending_filesystem_target(
                match &pending {
                    Pending::Filesystem(fs) => fs,
                    _ => panic!("expected Filesystem"),
                },
                ApprovalScope::Global,
                Some(&target),
                Some(Path::new("/home/user/repo")),
            )
            .expect("wire project_root should validate ./.git against .git/config"),
            PathBuf::from("./.git")
        );
    }

    #[tokio::test]
    async fn global_git_approval_works_when_pending_lacks_project_root() {
        let store = test_store("global-git-wire-root");
        let home = std::env::temp_dir().join(format!(
            "agent-sandbox-home-global-git-wire-{}",
            std::process::id()
        ));
        let project_root = home.join("dotfiles");
        std::fs::create_dir_all(&home).expect("create test home");
        std::fs::create_dir_all(project_root.join(".git")).expect("create git dir");
        let pending = PendingFilesystem {
            id: "fs-git-config-wire".into(),
            created_at: 0.0,
            path: project_root.join(".git/config"),
            access: FileAccess::ReadWrite,
            cwd: Some(project_root.clone()),
            home: Some(home.clone()),
            project_root: None,
            sandbox_session_id: None,
        };
        let pending_id = pending.id.clone();
        store
            .inner
            .lock()
            .await
            .insert_pending(Pending::Filesystem(pending));

        let reply = store
            .approve(PendingDecision {
                pending_id,
                scope: ApprovalScope::Global,
                target: Some(ApprovalTarget::FilesystemPath {
                    path: PathBuf::from("./.git"),
                }),
                wire: ScopeWire {
                    paths: SandboxPaths::new(
                        project_root.clone(),
                        home.clone(),
                        project_root.clone(),
                    ),
                    session_id: None,
                    owner_uid: Some(1000),
                    sandbox_session_id: None,
                    comment: None,
                },
                client_id: 1,
                approver_uid: None,
            })
            .await;
        assert!(
            reply.scope_succeeded(),
            "global ./.git approval should succeed via wire project_root, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn global_filesystem_git_dir_persists_project_relative_path() {
        let store = test_store("global-git-dir");
        let home = std::env::temp_dir().join(format!(
            "agent-sandbox-home-global-git-{}",
            std::process::id()
        ));
        let project_root = home.join("dotfiles");
        std::fs::create_dir_all(&home).expect("create test home");
        std::fs::create_dir_all(project_root.join(".git")).expect("create git dir");
        let pending = PendingFilesystem {
            id: "fs-git-config".into(),
            created_at: 0.0,
            path: project_root.join(".git/config"),
            access: FileAccess::ReadWrite,
            cwd: Some(project_root.clone()),
            home: Some(home.clone()),
            project_root: Some(project_root.clone()),
            sandbox_session_id: None,
        };
        let pending_id = pending.id.clone();
        store
            .inner
            .lock()
            .await
            .insert_pending(Pending::Filesystem(pending));

        let reply = store
            .approve(PendingDecision {
                pending_id,
                scope: ApprovalScope::Global,
                target: Some(ApprovalTarget::FilesystemPath {
                    path: PathBuf::from("./.git"),
                }),
                wire: ScopeWire {
                    paths: SandboxPaths::new(
                        project_root.clone(),
                        home.clone(),
                        project_root.clone(),
                    ),
                    session_id: None,
                    owner_uid: Some(1000),
                    sandbox_session_id: None,
                    comment: None,
                },
                client_id: 1,
                approver_uid: None,
            })
            .await;
        assert!(
            reply.scope_succeeded(),
            "global filesystem approval should succeed, got {reply:?}"
        );

        let policy_path = home.join(".config/agent-sandbox/policy.json");
        let raw = std::fs::read_to_string(&policy_path).expect("read policy.json");
        assert!(
            raw.contains("./.git"),
            "global project-relative paths should persist literally, got: {raw}"
        );
        let policy = agent_sandbox_core::load_policy(&policy_path, Some(home.as_path()), None);
        let found = policy.filesystem.allow.iter().any(|rule| {
            rule.path == Path::new("./.git") && rule.access.covers(FileAccess::ReadWrite)
        });
        assert!(
            found,
            "global ./.git approval should persist as ./.git in {:?}, allow={:?}",
            policy_path, policy.filesystem.allow
        );
    }

    #[tokio::test]
    async fn global_resource_dev_fd_glob_persists_to_policy_json() {
        // A non-once approval for a resource prompt whose target is the glob
        // /dev/fd/* under Global scope must persist an allow rule to the
        // global policy.json rather than silently doing nothing.
        let store = test_store("global-devfd");
        let home = std::env::temp_dir().join(format!(
            "agent-sandbox-home-global-devfd-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&home).expect("create test home");
        let pending = PendingResource {
            id: "rs-devfd".into(),
            created_at: 0.0,
            kind: ResourceKind::UnixSocket,
            path: "/dev/fd/3".into(),
            access: ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
            cwd: None,
            home: Some(home.clone()),
            project_root: None,
            sandbox_session_id: None,
        };
        let pending_id = pending.id.clone();
        store
            .inner
            .lock()
            .await
            .insert_pending(Pending::Resource(pending));

        let reply = store
            .approve(PendingDecision {
                pending_id,
                scope: ApprovalScope::Global,
                target: Some(ApprovalTarget::ResourcePath {
                    resource_kind: ResourceKind::UnixSocket,
                    path: "/dev/fd/*".into(),
                }),
                wire: ScopeWire {
                    paths: SandboxPaths::new("/repo", home.clone(), "/repo"),
                    session_id: None,
                    owner_uid: Some(1000),
                    sandbox_session_id: None,
                    comment: None,
                },
                client_id: 1,
                approver_uid: None,
            })
            .await;
        assert!(
            reply.scope_succeeded(),
            "global resource approval should succeed, got {reply:?}"
        );

        let policy_path = home.join(".config/agent-sandbox/policy.json");
        let policy = load_policy(&policy_path, Some(home.as_path()), None);
        let found = policy.resources.allow.iter().any(|rule| {
            rule.kind == ResourceKind::UnixSocket
                && rule.path == Path::new("/dev/fd/*")
                && rule.access.covers(ResourceAccess::Socket(
                    agent_sandbox_core::SocketAccess::Connect,
                ))
        });
        assert!(
            found,
            "global /dev/fd/* resource rule should be persisted to {:?}, allow={:?}",
            policy_path, policy.resources.allow
        );
    }

    fn test_store(name: &str) -> PolicyStore {
        let dir = std::env::temp_dir().join(format!(
            "agent-sandbox-fs-session-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test store dir");
        PolicyStore::new(PolicydArgs {
            host_socket: dir.join("policy.sock"),
            sandbox_socket: dir.join("sandbox-policy.sock"),
            declarative: dir.join("declarative.json"),
            export_json: dir.join("exported-policy.json"),
            export_nix: None,
            approval_timeout: Duration::from_mins(1),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
            proxy_socket: None,
            proxy_gid: None,
        })
    }

    fn writer() -> Arc<Mutex<tokio::net::unix::OwnedWriteHalf>> {
        Arc::new(Mutex::new(
            UnixStream::pair()
                .expect("unix stream pair")
                .0
                .into_split()
                .1,
        ))
    }

    fn ui_session_context() -> UiSessionContext {
        UiSessionContext {
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            sandbox_session_id: None,
            owner_uid: Some(1000),
            client_id: 1,
        }
    }

    #[tokio::test]
    async fn dbus_once_approval_caches_encoded_pending_path() {
        let store = test_store("dbus-once");
        let target = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        );
        let encoded = serde_json::to_string(&target).expect("encode D-Bus target");
        let path = PathBuf::from(format!("@dbus:{encoded}"));
        let pending_id = "dbus:once".to_owned();
        {
            let mut inner = store.inner.lock().await;
            inner.insert_pending(Pending::Dbus(PendingDbus {
                id: pending_id.clone(),
                created_at: 0.0,
                target: target.clone(),
                path: path.clone(),
                cwd: Some("/repo".into()),
                home: Some("/home/user".into()),
                project_root: Some("/repo".into()),
                sandbox_session_id: None,
            }));
        }

        let ctx = agent_sandbox_core::ResolvedRequestContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::from_options(Some(123), Some(1000)),
            sandbox_session_id: None,
        };
        add_ui_sessions(&store).await;
        let reply = store
            .approve(PendingDecision {
                pending_id,
                scope: ApprovalScope::Once,
                target: Some(ApprovalTarget::Dbus {
                    target: target.clone(),
                }),
                wire: ScopeWire::from_resolved(&ctx, None),
                client_id: 1,
                approver_uid: Some(1000),
            })
            .await;

        assert!(matches!(
            reply,
            RpcReply::ScopeAction(agent_sandbox_core::ScopeActionReply::Dbus(_))
        ));
        let inner = store.inner.lock().await;
        assert!(inner.resource_verdict_cache.contains_key(
            &crate::store::types::ResourceVerdictKey {
                kind: ResourceKind::UnixSocket,
                path: path.clone(),
                access: ResourceAccess::default(),
            }
        ));
        assert!(!inner.resource_verdict_cache.contains_key(
            &crate::store::types::ResourceVerdictKey {
                kind: ResourceKind::UnixSocket,
                path: PathBuf::from("@dbus"),
                access: ResourceAccess::default(),
            }
        ));
        drop(inner);
    }

    #[tokio::test]
    async fn dbus_global_approval_with_comment_persists_edited_target() {
        let store = test_store("dbus-global-comment");
        let home = std::env::temp_dir().join(format!(
            "agent-sandbox-home-dbus-comment-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&home).expect("create test home");
        let requested = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "",
            Vec::new(),
        );
        let edited = DbusTarget {
            destination: "org.example.Service".into(),
            object_path: "*".into(),
            interface: "*".into(),
            member: "*".into(),
            ..requested.clone()
        };
        let pending_id = "dbus-global-comment".to_owned();
        {
            let mut inner = store.inner.lock().await;
            inner.insert_pending(Pending::Dbus(PendingDbus {
                id: pending_id.clone(),
                created_at: 0.0,
                target: requested.clone(),
                path: PathBuf::from("@dbus:placeholder"),
                cwd: Some("/repo".into()),
                home: Some(home.clone()),
                project_root: None,
                sandbox_session_id: None,
            }));
        }

        add_ui_sessions(&store).await;

        let reply = store
            .approve(PendingDecision {
                pending_id,
                scope: ApprovalScope::Global,
                target: Some(ApprovalTarget::Dbus {
                    target: edited.clone(),
                }),
                wire: ScopeWire {
                    paths: SandboxPaths::new("/repo", home.clone(), "/repo"),
                    session_id: None,
                    owner_uid: Some(1000),
                    sandbox_session_id: None,
                    comment: Some("allow introspect".into()),
                },
                client_id: 1,
                approver_uid: Some(1000),
            })
            .await;

        assert!(
            reply.scope_succeeded(),
            "global D-Bus wildcard approval should succeed, got {reply:?}"
        );

        let policy_path = home.join(".config/agent-sandbox/policy.json");
        let policy = load_policy(&policy_path, Some(&home), None);
        let found = policy.dbus.allow.iter().find(|rule| {
            rule.target.destination == "org.example.Service" && rule.target.object_path == "*"
        });
        let found = found.expect("wildcard D-Bus rule persisted");
        assert_eq!(
            found.comment.as_deref(),
            Some("allow introspect"),
            "persisted rule should carry the user-supplied comment"
        );
    }

    async fn add_ui_sessions(store: &PolicyStore) {
        let mut inner = store.inner.lock().await;
        inner.ui_clients.insert(
            1,
            UiClient {
                session_id: "ui-session".into(),
                writer: writer(),
            },
        );
        inner
            .ui_context_by_session
            .insert("ui-session".into(), ui_session_context());
    }

    fn pending_filesystem() -> PendingFilesystem {
        PendingFilesystem {
            id: "fs1".into(),
            created_at: 0.0,
            path: "/home/user/projects/foo/src/main.rs".into(),
            access: FileAccess::Read,
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            sandbox_session_id: None,
        }
    }

    fn scope_wire(session_id: &str) -> ScopeWire {
        ScopeWire {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            session_id: Some(session_id.into()),
            owner_uid: Some(1000),
            sandbox_session_id: None,
            comment: None,
        }
    }

    async fn approve_filesystem_session(
        store: &PolicyStore,
        pending: PendingFilesystem,
        submitting_session_id: &str,
    ) {
        let pending_id = pending.id.clone();
        store
            .inner
            .lock()
            .await
            .insert_pending(Pending::Filesystem(pending));
        let reply = store
            .approve(PendingDecision {
                pending_id,
                scope: ApprovalScope::Session,
                target: Some(ApprovalTarget::FilesystemPath {
                    path: "/home/user/projects/foo".into(),
                }),
                wire: scope_wire(submitting_session_id),
                client_id: 1,
                approver_uid: None,
            })
            .await;
        assert!(reply.scope_succeeded());
    }

    fn merge_context(pid: Option<u32>) -> agent_sandbox_core::ResolvedRequestContext {
        agent_sandbox_core::ResolvedRequestContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::from_options(pid, None),
            sandbox_session_id: None,
        }
    }

    #[tokio::test]
    async fn filesystem_session_approval_binds_to_submitting_session() {
        let store = test_store("ui-session");
        add_ui_sessions(&store).await;
        approve_filesystem_session(&store, pending_filesystem(), "ui-session").await;

        let has_allow = {
            let inner = store.inner.lock().await;
            inner.session_filesystem_allow.contains_key("ui-session")
        };
        assert!(has_allow);

        assert!(
            store
                .session_filesystem_allowed(
                    Path::new("/home/user/projects/foo/src/lib.rs"),
                    FileAccess::Read,
                    &merge_context(None),
                )
                .await
        );
    }

    #[tokio::test]
    async fn filesystem_session_approval_keeps_standalone_session() {
        let store = test_store("standalone");
        add_ui_sessions(&store).await;
        approve_filesystem_session(&store, pending_filesystem(), "ui-session").await;

        let has_allow = {
            let inner = store.inner.lock().await;
            inner.session_filesystem_allow.contains_key("ui-session")
        };
        assert!(has_allow);

        assert!(
            store
                .session_filesystem_allowed(
                    Path::new("/home/user/projects/foo/src/lib.rs"),
                    FileAccess::Read,
                    &merge_context(None),
                )
                .await
        );
    }

    #[tokio::test]
    async fn sandbox_session_pending_rejects_foreign_host_uid() {
        let store = test_store("sandbox-session-direct-approval");
        store.sandbox_sessions.write().unwrap().insert(
            "sandbox-a".into(),
            crate::store::types::SandboxSessionRegistration {
                root_pid: 42,
                owner_uid: 1000,
                project_root: "/repo".into(),
            },
        );
        let mut pending = pending_filesystem();
        pending.sandbox_session_id = Some("sandbox-a".into());
        let pending_id = pending.id.clone();
        store
            .inner
            .lock()
            .await
            .insert_pending(Pending::Filesystem(pending));

        let reply = store
            .approve(PendingDecision {
                pending_id: pending_id.clone(),
                scope: ApprovalScope::Once,
                target: None,
                wire: ScopeWire {
                    paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                    session_id: None,
                    owner_uid: Some(1001),
                    sandbox_session_id: Some("sandbox-a".into()),
                    comment: None,
                },
                client_id: 99,
                approver_uid: Some(1001),
            })
            .await;

        assert!(
            matches!(&reply, RpcReply::Error(e) if e.error == "approval not authorized for this connection"),
            "foreign uid host approval must be rejected, got: {reply:?}"
        );
        let summaries = store.pending_summaries().await;
        assert_eq!(summaries.len(), 1);
        assert!(
            matches!(&summaries[0], PendingSummary::Filesystem { id, .. } if id == &pending_id),
            "rejected approval must leave pending request intact"
        );
    }

    #[tokio::test]
    async fn cross_connection_approve_rejects_foreign_sandbox_ui() {
        let store = test_store("cross-connection-approve");
        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(
                1,
                UiClient {
                    session_id: "ui-b".into(),
                    writer: writer(),
                },
            );
            inner.ui_context_by_session.insert(
                "ui-b".into(),
                UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: Some("sandbox-b".into()),
                    owner_uid: Some(1000),
                    client_id: 1,
                },
            );
        }

        let mut pending = pending_filesystem();
        pending.sandbox_session_id = Some("sandbox-a".into());
        let pending_id = pending.id.clone();
        store
            .inner
            .lock()
            .await
            .insert_pending(Pending::Filesystem(pending));

        let reply = store
            .approve(PendingDecision {
                pending_id: pending_id.clone(),
                scope: ApprovalScope::Once,
                target: None,
                wire: scope_wire("ui-b"),
                client_id: 1,
                approver_uid: None,
            })
            .await;

        assert!(
            matches!(&reply, RpcReply::Error(e) if e.error == "approval not authorized for this connection"),
            "cross-sandbox Approve must be rejected, got: {reply:?}"
        );
        let summaries = store.pending_summaries().await;
        assert_eq!(summaries.len(), 1);
        assert!(
            matches!(&summaries[0], PendingSummary::Filesystem { id, .. } if id == &pending_id),
            "rejected approval must leave pending request intact"
        );
    }

    #[tokio::test]
    async fn sandbox_session_pending_allows_matching_uifd_approval() {
        let store = test_store("sandbox-session-uifd-approval");
        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(
                1,
                UiClient {
                    session_id: "ui-a".into(),
                    writer: writer(),
                },
            );
            inner.ui_context_by_session.insert(
                "ui-a".into(),
                UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: Some("sandbox-a".into()),
                    owner_uid: Some(1000),
                    client_id: 1,
                },
            );
        }

        let mut pending = pending_filesystem();
        pending.sandbox_session_id = Some("sandbox-a".into());
        let pending_id = pending.id.clone();
        store
            .inner
            .lock()
            .await
            .insert_pending(Pending::Filesystem(pending));

        let reply = store
            .approve(PendingDecision {
                pending_id,
                scope: ApprovalScope::Once,
                target: None,
                wire: scope_wire("ui-a"),
                client_id: 1,
                approver_uid: None,
            })
            .await;

        assert!(
            reply.scope_succeeded(),
            "matching UiFd approval failed: {reply:?}"
        );
    }

    #[tokio::test]
    async fn sandbox_session_pending_allows_host_owner_cli_approval() {
        let store = test_store("sandbox-session-host-cli-approval");
        store.sandbox_sessions.write().unwrap().insert(
            "sandbox-a".into(),
            crate::store::types::SandboxSessionRegistration {
                root_pid: 42,
                owner_uid: 1000,
                project_root: "/repo".into(),
            },
        );
        let mut pending = pending_filesystem();
        pending.sandbox_session_id = Some("sandbox-a".into());
        let pending_id = pending.id.clone();
        store
            .inner
            .lock()
            .await
            .insert_pending(Pending::Filesystem(pending));

        let reply = store
            .approve(PendingDecision {
                pending_id,
                scope: ApprovalScope::Once,
                target: None,
                wire: ScopeWire {
                    paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                    session_id: None,
                    owner_uid: Some(1000),
                    sandbox_session_id: Some("sandbox-a".into()),
                    comment: None,
                },
                client_id: 99,
                approver_uid: Some(1000),
            })
            .await;

        assert!(
            reply.scope_succeeded(),
            "host owner CLI approval failed: {reply:?}"
        );
    }

    #[tokio::test]
    async fn session_network_rules_do_not_cross_sandbox_sessions_in_same_project() {
        let store = test_store("sandbox-session-isolation");
        {
            let mut inner = store.inner.lock().await;
            for (client_id, ui_session_id, sandbox_session_id) in
                [(10_u64, "ui-a", "sandbox-a"), (11_u64, "ui-b", "sandbox-b")]
            {
                inner.ui_clients.insert(
                    client_id,
                    UiClient {
                        session_id: ui_session_id.into(),
                        writer: writer(),
                    },
                );
                inner.ui_context_by_session.insert(
                    ui_session_id.into(),
                    UiSessionContext {
                        cwd: Some("/repo".into()),
                        home: Some("/home/user".into()),
                        project_root: Some("/repo".into()),
                        sandbox_session_id: Some(sandbox_session_id.into()),
                        owner_uid: Some(1000),
                        client_id,
                    },
                );
            }
            inner
                .session_allow
                .entry("ui-a".into())
                .or_default()
                .insert(NetworkRuleKey::new("api.example.com", 443));
        }

        assert!(
            store
                .session_allowed(
                    "api.example.com",
                    443,
                    &agent_sandbox_core::ResolvedRequestContext {
                        paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                        ids: ProcessIds::default(),
                        sandbox_session_id: Some("sandbox-a".into()),
                    },
                )
                .await
        );
        assert!(
            !store
                .session_allowed(
                    "api.example.com",
                    443,
                    &agent_sandbox_core::ResolvedRequestContext {
                        paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                        ids: ProcessIds::default(),
                        sandbox_session_id: Some("sandbox-b".into()),
                    },
                )
                .await
        );
    }
}

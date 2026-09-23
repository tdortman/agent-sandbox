//! Route incoming RPC requests to store methods.

mod auth;

pub use auth::SocketRole;

mod check;
mod context;
mod handlers;
use std::sync::Arc;

use agent_sandbox_core::{RpcReply, RpcRequest};

use crate::{error::PolicydError, server::peer::ClientPeer, store::PolicyStore};

pub async fn dispatch(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    role: SocketRole,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    auth::ensure_allowed(role, &req)?;

    if matches!(
        &req,
        RpcRequest::RegisterNetworkFlow { .. }
            | RpcRequest::FilesystemSnapshot { .. }
            | RpcRequest::BindNetworkRevocation { .. }
            | RpcRequest::ObserveNetworkGrants { .. }
            | RpcRequest::PublishNetworkGrants
    ) && peer.uid != 0
    {
        return Err(PolicydError::UnauthorizedRequest);
    }

    handlers::handle(store, client, peer, role, req).await
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use agent_sandbox_core::{
        FileAccess, FlowContext, FlowProtocol, FlowRegistration, NetworkFlowKey,
        NormalizedPolicyHost, ProcessIdentity, RequestContext, RpcReply, RpcRequest,
        SocketIdentity, SocketInode,
    };
    use tokio::{net::UnixStream, sync::Mutex};

    use super::{SocketRole, dispatch};
    use crate::{error::PolicydError, server::peer::ClientPeer, store::PolicyStore};

    fn test_store(dir: &tempfile::TempDir) -> Arc<PolicyStore> {
        Arc::new(PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("policy.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            false,
        )))
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

    fn test_registration() -> FlowRegistration {
        FlowRegistration::new(
            NetworkFlowKey::try_new(
                FlowProtocol::Tcp,
                "127.0.0.1".parse().expect("valid test source address"),
                12345,
                "192.0.2.1".parse().expect("valid test destination address"),
                443,
            )
            .expect("test flow ports are non-zero"),
            SocketIdentity::new(
                ProcessIdentity::new(1, 0, 1).expect("test process identity is non-zero"),
                SocketInode::new(1).expect("test socket inode is non-zero"),
            ),
            NormalizedPolicyHost::parse("example.com").expect("valid test policy host"),
            FlowContext::default(),
        )
    }

    #[tokio::test]
    async fn filesystem_snapshots_require_root_and_refresh_trusted_context() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(&dir);
        let client = PolicyStore::new_client_handle(writer());
        let home_policy = dir.path().join(".config/agent-sandbox/policy.json");
        std::fs::create_dir_all(home_policy.parent().expect("parent")).expect("policy directory");
        let ctx = RequestContext {
            home: Some(dir.path().to_path_buf()),
            ..RequestContext::default()
        };
        for role in [
            SocketRole::Host,
            SocketRole::Sandbox,
            SocketRole::Proxy,
            SocketRole::UiFd,
        ] {
            for uid in [0, 1000] {
                let result = dispatch(
                    &store,
                    &client,
                    ClientPeer {
                        pid: std::process::id(),
                        uid,
                        gid: 0,
                    },
                    role,
                    RpcRequest::FilesystemSnapshot { ctx: ctx.clone() },
                )
                .await;
                if uid == 0 && matches!(role, SocketRole::Host | SocketRole::Sandbox) {
                    assert!(matches!(result, Ok(RpcReply::FilesystemSnapshot { .. })));
                } else {
                    assert!(matches!(
                        result,
                        Err(PolicydError::UnauthorizedRequest
                            | PolicydError::UnauthorizedUiFdRequest)
                    ));
                }
            }
        }
        let request_path = dir.path().join("granted");
        for section in ["allow", "deny"] {
            let policy = serde_json::json!({"filesystem": {section: [{"path": "~/granted", "access": "read"}]}});
            let replacement = home_policy.with_extension("new");
            std::fs::write(&replacement, policy.to_string()).expect("replacement policy");
            std::fs::rename(replacement, &home_policy).expect("atomic replace");
            let reply = dispatch(
                &store,
                &client,
                ClientPeer {
                    pid: std::process::id(),
                    uid: 0,
                    gid: 0,
                },
                SocketRole::Sandbox,
                RpcRequest::FilesystemSnapshot { ctx: ctx.clone() },
            )
            .await
            .expect("snapshot");
            let reply = serde_json::from_slice::<RpcReply>(
                &serde_json::to_vec(&reply).expect("encode snapshot reply"),
            )
            .expect("decode snapshot reply");
            let RpcReply::FilesystemSnapshot {
                filesystem,
                denied_inodes,
            } = reply
            else {
                panic!("unexpected reply")
            };
            // Hard links to the implicitly denied policy file must stay on the
            // monitor's policyd check path.
            assert!(denied_inodes.contains(
                &agent_sandbox_core::InodeIdentity::from_path(&home_policy).expect("policy inode")
            ));
            assert_eq!(
                filesystem.allow.iter().any(|rule| rule.matches(
                    &request_path,
                    FileAccess::Read,
                    None
                )),
                section == "allow"
            );
            assert_eq!(
                filesystem.deny.iter().any(|rule| rule.matches(
                    &request_path,
                    FileAccess::Read,
                    None
                )),
                section == "deny"
            );
        }
    }

    #[tokio::test]
    async fn network_publication_requires_root_host_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(&dir);
        let client = PolicyStore::new_client_handle(writer());
        for role in [
            SocketRole::Host,
            SocketRole::Sandbox,
            SocketRole::Proxy,
            SocketRole::UiFd,
        ] {
            for uid in [0, 1000] {
                for request in [
                    RpcRequest::BindNetworkRevocation {
                        path: dir.path().join("missing-map"),
                    },
                    RpcRequest::ObserveNetworkGrants {
                        program: dir.path().join("program"),
                        pins: dir.path().join("pins"),
                        pid: std::process::id(),
                        cgroup: 1,
                        endpoints: vec![],
                        dns: dir.path().join("dns"),
                    },
                    RpcRequest::PublishNetworkGrants,
                ] {
                    let result = dispatch(
                        &store,
                        &client,
                        ClientPeer {
                            pid: std::process::id(),
                            uid,
                            gid: 0,
                        },
                        role,
                        request,
                    )
                    .await;
                    if role == SocketRole::Host && uid == 0 {
                        assert!(matches!(result, Err(PolicydError::Io(_))));
                    } else {
                        assert!(matches!(
                            result,
                            Err(PolicydError::UnauthorizedRequest
                                | PolicydError::UnauthorizedUiFdRequest)
                        ));
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn sandbox_dispatch_records_owner_for_later_ui_registration() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let file = dir.path().join("file.txt");
        std::fs::write(&file, "contents").expect("write test file");
        let store = test_store(&dir);
        let client = PolicyStore::new_client_handle(writer());

        dispatch(
            &store,
            &client,
            ClientPeer {
                pid: std::process::id(),
                uid: 1000,
                gid: 0,
            },
            SocketRole::Sandbox,
            RpcRequest::CheckFilesystem {
                path: file,
                access: FileAccess::Read,
                ctx: RequestContext {
                    sandbox_session_id: Some("sandbox-a".into()),
                    ..RequestContext::default()
                },
            },
        )
        .await
        .expect("sandbox request dispatches");

        let result = dispatch(
            &store,
            &client,
            ClientPeer {
                pid: std::process::id(),
                uid: 2000,
                gid: 0,
            },
            SocketRole::Host,
            RpcRequest::RegisterUi {
                ui_client: Some("standalone".into()),
                ctx: RequestContext {
                    uid: Some(1000),
                    sandbox_session_id: Some("sandbox-a".into()),
                    ..RequestContext::default()
                },
            },
        )
        .await;

        assert!(
            matches!(result, Err(PolicydError::UnauthorizedUiRegistration)),
            "dispatch must reject cross-uid UI registration after planning sandbox ownership, \
             got: {result:?}"
        );
    }

    #[tokio::test]
    async fn sandbox_dispatch_rejects_unprivileged_network_flow_registration() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let store = test_store(&dir);
        let client = PolicyStore::new_client_handle(writer());

        let result = dispatch(
            &store,
            &client,
            ClientPeer {
                pid: std::process::id(),
                uid: 1000,
                gid: 0,
            },
            SocketRole::Sandbox,
            RpcRequest::RegisterNetworkFlow {
                registration: test_registration(),
                owner_fd_hint: None,
            },
        )
        .await;

        assert!(
            matches!(result, Err(PolicydError::UnauthorizedRequest)),
            "sandbox socket must reject unprivileged flow registration, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn host_dispatch_registers_sandbox_package() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let store = test_store(&dir);
        let client = PolicyStore::new_client_handle(writer());

        // The launcher binding check reads /proc/<peer.pid>/stat, so the
        // test peer must be a real child of the launcher pid.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a child of the test process");

        let launcher_pid = std::process::id();
        let peer_pid = child.id();

        let result = dispatch(
            &store,
            &client,
            ClientPeer {
                pid: peer_pid,
                uid: 1000,
                gid: 0,
            },
            SocketRole::Host,
            RpcRequest::RegisterSandbox {
                session_id: "sandbox-a".into(),
                package: "omp".into(),
                launcher_pid,
            },
        )
        .await;

        assert!(
            matches!(result, Ok(RpcReply::Simple(_))),
            "host dispatch must accept RegisterSandbox, got: {result:?}"
        );

        let sessions = store
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let reg = sessions
            .get("sandbox-a")
            .expect("RegisterSandbox must store the registration");

        assert_eq!(reg.package.as_deref(), Some("omp"));
        assert_eq!(reg.owner_uid, 1000);
        assert_eq!(reg.launcher_pid, launcher_pid);
        drop(sessions);
        child.kill().expect("kill child");
        let _ = child.wait();
    }
}

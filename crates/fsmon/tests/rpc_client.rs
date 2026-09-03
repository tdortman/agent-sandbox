//! Fail-closed contract for the filesystem monitor starter.
//!
//! `start_monitor` must reject a policy socket whose listener runs as our own
//! uid, so a sandbox-resident impostor can never answer monitor requests.
use std::path::PathBuf;

use agent_sandbox_core::{FileAccess, FilesystemRule, RequestContext, RpcClientError};
use agent_sandbox_fsmon::start_monitor;
use tokio::net::UnixListener;

#[tokio::test]
async fn start_monitor_rejects_same_uid_listener() {
    let socket_path = std::env::temp_dir().join(format!(
        "agent-sandbox-fsmon-start-{}.sock",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind test socket");

    let server = tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let ctx = RequestContext {
        pid: Some(std::process::id()),
        ..RequestContext::default()
    };

    let rules = vec![FilesystemRule {
        path: PathBuf::from("/workspace"),
        access: FileAccess::Write,
        comment: None,
    }];

    let err = start_monitor(&socket_path, ctx, rules)
        .await
        .expect_err("same-uid listener must be rejected");

    assert!(matches!(err, RpcClientError::UntrustedPeer));
    server.await.expect("server task");
    std::fs::remove_file(socket_path).expect("remove test socket");
}

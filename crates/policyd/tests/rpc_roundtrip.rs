use std::{path::Path, sync::Arc, time::Duration};

use agent_sandbox_core::RpcReply;
use agent_sandbox_policyd::{PolicyServer, PolicyStore, PolicydArgs};
use tempfile::tempdir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

fn test_args(root: &Path) -> PolicydArgs {
    PolicydArgs {
        host_socket: root.join("host.sock"),
        sandbox_socket: root.join("sandbox.sock"),
        proxy_socket: None,
        proxy_gid: None,
        declarative: root.join("declarative.json"),
        export_json: root.join("export.json"),
        export_nix: None,
        approval_timeout: Duration::from_secs(1),
        interactive_approval: false,
        ui_spawn_cmd: None,
        fs_monitor_cmd: None,
        syscall_broker_cmd: None,
    }
}

async fn connect_when_ready(path: &Path) -> UnixStream {
    for _ in 0..100 {
        match UnixStream::connect(path).await {
            Ok(stream) => return stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
    panic!("timed out waiting for {}", path.display());
}

async fn rpc(stream: UnixStream, request: &str) -> RpcReply {
    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    writer.write_all(b"\n").await.expect("write newline");
    writer.flush().await.expect("flush request");

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read reply");
    serde_json::from_str(line.trim()).expect("valid RPC reply")
}

#[tokio::test]
async fn sandbox_filesystem_rpc_applies_allow_and_deny_policy() {
    let root = tempdir().expect("temporary directory");
    let args = test_args(root.path());
    std::fs::write(
        &args.declarative,
        r#"{
            "filesystem": {
                "allow": [{"path": "/workspace", "access": "write"}],
                "deny": [{"path": "/workspace/secret", "access": "write"}]
            }
        }"#,
    )
    .expect("declarative policy");
    let sandbox_socket = args.sandbox_socket.clone();
    let server = tokio::spawn(PolicyServer::new(Arc::new(PolicyStore::new(args))).run());

    let allowed = rpc(
        connect_when_ready(&sandbox_socket).await,
        r#"{"op":"check_filesystem","path":"/workspace/file","access":"write","ctx":{}}"#,
    )
    .await;
    match allowed {
        RpcReply::FilesystemCheck(reply) => {
            assert!(reply.ok);
            assert!(reply.allowed);
            assert_eq!(reply.path, Path::new("/workspace/file"));
        }
        other => panic!("allowed filesystem check returned unexpected reply: {other:?}"),
    }

    let denied = rpc(
        connect_when_ready(&sandbox_socket).await,
        r#"{"op":"check_filesystem","path":"/workspace/secret","access":"write","ctx":{}}"#,
    )
    .await;
    match denied {
        RpcReply::FilesystemCheck(reply) => {
            assert!(reply.ok);
            assert!(!reply.allowed);
            assert_eq!(reply.path, Path::new("/workspace/secret"));
        }
        other => panic!("denied filesystem check returned unexpected reply: {other:?}"),
    }

    server.abort();
}

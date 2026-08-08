use agent_sandbox_core::{
    FileAccess, FilesystemMonitorReply, FilesystemRule, RequestContext, RpcReply,
};

use agent_sandbox_fsmon::start_monitor;
use std::path::PathBuf;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
};

#[tokio::test]
async fn start_monitor_round_trips_static_allow_rules_over_unix_socket() {
    let socket_path = std::env::temp_dir().join(format!(
        "agent-sandbox-fsmon-start-{}.sock",
        std::process::id()
    ));

    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind test socket");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept client");
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let mut request = String::new();

        reader.read_line(&mut request).await.expect("read request");

        let request: serde_json::Value =
            serde_json::from_str(request.trim()).expect("valid request JSON");

        assert_eq!(request["op"], "start_filesystem_monitor");
        assert_eq!(request["ctx"]["pid"], std::process::id());
        assert_eq!(request["static_allow"][0]["path"], "/workspace");
        assert_eq!(request["static_allow"][0]["access"], "write");

        let reply = RpcReply::FilesystemMonitor(FilesystemMonitorReply::active());

        let reply = serde_json::to_string(&reply).expect("serialize reply") + "\n";

        write
            .write_all(reply.as_bytes())
            .await
            .expect("write reply");

        write.flush().await.expect("flush reply");
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

    let reply = start_monitor(&socket_path, ctx, rules)
        .await
        .expect("start monitor RPC");

    assert!(reply.ok);
    assert!(reply.active);
    server.await.expect("server task");
    std::fs::remove_file(socket_path).expect("remove test socket");
}

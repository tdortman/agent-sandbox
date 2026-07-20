use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;

use agent_sandbox_core::{
    FileAccess, FilesystemMonitorReply, FilesystemRule, RequestContext, RpcReply,
};
use agent_sandbox_fsmon::rpc_client::start_monitor;

#[test]
fn start_monitor_round_trips_static_allow_rules_over_unix_socket() {
    let socket_path = std::env::temp_dir().join(format!(
        "agent-sandbox-fsmon-start-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind test socket");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        let mut request = String::new();
        BufReader::new(stream.try_clone().expect("clone stream"))
            .read_line(&mut request)
            .expect("read request");
        let request: serde_json::Value =
            serde_json::from_str(request.trim()).expect("valid request JSON");
        assert_eq!(request["op"], "start_filesystem_monitor");
        assert_eq!(request["ctx"]["pid"], std::process::id());
        assert_eq!(request["static_allow"][0]["path"], "/workspace");
        assert_eq!(request["static_allow"][0]["access"], "write");

        let reply = RpcReply::FilesystemMonitor(FilesystemMonitorReply::active());
        writeln!(
            stream,
            "{}",
            serde_json::to_string(&reply).expect("serialize reply")
        )
        .expect("write reply");
        stream.flush().expect("flush reply");
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
    let reply = start_monitor(&socket_path, ctx, rules).expect("start monitor RPC");
    assert!(reply.ok);
    assert!(reply.active);

    server.join().expect("server thread");
    std::fs::remove_file(socket_path).expect("remove test socket");
}

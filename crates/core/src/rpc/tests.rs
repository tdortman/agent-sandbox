use super::{
    CheckReply, ElevateReply, FilesystemCheckReply, FilesystemMonitorReply, RegisterUiReply,
    RpcMessage, RpcReply, RpcRequest, StatusReply, UiPush,
};
use crate::policy::FileAccess;
use std::path::Path;

#[test]
fn check_request_deserializes() {
    let req: RpcRequest = serde_json::from_str(
        r#"{"op":"check","host":"example.com","port":443,"scheme":"https","cwd":"/tmp"}"#,
    )
    .expect("parse request json");
    assert!(matches!(req, RpcRequest::Check { .. }));
}

#[test]
fn register_ui_reply_serializes() {
    let line = RpcReply::RegisterUi(RegisterUiReply {
        ok: true,
        role: "ui".into(),
        session_id: "abc".into(),
    })
    .to_string();
    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("deserialize rpc reply");
    assert_eq!(v["ok"], true);
    assert_eq!(v["role"], "ui");
    assert_eq!(v["session_id"], "abc");
}

#[test]
fn ui_push_network_request() {
    let line = RpcMessage::UiPush(UiPush::NetworkRequest {
        id: "n1".into(),
        host: Some("host".into()),
        port: Some(443),
        scheme: None,
        url: None,
        cwd: None,
        home: None,
        project_root: None,
    })
    .to_string();
    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("deserialize rpc reply");
    assert_eq!(v["type"], "network_request");
    assert_eq!(v["id"], "n1");
}

#[test]
fn check_reply_roundtrip() {
    let reply = CheckReply::blocked("timeout");
    let json = serde_json::to_value(&reply).expect("serialize rpc reply");
    assert_eq!(json["allowed"], false);
    assert_eq!(json["source"], "blocked");
    assert_eq!(json["error"], "timeout");
}

#[test]
fn status_reply_includes_merged_policy() {
    let reply = StatusReply {
        ok: true,
        merged: crate::policy::Policy::default(),
        pending: vec![],
    };
    let json = serde_json::to_value(&reply).expect("serialize rpc reply");
    assert!(
        json.get("merged")
            .expect("merged field present")
            .is_object()
    );
}

#[test]
fn check_reply_deserializes_as_check_not_simple() {
    let line = serde_json::to_string(&CheckReply::allowed("once")).expect("serialize rpc reply");
    let reply: RpcReply = serde_json::from_str(&line).expect("deserialize rpc reply");
    assert!(matches!(reply, RpcReply::Check(c) if c.allowed && c.source == "once"));
}

#[test]
fn elevate_reply_deserializes_as_elevate_not_simple() {
    let line = serde_json::to_string(&ElevateReply::executed(0, "root\n".into(), String::new()))
        .expect("serialize rpc reply");
    let reply: RpcReply = serde_json::from_str(&line).expect("deserialize rpc reply");
    assert!(matches!(
        reply,
        RpcReply::Elevate(e) if e.allowed && e.exit_code == 0 && e.stdout == "root\n"
    ));
}

#[test]
fn filesystem_check_reply_roundtrip() {
    let reply = FilesystemCheckReply::blocked(
        "no matching rule",
        "/home/user/file.txt".into(),
        FileAccess::Read,
    );
    let json = serde_json::to_value(&reply).expect("serialize rpc reply");
    assert_eq!(json["allowed"], false);
    assert_eq!(json["source"], "blocked");
    assert_eq!(json["path"], "/home/user/file.txt");
    assert_eq!(json["access"], "read");
    assert_eq!(json["error"], "no matching rule");
}

#[test]
fn filesystem_check_reply_allowed() {
    let reply = FilesystemCheckReply::allowed("deny", "/tmp".into(), FileAccess::ReadWrite);
    let json = serde_json::to_value(&reply).expect("serialize rpc reply");
    assert_eq!(json["allowed"], true);
    assert_eq!(json["path"], "/tmp");
    assert_eq!(json["access"], "read_write");
}

#[test]
fn filesystem_monitor_reply_roundtrip() {
    let reply = FilesystemMonitorReply::active();
    let json = serde_json::to_value(&reply).expect("serialize rpc reply");
    assert_eq!(json["ok"], true);
    assert_eq!(json["active"], true);
}

#[test]
fn filesystem_check_reply_deserializes_as_filesystem_check() {
    let line = serde_json::to_string(&FilesystemCheckReply::allowed(
        "once",
        "/data".into(),
        FileAccess::All,
    ))
    .expect("serialize rpc reply");
    let reply: RpcReply = serde_json::from_str(&line).expect("deserialize rpc reply");
    assert!(
        matches!(reply, RpcReply::FilesystemCheck(c) if c.allowed && c.source == "once" && c.path == Path::new("/data"))
    );
}

#[test]
fn check_filesystem_request_deserializes() {
    let req: RpcRequest = serde_json::from_str(
        r#"{"op":"check_filesystem","path":"/home/user/doc.txt","access":"read","cwd":"/home/user"}"#,
    )
    .expect("parse request json");
    assert!(matches!(req, RpcRequest::CheckFilesystem { .. }));
}

#[test]
fn start_filesystem_monitor_request_deserializes() {
    let req: RpcRequest =
        serde_json::from_str(r#"{"op":"start_filesystem_monitor","cwd":"/home/user"}"#)
            .expect("parse request json");
    assert!(matches!(req, RpcRequest::StartFilesystemMonitor { .. }));
}

#[test]
fn start_filesystem_monitor_with_static_allow() {
    let req: RpcRequest = serde_json::from_str(
        r#"{"op":"start_filesystem_monitor","ctx":{"cwd":"/home/user"},"static_allow":[{"path":"/nix/store","access":"all"}]}"#,
    )
    .expect("parse request json");
    match req {
        RpcRequest::StartFilesystemMonitor { static_allow, .. } => {
            assert_eq!(static_allow.len(), 1);
            assert_eq!(static_allow[0].path, Path::new("/nix/store"));
            assert_eq!(static_allow[0].access, FileAccess::All);
        }
        _ => panic!("expected StartFilesystemMonitor"),
    }
}

#[test]
fn start_filesystem_monitor_defaults_static_allow_empty() {
    let req: RpcRequest =
        serde_json::from_str(r#"{"op":"start_filesystem_monitor","ctx":{"cwd":"/home/user"}}"#)
            .expect("parse request json");
    match req {
        RpcRequest::StartFilesystemMonitor { static_allow, .. } => {
            assert!(
                static_allow.is_empty(),
                "static_allow must default to empty"
            );
        }
        _ => panic!("expected StartFilesystemMonitor"),
    }
}

use super::{
    CheckReply, ElevateReply, RegisterUiReply, RpcMessage, RpcReply, RpcRequest, ScopeActionReply,
    StatusReply, UiPush,
};

#[test]
fn check_request_deserializes() {
    let req: RpcRequest = serde_json::from_str(
        r#"{"op":"check","host":"example.com","port":443,"scheme":"https","cwd":"/tmp"}"#,
    )
    .unwrap();
    assert!(matches!(req, RpcRequest::Check { .. }));
}

#[test]
fn register_ui_reply_serializes() {
    let line = RpcReply::RegisterUi(RegisterUiReply {
        ok: true,
        role: "ui".into(),
        session_id: "abc".into(),
    })
    .to_line();
    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
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
    .to_line();
    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(v["type"], "network_request");
    assert_eq!(v["id"], "n1");
}

#[test]
fn check_reply_roundtrip() {
    let reply = CheckReply::blocked("timeout");
    let json = serde_json::to_value(&reply).unwrap();
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
    let json = serde_json::to_value(&reply).unwrap();
    assert!(json.get("merged").unwrap().is_object());
}

#[test]
fn check_reply_deserializes_as_check_not_simple() {
    let line = serde_json::to_string(&CheckReply::allowed("once")).unwrap();
    let reply: RpcReply = serde_json::from_str(&line).unwrap();
    assert!(matches!(reply, RpcReply::Check(c) if c.allowed && c.source == "once"));
}

#[test]
fn elevate_reply_deserializes_as_elevate_not_simple() {
    let line = serde_json::to_string(&ElevateReply::executed(
        0,
        "root\n".into(),
        String::new(),
    ))
    .unwrap();
    let reply: RpcReply = serde_json::from_str(&line).unwrap();
    assert!(matches!(
        reply,
        RpcReply::Elevate(e) if e.allowed && e.exit_code == 0 && e.stdout == "root\n"
    ));
}

#[test]
fn scope_action_reply_deserializes_as_scope_action() {
    let line = serde_json::to_string(&ScopeActionReply::ok_network(
        "example.com".into(),
        443,
        "once",
        None,
    ))
    .unwrap();
    let reply: RpcReply = serde_json::from_str(&line).unwrap();
    assert!(matches!(reply, RpcReply::ScopeAction(s) if s.host.as_deref() == Some("example.com")));
}

#[test]
fn scope_action_reply_optional_fields_omitted() {
    let json = serde_json::to_value(ScopeActionReply::ok_network(
        "ex.com".into(),
        443,
        "once",
        None,
    ))
    .unwrap();
    assert!(json.get("argv").is_none());
    assert_eq!(json["host"], "ex.com");
}

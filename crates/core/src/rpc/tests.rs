use super::{
    ApprovalScope, CheckReply, ElevateReply, FilesystemCheckReply, FilesystemMonitorReply,
    HttpCheckReply, ProxyReply, ProxyReplyBody, ProxyRequestId, RegisterUiReply,
    ResourceCheckReply, RpcMessage, RpcReply, RpcRequest, ScopeActionReply, SimpleOkReply,
    StatusReply, UiPush, Verdict, VerdictSource,
};
use crate::ResourceKind;
use crate::http::HttpRequest;
use crate::policy::{DeviceAccess, FileAccess, ResourceAccess};
use std::path::{Path, PathBuf};

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
fn proxy_reply_envelopes_preserve_request_id_and_body() {
    let request_id = ProxyRequestId::new();
    let request =
        HttpRequest::from_parts("GET", "https", "example.com", "/api").expect("valid HTTP request");
    let replies = [
        ProxyReplyBody::HttpCheck(HttpCheckReply::from_verdict(
            request,
            Verdict::allowed(VerdictSource::Scope(ApprovalScope::Once)),
        )),
        ProxyReplyBody::NetworkFlow(CheckReply::blocked("denied")),
        ProxyReplyBody::Canceled(SimpleOkReply::OK),
        ProxyReplyBody::Error(super::ErrorReply::new("failed")),
    ];

    for body in replies {
        let wire = serde_json::to_string(&RpcReply::Proxy(ProxyReply {
            request_id,
            reply: body,
        }))
        .expect("serialize proxy reply");
        let value: serde_json::Value = serde_json::from_str(&wire).expect("parse proxy reply wire");
        assert_eq!(value["request_id"], request_id.to_string());
        assert!(value["reply"]["kind"].is_string());
        let parsed: RpcReply = serde_json::from_str(&wire).expect("deserialize proxy reply");
        let RpcReply::Proxy(parsed) = parsed else {
            panic!("proxy reply envelope was not selected");
        };
        assert_eq!(parsed.request_id, request_id);
    }
}

#[test]
fn proxy_replies_can_be_reordered_without_losing_identity() {
    let first = ProxyRequestId::new();
    let second = ProxyRequestId::new();
    let first_wire = serde_json::to_string(&RpcReply::Proxy(ProxyReply {
        request_id: first,
        reply: ProxyReplyBody::NetworkFlow(CheckReply::blocked("first")),
    }))
    .expect("serialize first reply");
    let second_wire = serde_json::to_string(&RpcReply::Proxy(ProxyReply {
        request_id: second,
        reply: ProxyReplyBody::NetworkFlow(CheckReply::blocked("second")),
    }))
    .expect("serialize second reply");

    let reordered = [second_wire, first_wire]
        .into_iter()
        .map(|wire| serde_json::from_str::<RpcReply>(&wire).expect("deserialize proxy reply"))
        .collect::<Vec<_>>();
    assert!(matches!(
        &reordered[..],
        [RpcReply::Proxy(second_reply), RpcReply::Proxy(first_reply)]
            if second_reply.request_id == second && first_reply.request_id == first
    ));
}

#[test]
fn blocked_http_reply_without_request_deserializes() {
    let reply: HttpCheckReply = serde_json::from_str(
        r#"{"ok":false,"allowed":false,"source":"blocked","error":"cancelled"}"#,
    )
    .expect("blocked HTTP reply without request");
    assert!(reply.request.is_none());
}

#[test]
fn filesystem_monitor_error_reply_deserializes_as_monitor() {
    let reply: RpcReply = serde_json::from_str(
        r#"{"ok":true,"active":false,"error":"fs_monitor_cmd not configured"}"#,
    )
    .expect("deserialize monitor reply");
    assert!(matches!(
        reply,
        RpcReply::FilesystemMonitor(FilesystemMonitorReply { active: false, .. })
    ));
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
    let line = serde_json::to_string(&CheckReply::allowed(VerdictSource::Scope(
        ApprovalScope::Once,
    )))
    .expect("serialize rpc reply");
    let reply: RpcReply = serde_json::from_str(&line).expect("deserialize rpc reply");
    assert!(matches!(
        reply,
        RpcReply::Check(c) if c.allowed && c.source == VerdictSource::Scope(ApprovalScope::Once)
    ));
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
fn filesystem_check_reply_denied_preserves_deny_wire_string() {
    let reply = FilesystemCheckReply::denied(
        VerdictSource::policy(),
        "/tmp".into(),
        FileAccess::ReadWrite,
    );
    let json = serde_json::to_value(&reply).expect("serialize rpc reply");
    assert_eq!(json["allowed"], false);
    assert_eq!(json["source"], "deny");
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
        VerdictSource::Scope(ApprovalScope::Once),
        "/data".into(),
        FileAccess::All,
    ))
    .expect("serialize rpc reply");
    let reply: RpcReply = serde_json::from_str(&line).expect("deserialize rpc reply");
    assert!(matches!(
        reply,
        RpcReply::FilesystemCheck(c)
            if c.allowed
                && c.source == VerdictSource::Scope(ApprovalScope::Once)
                && c.path == Path::new("/data")
    ));
}

#[test]
fn check_reply_roundtrips_allow_comment_wire_string() {
    let line = r#"{"ok":true,"allowed":true,"source":"allow:trusted policy file"}"#;
    let reply: RpcReply = serde_json::from_str(line).expect("deserialize rpc reply");
    assert!(matches!(
        &reply,
        RpcReply::Check(CheckReply {
            allowed: true,
            source,
            error: None,
            ..
        }) if source == &VerdictSource::policy_with_comment("trusted policy file")
    ));
    let json = serde_json::to_value(&reply).expect("serialize rpc reply");
    assert_eq!(json["source"], "allow:trusted policy file");
}

#[test]
fn check_reply_rejects_allowed_false_with_allow_source() {
    let err = serde_json::from_str::<CheckReply>(
        r#"{"ok":true,"allowed":false,"source":"allow:trusted policy file"}"#,
    )
    .expect_err("mismatched allowed/source must fail");
    assert!(err.to_string().contains("allow"));
}

#[test]
fn check_reply_rejects_allowed_true_with_denied_source() {
    let err = serde_json::from_str::<CheckReply>(r#"{"ok":true,"allowed":true,"source":"denied"}"#)
        .expect_err("mismatched allowed/source must fail");
    assert!(err.to_string().contains("denied"));
}

#[test]
fn filesystem_check_reply_rejects_allowed_false_with_once_source() {
    let err = serde_json::from_str::<FilesystemCheckReply>(
        r#"{"ok":true,"allowed":false,"source":"once","path":"/data","access":"read"}"#,
    )
    .expect_err("mismatched allowed/source must fail");
    assert!(err.to_string().contains("once"));
}

#[test]
fn resource_and_scope_replies_preserve_wire_strings() {
    let resource = ResourceCheckReply::allowed(
        VerdictSource::Infrastructure,
        ResourceKind::Device,
        PathBuf::from("/dev/fd/3"),
        ResourceAccess::Device(DeviceAccess::Read),
    );
    let resource_json = serde_json::to_value(&resource).expect("serialize resource reply");
    assert_eq!(resource_json["source"], "infrastructure");

    let scope = ScopeActionReply::ok_network(
        "example.com".into(),
        443,
        ApprovalScope::Global,
        Some(PathBuf::from(
            "/home/user/.config/agent-sandbox/policy.json",
        )),
    );
    let scope_json = serde_json::to_value(&scope).expect("serialize scope reply");
    assert_eq!(scope_json["scope"], "global");
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

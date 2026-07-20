use std::path::PathBuf;

use agent_sandbox_core::{
    ApprovalScope, HttpCheckReply, HttpRequest, ProxyReply, ProxyRequestId, RequestContext,
    RpcMessage, RpcReply, RpcRequest, Verdict, VerdictSource,
};

#[test]
fn check_request_round_trips_with_context_over_json_wire() {
    let request = RpcRequest::Check {
        host: Some("example.com".into()),
        connect_host: Some("203.0.113.7".into()),
        port: Some(443),
        scheme: "https".into(),
        url: Some("https://example.com/api?token=redacted".into()),
        ctx: RequestContext {
            cwd: Some(PathBuf::from("/worktree")),
            home: Some(PathBuf::from("/home/user")),
            project_root: Some(PathBuf::from("/worktree/project")),
            pid: Some(42),
            uid: Some(1000),
            sandbox_session_id: Some("session-1".into()),
        },
    };

    let wire = serde_json::to_string(&request).expect("serialize RPC request");
    let decoded: RpcRequest = serde_json::from_str(&wire).expect("deserialize RPC request");
    match decoded {
        RpcRequest::Check {
            host,
            connect_host,
            port,
            scheme,
            url,
            ctx,
        } => {
            assert_eq!(host.as_deref(), Some("example.com"));
            assert_eq!(connect_host.as_deref(), Some("203.0.113.7"));
            assert_eq!(port, Some(443));
            assert_eq!(scheme, "https");
            assert_eq!(
                url.as_deref(),
                Some("https://example.com/api?token=redacted")
            );
            assert_eq!(ctx.cwd, Some(PathBuf::from("/worktree")));
            assert_eq!(ctx.pid, Some(42));
            assert_eq!(ctx.uid, Some(1000));
            assert_eq!(ctx.sandbox_session_id.as_deref(), Some("session-1"));
        }
        other => panic!("unexpected request variant: {other:?}"),
    }
}

#[test]
fn proxy_http_reply_round_trips_as_a_single_json_line() {
    let request =
        HttpRequest::parse_absolute("GET", "https://example.com/api/v1").expect("request");
    let request_id = ProxyRequestId::new();
    let reply = HttpCheckReply::from_verdict(
        request.clone(),
        Verdict::allowed(VerdictSource::Scope(ApprovalScope::Session)),
    );
    let proxy = ProxyReply::from_reply(request_id, RpcReply::HttpCheck(reply));
    let line = RpcMessage::Reply(RpcReply::Proxy(proxy)).to_string();

    assert!(line.ends_with('\n'));
    let decoded: RpcMessage = serde_json::from_str(line.trim_end()).expect("decode RPC line");
    match decoded {
        RpcMessage::Reply(RpcReply::Proxy(proxy)) => {
            assert_eq!(proxy.request_id, request_id);
            match proxy.reply {
                agent_sandbox_core::ProxyReplyBody::HttpCheck(reply) => {
                    assert!(reply.ok);
                    assert!(reply.allowed);
                    assert_eq!(reply.source, VerdictSource::Scope(ApprovalScope::Session));
                    assert_eq!(reply.request, Some(request));
                }
                other => panic!("unexpected proxy body: {other:?}"),
            }
        }
        other => panic!("unexpected message variant: {other:?}"),
    }
}

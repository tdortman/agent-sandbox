//! Wire compatibility across a policyd upgrade.
//!
//! Brokers, fsmon, the D-Bus proxy, nfq and the transparent proxy of a
//! running system keep their binary when policyd is replaced. The request
//! lines below are what those clients send today: a release must keep
//! decoding them, so change a fixture only together with a note that running
//! sandboxes need a restart. The replies carry a field no current type has,
//! as a newer policyd may send.

use std::path::Path;

use agent_sandbox_core::{
    FileAccess, ProxyReplyBody, ResourceKind, RpcMessage, RpcReply, RpcRequest, SimpleOkReply,
    parse_rpc_request, policy::DbusMessageKind,
};

fn request(line: &str) -> RpcRequest {
    serde_json::from_str(line).unwrap_or_else(|error| panic!("{line}: {error}"))
}

fn reply(line: &str) -> RpcReply {
    match serde_json::from_str(line) {
        Ok(RpcMessage::Reply(reply)) => reply,
        Ok(RpcMessage::UiPush(push)) => panic!("{line}: decoded as push {push:?}"),
        Err(error) => panic!("{line}: {error}"),
    }
}

#[test]
fn requests_from_running_sandboxes_still_decode() {
    let RpcRequest::Check {
        host, port, ctx, ..
    } = request(
        r#"{"op":"check","host":"example.test","connect_host":"example.test","port":443,"scheme":"https","url":"https://example.test:443","ctx":{"cwd":"/work","pid":4242,"sandbox_session_id":"s1"}}"#,
    )
    else {
        panic!("network check decoded as another request");
    };
    assert_eq!(host.as_deref(), Some("example.test"));
    assert_eq!(port, Some(443));
    assert_eq!(ctx.sandbox_session_id.as_deref(), Some("s1"));

    let RpcRequest::CheckFilesystem { path, access, ctx } = request(
        r#"{"op":"check_filesystem","path":"/work/a","access":"read_write","ctx":{"cwd":"/work","pid":4242,"sandbox_session_id":"s1"}}"#,
    ) else {
        panic!("filesystem check decoded as another request");
    };
    assert_eq!(path, Path::new("/work/a"));
    assert_eq!(access, FileAccess::ReadWrite);
    assert_eq!(ctx.pid, Some(4242));

    let RpcRequest::CheckResource { kind, path, .. } = request(
        r#"{"op":"check_resource","kind":"device","path":"/dev/nvidia0","access":"open_read_write","ctx":{"cwd":"/work","pid":4242,"sandbox_session_id":"s1"}}"#,
    ) else {
        panic!("resource check decoded as another request");
    };
    assert_eq!(kind, ResourceKind::Device);
    assert_eq!(path, Path::new("/dev/nvidia0"));

    let RpcRequest::CheckDbus { target, .. } = request(
        r#"{"op":"check_dbus","target":{"bus":"session","destination":"org.example.Service","object_path":"/org/example/Object","interface":"org.example.Interface","member":"Read","message_kind":"method_call","signature":"s","fd_metadata":[]},"ctx":{"cwd":"/work","pid":4242,"sandbox_session_id":"s1"}}"#,
    ) else {
        panic!("D-Bus check decoded as another request");
    };
    assert_eq!(target.message_kind, DbusMessageKind::MethodCall);

    let RpcRequest::FilesystemSnapshot { ctx } = request(
        r#"{"op":"filesystem_snapshot","ctx":{"cwd":"/work","pid":4242,"sandbox_session_id":"s1"}}"#,
    ) else {
        panic!("filesystem snapshot decoded as another request");
    };
    assert_eq!(ctx.cwd.as_deref(), Some(Path::new("/work")));
}

#[test]
fn replies_with_unknown_fields_keep_their_meaning() {
    let RpcReply::FilesystemCheck(check) = reply(
        r#"{"result":"filesystem_check","ok":true,"allowed":true,"source":"static","path":"/work/a","access":"read_write","added_later":1}"#,
    ) else {
        panic!("filesystem reply decoded as another reply");
    };
    assert!(check.verdict.allowed);
    assert_eq!(check.path, Path::new("/work/a"));

    let RpcReply::ResourceCheck(check) = reply(
        r#"{"result":"resource_check","ok":true,"allowed":false,"source":"denied","kind":"device","path":"/dev/nvidia0","access":"open_read_write","added_later":1}"#,
    ) else {
        panic!("resource reply decoded as another reply");
    };
    assert!(!check.verdict.allowed);
    assert_eq!(check.kind, ResourceKind::Device);

    let RpcReply::Check(check) = reply(
        r#"{"result":"check","ok":true,"allowed":false,"source":"denied","error":"no rule","added_later":1}"#,
    ) else {
        panic!("network reply decoded as another reply");
    };
    assert!(!check.verdict.allowed);
    assert_eq!(check.error.as_deref(), Some("no rule"));

    let RpcReply::DbusCheck(check) = reply(
        r#"{"result":"dbus_check","ok":true,"allowed":true,"source":"static","target":{"bus":"session","destination":"org.example.Service","object_path":"/org/example/Object","interface":"org.example.Interface","member":"Read","message_kind":"method_call","signature":"s","fd_metadata":[]},"added_later":1}"#,
    ) else {
        panic!("D-Bus reply decoded as another reply");
    };
    assert!(check.verdict.allowed);

    let RpcReply::FilesystemSnapshot { filesystem, .. } = reply(
        r#"{"result":"filesystem_snapshot","filesystem":{"allow":[{"path":"/nix/store","access":"all"}],"deny":[]},"denied_inodes":[],"added_later":1}"#,
    ) else {
        panic!("filesystem snapshot decoded as another reply");
    };
    assert_eq!(filesystem.allow[0].path, Path::new("/nix/store"));

    let RpcReply::Error(error) =
        reply(r#"{"result":"error","ok":false,"error":"policyd failed","added_later":1}"#)
    else {
        panic!("error reply decoded as another reply");
    };
    assert_eq!(error.error, "policyd failed");
}

/// The nfq daemon and the transparent proxy outlive policyd restarts too.
#[test]
fn requests_from_running_proxy_and_nfq_still_decode() {
    let proxy_request =
        |line: &str| parse_rpc_request(line).unwrap_or_else(|error| panic!("{line}: {error}"));

    let RpcRequest::RegisterNetworkFlow {
        registration,
        owner_fd_hint,
    } = proxy_request(
        r#"{"op":"register_network_flow","registration":{"flow":{"protocol":"tcp","source_ip":"10.0.0.2","source_port":40000,"destination_ip":"93.184.216.34","destination_port":443},"owner":{"pid":4242,"uid":1000,"process_start_time_ticks":123456,"socket_inode":98765},"policy_host":"example.test","ctx":{"sandbox_session_id":"s1"}},"owner_fd_hint":7}"#,
    )
    else {
        panic!("flow registration decoded as another request");
    };
    assert_eq!(registration.owner().pid().get(), 4242);
    assert_eq!(registration.flow().destination_port().get(), 443);
    assert_eq!(owner_fd_hint, Some(7));

    let lines = [
        r#"{"op":"claim_network_flow","proxy_session":"0101010101010101010101010101010101010101010101010101010101010101","flow":{"protocol":"tcp","source_ip":"10.0.0.2","source_port":40000,"destination_ip":"93.184.216.34","destination_port":443},"connection_id":"6f1c2a52-4e0b-4c4f-9a39-0b7d2f2c9e11"}"#,
        r#"{"op":"claim_network_flow_by_source","proxy_session":"0101010101010101010101010101010101010101010101010101010101010101","selector":{"protocol":"udp","source_ip":"10.0.0.2","source_port":40001,"destination_port":443},"connection_id":"6f1c2a52-4e0b-4c4f-9a39-0b7d2f2c9e11"}"#,
        r#"{"op":"rebind_network_flow","proxy_session":"0101010101010101010101010101010101010101010101010101010101010101","attribution_token":"0202020202020202020202020202020202020202020202020202020202020202","connection_id":"6f1c2a52-4e0b-4c4f-9a39-0b7d2f2c9e11","flow":{"protocol":"tcp","source_ip":"10.0.0.2","source_port":40000,"destination_ip":"93.184.216.34","destination_port":443}}"#,
        r#"{"op":"check_http","proxy_session":"0101010101010101010101010101010101010101010101010101010101010101","request_id":"01890a5d-ac96-774b-bcce-b302099a8058","attribution_token":"0202020202020202020202020202020202020202020202020202020202020202","request":{"method":"GET","url":"https://example.test/a"}}"#,
        r#"{"op":"check_network_flow","proxy_session":"0101010101010101010101010101010101010101010101010101010101010101","request_id":"01890a5d-ac96-774b-bcce-b302099a8058","attribution_token":"0202020202020202020202020202020202020202020202020202020202020202"}"#,
        r#"{"op":"cancel_check","proxy_session":"0101010101010101010101010101010101010101010101010101010101010101","request_id":"01890a5d-ac96-774b-bcce-b302099a8058"}"#,
        r#"{"op":"release_network_flow","proxy_session":"0101010101010101010101010101010101010101010101010101010101010101","attribution_token":"0202020202020202020202020202020202020202020202020202020202020202","connection_id":"6f1c2a52-4e0b-4c4f-9a39-0b7d2f2c9e11"}"#,
    ];
    let ops = lines.map(|line| match proxy_request(line) {
        RpcRequest::ClaimNetworkFlow { .. } => "claim_network_flow",
        RpcRequest::ClaimNetworkFlowBySource { .. } => "claim_network_flow_by_source",
        RpcRequest::RebindNetworkFlow { .. } => "rebind_network_flow",
        RpcRequest::CheckHttp { .. } => "check_http",
        RpcRequest::CheckNetworkFlow { .. } => "check_network_flow",
        RpcRequest::CancelCheck { .. } => "cancel_check",
        RpcRequest::ReleaseNetworkFlow { .. } => "release_network_flow",
        other => panic!("{line}: decoded as {other:?}"),
    });
    for (line, op) in lines.iter().zip(ops) {
        assert!(line.starts_with(&format!(r#"{{"op":"{op}""#)), "{line}");
    }
}

#[test]
fn proxy_replies_with_unknown_fields_keep_their_meaning() {
    let RpcReply::ProxySession(session) = reply(
        r#"{"result":"proxy_session","ok":true,"proxy_session":"0101010101010101010101010101010101010101010101010101010101010101","added_later":1}"#,
    ) else {
        panic!("proxy session reply decoded as another reply");
    };
    assert_eq!(session.proxy_session.as_bytes(), &[1; 32]);

    let RpcReply::FlowClaim(claim) = reply(
        r#"{"result":"flow_claim","ok":true,"attribution_token":"0202020202020202020202020202020202020202020202020202020202020202","flow":{"protocol":"tcp","source_ip":"10.0.0.2","source_port":40000,"destination_ip":"93.184.216.34","destination_port":443},"policy_host":"example.test","owner_cgroup":"/sys/fs/cgroup/agent","added_later":1}"#,
    ) else {
        panic!("flow claim decoded as another reply");
    };
    assert_eq!(claim.attribution_token.as_bytes(), &[2; 32]);
    assert_eq!(
        claim.owner_cgroup.as_deref(),
        Some(Path::new("/sys/fs/cgroup/agent"))
    );

    let RpcReply::Proxy(proxy) = reply(
        r#"{"result":"proxy","request_id":"01890a5d-ac96-774b-bcce-b302099a8058","reply":{"kind":"http_check","reply":{"ok":true,"allowed":true,"source":"allow","request":{"method":"GET","url":"https://example.test/a"},"added_later":1}},"added_later":1}"#,
    ) else {
        panic!("HTTP check envelope decoded as another reply");
    };
    let ProxyReplyBody::HttpCheck(check) = proxy.reply else {
        panic!("HTTP check envelope carries another reply");
    };
    assert!(check.verdict.allowed);

    let RpcReply::Proxy(proxy) = reply(
        r#"{"result":"proxy","request_id":"01890a5d-ac96-774b-bcce-b302099a8058","reply":{"kind":"network_flow","reply":{"ok":true,"allowed":false,"source":"deny","added_later":1}}}"#,
    ) else {
        panic!("network flow envelope decoded as another reply");
    };
    let ProxyReplyBody::NetworkFlow(check) = proxy.reply else {
        panic!("network flow envelope carries another reply");
    };
    assert!(!check.verdict.allowed);

    let RpcReply::Proxy(proxy) = reply(
        r#"{"result":"proxy","request_id":"01890a5d-ac96-774b-bcce-b302099a8058","reply":{"kind":"canceled","reply":{"ok":true,"added_later":1}}}"#,
    ) else {
        panic!("cancel envelope decoded as another reply");
    };
    assert!(matches!(
        proxy.reply,
        ProxyReplyBody::Canceled(SimpleOkReply { ok: true })
    ));

    assert!(matches!(
        reply(r#"{"result":"simple","ok":true,"added_later":1}"#),
        RpcReply::Simple(SimpleOkReply { ok: true })
    ));
}

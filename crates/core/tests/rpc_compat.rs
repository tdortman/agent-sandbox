//! Wire compatibility across a policyd upgrade.
//!
//! Brokers, fsmon, the D-Bus proxy, nfq and the transparent proxy of a
//! running system keep their binary when policyd is replaced. The request
//! lines below are what those clients send today: a release must keep
//! decoding them, so change a fixture only together with a note that running
//! sandboxes need a restart. The replies carry a field no current type has,
//! as a newer policyd may send.

use std::{collections::BTreeMap, path::Path};

use agent_sandbox_core::{
    FileAccess, ProxyReplyBody, RequestContext, ResourceKind, RpcMessage, RpcReply, RpcRequest,
    SandboxPackageReply, SecretAccess, SecretBatchInfo, SecretCheckReply, SecretOperation,
    SecretPartition, SecretRequest, SimpleOkReply, VerdictSource, parse_rpc_request,
    policy::DbusMessageKind,
};

fn request(line: &str) -> RpcRequest {
    serde_json::from_str(line).unwrap_or_else(|error| panic!("{line}: {error}"))
}

fn reply(line: &str) -> RpcReply {
    match serde_json::from_str(line) {
        Ok(RpcMessage::Reply(reply)) => reply,
        Ok(RpcMessage::UiPush(push)) => panic!("{line}: decoded as push {push:?}"),
        Ok(RpcMessage::Heartbeat(_)) => panic!("{line}: decoded as heartbeat"),
        Err(error) => panic!("{line}: {error}"),
    }
}

#[test]
fn requests_from_running_sandboxes_still_decode() {
    let RpcRequest::Check {
        host,
        port,
        ctx,
        may_prompt,
        ..
    } = request(
        r#"{"op":"check","host":"example.test","connect_host":"example.test","port":443,"scheme":"https","url":"https://example.test:443","ctx":{"cwd":"/work","pid":4242,"sandbox_session_id":"s1"}}"#,
    )
    else {
        panic!("network check decoded as another request");
    };
    assert_eq!(host.as_deref(), Some("example.test"));
    assert_eq!(port, Some(443));
    assert_eq!(ctx.sandbox_session_id.as_deref(), Some("s1"));
    assert!(may_prompt, "requests that predate may_prompt still prompt");

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

    let RpcRequest::ResolveSandboxPackage { ctx } = request(
        r#"{"op":"resolve_sandbox_package","ctx":{"pid":4242,"uid":1000,"sandbox_session_id":"s1"}}"#,
    ) else {
        panic!("resolve_sandbox_package decoded as another request");
    };
    assert_eq!(ctx.sandbox_session_id.as_deref(), Some("s1"));

    let RpcRequest::CheckSecret { request: req, ctx } = request(
        r#"{"op":"check_secret","request":{"partition":"own_package","collection":"kdewallet","is_default_collection":true,"attributes":{"service":"gh"},"label":"GitHub token","access":"read","operation":"get_secret"},"ctx":{"pid":4242,"uid":1000,"sandbox_session_id":"s1"}}"#,
    ) else {
        panic!("check_secret decoded as another request");
    };
    assert_eq!(req.partition, SecretPartition::OwnPackage);
    assert_eq!(req.access, SecretAccess::Read);
    assert_eq!(req.operation, SecretOperation::GetSecret);
    assert_eq!(ctx.pid, Some(4242));
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

    let RpcReply::SandboxPackage(pkg) =
        reply(r#"{"result":"sandbox_package","ok":true,"package":"codex","added_later":1}"#)
    else {
        panic!("sandbox_package reply decoded as another reply");
    };
    assert!(pkg.ok);
    assert_eq!(pkg.package.as_deref(), Some("codex"));

    let RpcReply::SecretCheck(secret) = reply(
        r#"{"result":"secret_check","ok":true,"allowed":true,"source":"allow","request":{"partition":"host","collection":"kdewallet","is_default_collection":true,"attributes":{"service":"gh"},"label":"GitHub token","access":"read","operation":"get_secret"},"added_later":1}"#,
    ) else {
        panic!("secret_check reply decoded as another reply");
    };
    assert!(secret.ok);
    assert!(secret.verdict.allowed);
    assert_eq!(secret.request.partition, SecretPartition::Host);

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

#[test]
fn secret_and_package_rpc_messages_round_trip_through_json() {
    let mut attributes = BTreeMap::new();
    attributes.insert("service".to_owned(), "gh:github.com".to_owned());

    let secret_request = SecretRequest {
        partition: SecretPartition::Host,
        collection: "kdewallet".to_owned(),
        is_default_collection: true,
        attributes,
        label: "GitHub token".to_owned(),
        access: SecretAccess::Write,
        operation: SecretOperation::CreateItem,
        replace: true,
        batch: Some(SecretBatchInfo { index: 2, total: 5 }),
    };

    let check_req = RpcRequest::CheckSecret {
        request: secret_request.clone(),
        ctx: RequestContext {
            pid: Some(4242),
            uid: Some(1000),
            sandbox_session_id: Some("s1".to_owned()),
            ..RequestContext::default()
        },
    };
    let check_json = serde_json::to_string(&check_req).expect("serialize CheckSecret");
    let RpcRequest::CheckSecret {
        request: decoded_req,
        ctx: decoded_ctx,
    } = request(&check_json)
    else {
        panic!("CheckSecret round-trip decoded as another variant");
    };
    assert_eq!(decoded_req, secret_request);
    assert_eq!(decoded_ctx.sandbox_session_id.as_deref(), Some("s1"));

    let resolve_req = RpcRequest::ResolveSandboxPackage {
        ctx: RequestContext {
            sandbox_session_id: Some("s1".to_owned()),
            ..RequestContext::default()
        },
    };
    let resolve_json =
        serde_json::to_string(&resolve_req).expect("serialize ResolveSandboxPackage");
    let RpcRequest::ResolveSandboxPackage { ctx } = request(&resolve_json) else {
        panic!("ResolveSandboxPackage round-trip decoded as another variant");
    };
    assert_eq!(ctx.sandbox_session_id.as_deref(), Some("s1"));

    for pkg in [Some("codex".to_owned()), None] {
        let encoded = serde_json::to_string(&RpcReply::SandboxPackage(SandboxPackageReply::ok(
            pkg.clone(),
        )))
        .expect("serialize SandboxPackage");
        let RpcReply::SandboxPackage(decoded) = reply(&encoded) else {
            panic!("SandboxPackage round-trip decoded as another variant");
        };
        assert!(decoded.ok);
        assert_eq!(decoded.package, pkg);
    }

    let blocked = RpcReply::SecretCheck(SecretCheckReply::blocked(
        "secret denied",
        secret_request.clone(),
    ));
    let blocked_json = serde_json::to_string(&blocked).expect("serialize blocked SecretCheck");
    let RpcReply::SecretCheck(decoded_blocked) = reply(&blocked_json) else {
        panic!("blocked SecretCheck decoded as another variant");
    };
    assert!(!decoded_blocked.verdict.allowed);
    assert_eq!(decoded_blocked.verdict.source, VerdictSource::Blocked);
    assert_eq!(decoded_blocked.error.as_deref(), Some("secret denied"));
    assert_eq!(decoded_blocked.request, secret_request);

    let denied = RpcReply::SecretCheck(SecretCheckReply::denied(
        VerdictSource::policy(),
        secret_request.clone(),
    ));
    let denied_json = serde_json::to_string(&denied).expect("serialize denied SecretCheck");
    let RpcReply::SecretCheck(decoded_denied) = reply(&denied_json) else {
        panic!("denied SecretCheck decoded as another variant");
    };
    assert!(!decoded_denied.verdict.allowed);
    assert_eq!(decoded_denied.verdict.source, VerdictSource::policy());
    assert_eq!(decoded_denied.request, secret_request);

    let secret_target = agent_sandbox_core::SecretTarget::exact_for_request(&secret_request);
    let approve_req = RpcRequest::Approve {
        id: "secret:1".to_owned(),
        scope: agent_sandbox_core::ApprovalScope::ProjectPackage,
        session_id: Some("ui-1".to_owned()),
        target: Some(agent_sandbox_core::ApprovalTarget::Secret {
            target: secret_target.clone(),
        }),
        comment: Some("allow GitHub token".to_owned()),
        ctx: RequestContext::default(),
    };
    let approve_json = serde_json::to_string(&approve_req).expect("serialize Approve Secret");
    let RpcRequest::Approve {
        target:
            Some(agent_sandbox_core::ApprovalTarget::Secret {
                target: decoded_target,
            }),
        ..
    } = request(&approve_json)
    else {
        panic!("Approve with Secret target decoded as another variant");
    };
    assert_eq!(decoded_target, secret_target);

    let scope_reply = RpcReply::ScopeAction(agent_sandbox_core::ScopeActionReply::ok_secret(
        secret_target.clone(),
        agent_sandbox_core::ApprovalScope::GlobalPackage,
        Some(Path::new("/home/user/.config/agent-sandbox/packages/codex.json").to_path_buf()),
    ));
    let scope_json = serde_json::to_string(&scope_reply).expect("serialize ScopeAction Secret");
    let RpcReply::ScopeAction(agent_sandbox_core::ScopeActionReply::Secret {
        ok,
        target: reply_target,
        scope,
        path,
    }) = reply(&scope_json)
    else {
        panic!("ScopeAction Secret decoded as another variant");
    };
    assert!(ok);
    assert_eq!(reply_target, secret_target);
    assert_eq!(scope, "global_package");
    assert_eq!(
        path.as_deref(),
        Some(Path::new(
            "/home/user/.config/agent-sandbox/packages/codex.json"
        ))
    );

    let pending_summary = agent_sandbox_core::PendingSummary::Secret {
        id: "secret:1".to_owned(),
        request: secret_request.clone(),
        cwd: Some(Path::new("/repo").to_path_buf()),
        home: Some(Path::new("/home/user").to_path_buf()),
        project_root: Some(Path::new("/repo").to_path_buf()),
        sandbox_session_id: Some("s1".to_owned()),
        package: Some("codex".to_owned()),
    };
    let summary_json =
        serde_json::to_string(&pending_summary).expect("serialize PendingSummary::Secret");
    let decoded_summary: agent_sandbox_core::PendingSummary =
        serde_json::from_str(&summary_json).expect("deserialize PendingSummary::Secret");
    let agent_sandbox_core::PendingSummary::Secret {
        id: summary_id,
        request: summary_request,
        package: summary_pkg,
        ..
    } = &decoded_summary
    else {
        panic!("PendingSummary::Secret decoded as another variant");
    };
    assert_eq!(summary_id, "secret:1");
    assert_eq!(summary_request, &secret_request);
    assert_eq!(summary_pkg.as_deref(), Some("codex"));

    let ui_push = agent_sandbox_core::UiPush::SecretRequest {
        id: "secret:1".to_owned(),
        request: secret_request.clone(),
        cwd: Some(Path::new("/repo").to_path_buf()),
        home: Some(Path::new("/home/user").to_path_buf()),
        project_root: Some(Path::new("/repo").to_path_buf()),
        sandbox_session_id: Some("s1".to_owned()),
        package: Some("codex".to_owned()),
    };
    let push_json = serde_json::to_string(&ui_push).expect("serialize UiPush::SecretRequest");
    let decoded_push: agent_sandbox_core::UiPush =
        serde_json::from_str(&push_json).expect("deserialize UiPush::SecretRequest");
    assert!(decoded_push.is_for(&decoded_summary));
    let agent_sandbox_core::UiPush::SecretRequest {
        id: push_id,
        request: push_request,
        ..
    } = decoded_push
    else {
        panic!("UiPush::SecretRequest decoded as another variant");
    };
    assert_eq!(push_id, "secret:1");
    assert_eq!(push_request, secret_request);
}

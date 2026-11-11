//! Settlement driver behaviour against a scripted renderer and a real
//! policyd-shaped socket.

use std::{
    collections::{HashMap, VecDeque},
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, PendingSummary, Policy, RpcReply, RpcRequest, SandboxPaths,
    SimpleOkReply, StatusReply, UiPush,
};

use super::{handle_push, reviewed_choice};
use crate::ui::{
    dialog::{ApprovalReviewOutcome, Dialogs, Renderer},
    options::{ApprovalFormRequest, ApprovalFormResult, PromptAction, ReviewValidator},
    prompt::{ClientContext, valid_rule_path},
};

const REQUEST_ID: &str = "net-1";

/// Answers dialogs from queues and records what it was asked. A dialog the
/// script does not expect panics, which fails the settlement.
#[derive(Default)]
struct Script {
    reviews: Mutex<VecDeque<ApprovalReviewOutcome>>,
    options: Mutex<VecDeque<Option<&'static str>>>,
    texts: Mutex<VecDeque<Option<&'static str>>>,
    log: Mutex<Vec<String>>,
}

impl Script {
    fn log(&self) -> Vec<String> {
        self.log.lock().expect("log").clone()
    }
}

struct ScriptedRenderer(Arc<Script>);

impl Renderer for ScriptedRenderer {
    fn review(
        &self,
        _request: &ApprovalFormRequest,
        validate: Option<&ReviewValidator>,
    ) -> ApprovalReviewOutcome {
        let outcome = self
            .0
            .reviews
            .lock()
            .expect("reviews")
            .pop_front()
            .expect("unexpected review dialog");

        if let (ApprovalReviewOutcome::Submitted(result), Some(validate)) = (&outcome, validate) {
            self.0
                .log
                .lock()
                .expect("log")
                .push(format!("validator: {:?}", validate(result)));
        }

        outcome
    }

    fn pick_option(&self, title: &str, options: &[&str]) -> Option<String> {
        self.0
            .log
            .lock()
            .expect("log")
            .push(format!("option: {title} {options:?}"));

        self.0
            .options
            .lock()
            .expect("options")
            .pop_front()
            .expect("unexpected option dialog")
            .map(str::to_owned)
    }

    fn pick_text(&self, title: &str, default_text: &str) -> Option<String> {
        self.0
            .log
            .lock()
            .expect("log")
            .push(format!("text: {title} {default_text}"));

        self.0
            .texts
            .lock()
            .expect("texts")
            .pop_front()
            .expect("unexpected text dialog")
            .map(str::to_owned)
    }
}

/// A policyd stand-in on a real Unix socket: answers status checks with a
/// fixed pending list, acknowledges everything else, and records requests.
struct FakePolicyd {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    requests: Arc<Mutex<Vec<RpcRequest>>>,
}

impl FakePolicyd {
    fn start(pending: Vec<PendingSummary>) -> Self {
        let dir = tempfile::tempdir().expect("socket directory");
        let socket = dir.path().join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind fake policyd");
        let requests = Arc::new(Mutex::new(Vec::new()));

        thread::spawn({
            let requests = Arc::clone(&requests);

            move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    let mut line = String::new();

                    if BufReader::new(&stream).read_line(&mut line).is_err() {
                        return;
                    }

                    let request: RpcRequest =
                        serde_json::from_str(&line).expect("policyd request decodes");

                    let reply = match request {
                        RpcRequest::Status { .. } => RpcReply::Status(StatusReply {
                            ok: true,
                            merged: Policy::default(),
                            pending: pending.clone(),
                        }),
                        _ => RpcReply::Simple(SimpleOkReply::OK),
                    };

                    requests.lock().expect("requests").push(request);

                    let mut encoded = serde_json::to_vec(&reply).expect("encode reply");
                    encoded.push(b'\n');

                    if stream.write_all(&encoded).is_err() {
                        return;
                    }
                }
            }
        });

        Self {
            _dir: dir,
            socket,
            requests,
        }
    }

    /// Requests received so far, status checks excluded.
    fn decisions(&self) -> Vec<RpcRequest> {
        self.requests
            .lock()
            .expect("requests")
            .iter()
            .filter(|request| !matches!(request, RpcRequest::Status { .. }))
            .cloned()
            .collect()
    }

    fn status_checks(&self) -> usize {
        self.requests
            .lock()
            .expect("requests")
            .iter()
            .filter(|request| matches!(request, RpcRequest::Status { .. }))
            .count()
    }
}

fn network_push() -> UiPush {
    UiPush::NetworkRequest {
        id: REQUEST_ID.into(),
        host: Some("example.com".into()),
        port: Some(443),
        scheme: Some("tcp".into()),
        url: None,
        cwd: None,
        home: None,
        project_root: None,
        package: None,
    }
}

fn pending_network() -> PendingSummary {
    PendingSummary::Network {
        id: REQUEST_ID.into(),
        host: Some("example.com".into()),
        port: Some(443),
        scheme: Some("tcp".into()),
        url: None,
        cwd: None,
        home: None,
        package: None,
    }
}

fn submitted(
    action: Option<PromptAction>,
    scope: ApprovalScope,
    target: &str,
) -> ApprovalFormResult {
    ApprovalFormResult {
        action,
        scope,
        values: HashMap::from([
            ("target".into(), target.into()),
            ("comment".into(), "  because  ".into()),
        ]),
    }
}

/// Settle the network push against `policyd`, with the renderer answering
/// from `script`.
async fn settle_network_push(policyd: &FakePolicyd, script: &Arc<Script>) {
    let paths = SandboxPaths::new("/work/project", "/home/user", "/work/project");

    let client = ClientContext {
        socket: &policyd.socket,
        paths: &paths,
        session_id: Some("ui-session"),
        sandbox_session_id: None,
    };

    handle_push(
        &client,
        &Dialogs::new(ScriptedRenderer(Arc::clone(script))),
        network_push(),
    )
    .await
    .expect("settlement succeeds");
}

fn script_with_review(outcome: ApprovalReviewOutcome) -> Arc<Script> {
    let script = Arc::new(Script::default());
    script.reviews.lock().expect("reviews").push_back(outcome);
    script
}

#[tokio::test]
async fn accepted_review_approves_the_validated_target() {
    let policyd = FakePolicyd::start(vec![pending_network()]);

    let script = script_with_review(ApprovalReviewOutcome::Submitted(submitted(
        Some(PromptAction::Allow),
        ApprovalScope::Project,
        "*.example.com",
    )));

    settle_network_push(&policyd, &script).await;

    let decisions = policyd.decisions();
    let [
        RpcRequest::Approve {
            id,
            scope,
            session_id,
            target,
            comment,
            ..
        },
    ] = decisions.as_slice()
    else {
        panic!("expected one approval, got {decisions:?}");
    };

    assert_eq!(id, REQUEST_ID);
    assert_eq!(*scope, ApprovalScope::Project);
    assert_eq!(session_id.as_deref(), Some("ui-session"));

    assert_eq!(
        *target,
        Some(ApprovalTarget::NetworkHost {
            host: "*.example.com".into()
        })
    );

    assert_eq!(comment.as_deref(), Some("because"));
    assert_eq!(script.log(), ["validator: Ok(())"]);
}

#[tokio::test]
async fn denied_review_at_once_scope_sends_a_targetless_deny() {
    let policyd = FakePolicyd::start(vec![pending_network()]);

    let script = script_with_review(ApprovalReviewOutcome::Submitted(submitted(
        Some(PromptAction::Deny),
        ApprovalScope::Once,
        "ignored",
    )));

    settle_network_push(&policyd, &script).await;

    let decisions = policyd.decisions();
    let [
        RpcRequest::Deny {
            scope,
            target,
            comment,
            ..
        },
    ] = decisions.as_slice()
    else {
        panic!("expected one deny, got {decisions:?}");
    };

    assert_eq!(*scope, ApprovalScope::Once);
    assert!(target.is_none());
    assert!(comment.is_none());
}

#[tokio::test]
async fn cancelled_review_sends_a_one_time_deny() {
    let policyd = FakePolicyd::start(vec![pending_network()]);
    let script = script_with_review(ApprovalReviewOutcome::Cancelled);

    settle_network_push(&policyd, &script).await;

    let decisions = policyd.decisions();
    let [
        RpcRequest::Deny {
            id, scope, target, ..
        },
    ] = decisions.as_slice()
    else {
        panic!("expected one deny, got {decisions:?}");
    };

    assert_eq!(id, REQUEST_ID);
    assert_eq!(*scope, ApprovalScope::Once);
    assert!(target.is_none());
}

#[tokio::test]
async fn submission_that_fails_revalidation_is_denied_once() {
    let policyd = FakePolicyd::start(vec![pending_network()]);

    let script = script_with_review(ApprovalReviewOutcome::Submitted(submitted(
        Some(PromptAction::Allow),
        ApprovalScope::Global,
        "other.com",
    )));

    settle_network_push(&policyd, &script).await;

    let decisions = policyd.decisions();
    let [RpcRequest::Deny { scope, target, .. }] = decisions.as_slice() else {
        panic!("expected one deny, got {decisions:?}");
    };

    assert_eq!(*scope, ApprovalScope::Once);
    assert!(target.is_none());

    assert_eq!(script.log(), [
        "validator: Err(\"The rule does not match the request.\")"
    ]);
}

#[tokio::test]
async fn unavailable_review_falls_back_to_the_sequential_questions() {
    let policyd = FakePolicyd::start(vec![pending_network()]);
    let script = script_with_review(ApprovalReviewOutcome::Unavailable);

    script
        .options
        .lock()
        .expect("options")
        .extend([Some("Allow"), Some("This project, all packages")]);

    script
        .texts
        .lock()
        .expect("texts")
        .push_back(Some("example.com"));

    settle_network_push(&policyd, &script).await;

    let decisions = policyd.decisions();
    let [RpcRequest::Approve { scope, target, .. }] = decisions.as_slice() else {
        panic!("expected one approval, got {decisions:?}");
    };

    assert_eq!(*scope, ApprovalScope::Project);

    assert_eq!(
        *target,
        Some(ApprovalTarget::NetworkHost {
            host: "example.com".into()
        })
    );

    let log = script.log();
    assert!(
        log[0].starts_with("option: agent-sandbox: tcp://example.com:443 "),
        "{log:?}"
    );
    assert!(
        log[1].starts_with("option: agent-sandbox: allow tcp://example.com:443 scope?"),
        "{log:?}"
    );
    assert_eq!(
        log[2],
        "text: agent-sandbox: allow tcp://example.com:443 target? example.com"
    );
}

#[tokio::test]
async fn cancelling_a_fallback_question_sends_a_one_time_deny() {
    let policyd = FakePolicyd::start(vec![pending_network()]);
    let script = script_with_review(ApprovalReviewOutcome::Unavailable);

    script
        .options
        .lock()
        .expect("options")
        .extend([Some("Allow"), None]);

    settle_network_push(&policyd, &script).await;

    let decisions = policyd.decisions();
    let [RpcRequest::Deny { scope, target, .. }] = decisions.as_slice() else {
        panic!("expected one deny, got {decisions:?}");
    };

    assert_eq!(*scope, ApprovalScope::Once);
    assert!(target.is_none());
}

#[tokio::test]
async fn prompt_for_a_request_settled_while_queued_is_skipped() {
    let policyd = FakePolicyd::start(Vec::new());
    let script = Arc::new(Script::default());

    settle_network_push(&policyd, &script).await;

    assert_eq!(policyd.status_checks(), 1);
    assert!(policyd.decisions().is_empty());
    assert_eq!(script.log(), Vec::<String>::new());
}

#[test]
fn once_review_ignores_untrusted_target_value() {
    let result = ApprovalFormResult {
        action: Some(PromptAction::Allow),
        scope: ApprovalScope::Once,
        values: HashMap::new(),
    };

    let choice = reviewed_choice(&result, false, false, |_| {
        panic!("target validator must not run for Once")
    })
    .expect("valid Once choice")
    .choice;

    assert!(choice.target.is_none());
}

#[test]
fn persistent_review_requires_valid_target() {
    let result = ApprovalFormResult {
        action: Some(PromptAction::Allow),
        scope: ApprovalScope::Project,
        values: HashMap::from([("target".into(), String::new())]),
    };

    let choice = reviewed_choice(&result, false, false, |result| {
        valid_rule_path(result.values.get("target")?)
            .map(|path| ApprovalTarget::FilesystemPath { path })
    });

    assert!(choice.is_none());
}

#[test]
fn review_rejects_unavailable_scopes_and_cancel_action() {
    let unavailable = ApprovalFormResult {
        action: Some(PromptAction::Deny),
        scope: ApprovalScope::Session,
        values: HashMap::new(),
    };

    assert!(reviewed_choice(&unavailable, false, false, |_| None).is_none());

    let no_package = ApprovalFormResult {
        action: Some(PromptAction::Deny),
        scope: ApprovalScope::GlobalPackage,
        values: HashMap::new(),
    };

    assert!(reviewed_choice(&no_package, true, false, |_| None).is_none());

    let cancelled = ApprovalFormResult {
        action: None,
        scope: ApprovalScope::Once,
        values: HashMap::new(),
    };

    assert!(reviewed_choice(&cancelled, true, false, |_| None).is_none());
}

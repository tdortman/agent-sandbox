use std::{
    collections::HashMap,
    io::{BufRead, Write},
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, LazyLock},
};

use agent_sandbox_core::{graphical_session_env, tool_path};
use tracing::info;

use super::{
    error::UiCliError,
    options::{ApprovalFormRequest, ApprovalFormResult, ReviewValidator},
    prompt_blocking,
};

const MAX_REVIEW_REQUEST_BYTES: usize = 64 * 1024;
const MAX_REVIEW_RESULT_BYTES: usize = 16 * 1024;
const MAX_REVIEW_VALUE_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalReviewOutcome {
    Unavailable,
    Cancelled,
    Failed,
    Submitted(ApprovalFormResult),
}

/// Mutex serialising graphical prompts: only one prompt UI at a time.
static GRAPHICAL_LOCK: LazyLock<std::sync::Mutex<()>> = LazyLock::new(|| std::sync::Mutex::new(()));

/// Shows prompts to the user: the seam between settlement logic and the Qt
/// and zenity front ends. Calls block until the user answers.
pub trait Renderer: Send + Sync + 'static {
    /// Show the review form; the dialog keeps it open until `validate`
    /// accepts the submission.
    fn review(
        &self,
        request: &ApprovalFormRequest,
        validate: Option<&ReviewValidator>,
    ) -> ApprovalReviewOutcome;

    /// Ask the user to pick one of `options`; `None` when cancelled or no
    /// dialog is available.
    fn pick_option(&self, title: &str, options: &[&str]) -> Option<String>;

    /// Ask for free-form text; `None` when cancelled or no dialog is
    /// available.
    fn pick_text(&self, title: &str, default_text: &str) -> Option<String>;
}

/// The Qt dialog helper with a zenity fallback.
pub struct Graphical;

impl Renderer for Graphical {
    fn review(
        &self,
        request: &ApprovalFormRequest,
        validate: Option<&ReviewValidator>,
    ) -> ApprovalReviewOutcome {
        review_approval(request, validate)
    }

    fn pick_option(&self, title: &str, options: &[&str]) -> Option<String> {
        pick_option(title, options)
    }

    fn pick_text(&self, title: &str, default_text: &str) -> Option<String> {
        pick_text(title, default_text)
    }
}

/// Async access to a [`Renderer`]: each call runs on the blocking pool so a
/// waiting dialog never stalls the runtime.
#[derive(Clone)]
pub struct Dialogs<R: Renderer = Graphical> {
    renderer: Arc<R>,
}

impl<R: Renderer> Dialogs<R> {
    pub fn new(renderer: R) -> Self {
        Self {
            renderer: Arc::new(renderer),
        }
    }

    pub async fn review(
        &self,
        request: ApprovalFormRequest,
        validate: Option<ReviewValidator>,
    ) -> Result<ApprovalReviewOutcome, UiCliError> {
        let renderer = Arc::clone(&self.renderer);
        prompt_blocking(move || renderer.review(&request, validate.as_ref())).await
    }

    pub async fn pick_option(
        &self,
        title: &str,
        options: &[&str],
    ) -> Result<Option<String>, UiCliError> {
        let renderer = Arc::clone(&self.renderer);
        let title = title.to_owned();
        let options: Vec<String> = options.iter().map(|option| (*option).to_owned()).collect();

        prompt_blocking(move || {
            let options: Vec<&str> = options.iter().map(String::as_str).collect();
            renderer.pick_option(&title, &options)
        })
        .await
    }

    pub async fn pick_text(
        &self,
        title: &str,
        default_text: &str,
    ) -> Result<Option<String>, UiCliError> {
        let renderer = Arc::clone(&self.renderer);
        let title = title.to_owned();
        let default_text = default_text.to_owned();
        prompt_blocking(move || renderer.pick_text(&title, &default_text)).await
    }
}

fn pick_option(title: &str, options: &[&str]) -> Option<String> {
    if prefer_graphical() {
        if let Some(c) = pick_with_backends(title, options) {
            return Some(c);
        }

        info!("no graphical backend available; use agent-sandbox-approve");
    }

    None
}

/// Prompt for free-form text (e.g. an editable policy path). Returns the
/// trimmed user input on success.
fn pick_text(title: &str, default_text: &str) -> Option<String> {
    if prefer_graphical() {
        if let Some(c) = input_with_backends(title, default_text) {
            return Some(c);
        }

        info!("no graphical backend available; use agent-sandbox-approve");
    }

    None
}

fn prefer_graphical() -> bool {
    if std::env::var("AGENT_SANDBOX_UI_PREFER_GRAPHICAL").as_deref() == Ok("1") {
        return true;
    }

    std::env::var("WAYLAND_DISPLAY").is_ok() || std::env::var("DISPLAY").is_ok()
}

fn graphical_env() -> HashMap<String, String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    let uid = nix::unistd::getuid().as_raw();

    if uid > 0 {
        env.extend(graphical_session_env(uid, env.get("HOME").map(Path::new)));
    }

    env
}

fn pick_with_backends(title: &str, options: &[&str]) -> Option<String> {
    let env = graphical_env();

    match env.get("AGENT_SANDBOX_UI_BACKEND").map(String::as_str) {
        Some("qt-dialog") => {
            let binary = resolve_qt_dialog(&env)?;
            qt_dialog_select(&binary, title, options, &env)
        }

        Some("zenity") => {
            let binary = resolve_zenity(&env)?;
            zenity_select(&binary, title, options, &env)
        }

        Some("none") => None,

        Some(_) | None => {
            if let Some(binary) = resolve_qt_dialog(&env)
                && let Some(choice) = qt_dialog_select(&binary, title, options, &env)
            {
                return Some(choice);
            }
            if let Some(binary) = resolve_zenity(&env) {
                return zenity_select(&binary, title, options, &env);
            }
            None
        }
    }
}

fn input_with_backends(title: &str, default_text: &str) -> Option<String> {
    let env = graphical_env();

    match env.get("AGENT_SANDBOX_UI_BACKEND").map(String::as_str) {
        Some("qt-dialog") => {
            let binary = resolve_qt_dialog(&env)?;
            qt_dialog_input(&binary, title, default_text, &env)
        }

        Some("zenity") => {
            let binary = resolve_zenity(&env)?;
            zenity_input(&binary, title, default_text, &env)
        }

        Some("none") => None,

        Some(_) | None => {
            if let Some(binary) = resolve_qt_dialog(&env)
                && let Some(input) = qt_dialog_input(&binary, title, default_text, &env)
            {
                return Some(input);
            }
            if let Some(binary) = resolve_zenity(&env) {
                return zenity_input(&binary, title, default_text, &env);
            }
            None
        }
    }
}

fn review_approval(
    request: &ApprovalFormRequest,
    validate: Option<&ReviewValidator>,
) -> ApprovalReviewOutcome {
    if !prefer_graphical() {
        return ApprovalReviewOutcome::Unavailable;
    }

    let env = graphical_env();

    if matches!(
        env.get("AGENT_SANDBOX_UI_BACKEND").map(String::as_str),
        Some("zenity" | "none")
    ) {
        return ApprovalReviewOutcome::Unavailable;
    }

    let Some(binary) = resolve_qt_dialog(&env) else {
        return ApprovalReviewOutcome::Unavailable;
    };

    qt_dialog_review(&binary, request, &env, validate)
}

struct SpawnedQtDialog(Option<std::process::Child>);

impl SpawnedQtDialog {
    const fn child_mut(&mut self) -> Option<&mut std::process::Child> {
        self.0.as_mut()
    }

    fn wait_status(mut self) -> std::io::Result<std::process::ExitStatus> {
        let mut child = self.0.take().expect("dialog child present");
        drop(child.stdin.take());
        child.wait()
    }
}

impl Drop for SpawnedQtDialog {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            drop(child.stdin.take());
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn qt_dialog_review(
    binary: &str,
    request: &ApprovalFormRequest,
    env: &HashMap<String, String>,
    validate: Option<&ReviewValidator>,
) -> ApprovalReviewOutcome {
    let Ok(mut encoded) = serde_json::to_vec(&request.to_json()) else {
        return ApprovalReviewOutcome::Failed;
    };
    encoded.push(b'\n');

    if encoded.len() > MAX_REVIEW_REQUEST_BYTES {
        return ApprovalReviewOutcome::Failed;
    }

    let Ok(_lock) = GRAPHICAL_LOCK.lock() else {
        return ApprovalReviewOutcome::Failed;
    };

    let Ok(child) = Command::new(binary)
        .arg("--review")
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        return ApprovalReviewOutcome::Failed;
    };

    let mut dialog = SpawnedQtDialog(Some(child));
    let Some(child) = dialog.child_mut() else {
        return ApprovalReviewOutcome::Failed;
    };
    let Some(stdout) = child.stdout.take() else {
        return ApprovalReviewOutcome::Failed;
    };
    let Some(stdin) = child.stdin.as_mut() else {
        return ApprovalReviewOutcome::Failed;
    };
    if stdin.write_all(&encoded).is_err() || stdin.flush().is_err() {
        return ApprovalReviewOutcome::Failed;
    }
    let mut reader = std::io::BufReader::new(stdout);

    loop {
        let mut line = String::new();

        let Ok(read) = reader.read_line(&mut line) else {
            return ApprovalReviewOutcome::Failed;
        };
        if read == 0 {
            return match dialog.wait_status() {
                Ok(status) if status.success() => ApprovalReviewOutcome::Cancelled,
                Ok(_) | Err(_) => ApprovalReviewOutcome::Failed,
            };
        }

        let Some(result) = parse_review_result(line.as_bytes()) else {
            return ApprovalReviewOutcome::Failed;
        };

        let Some(stdin) = dialog.child_mut().and_then(|c| c.stdin.as_mut()) else {
            return ApprovalReviewOutcome::Failed;
        };

        // Cancel exits without validation. Deny with a persistent scope
        // still needs a valid target to create the deny rule.
        if result.action.is_none() {
            if writeln!(stdin, r#"{{"valid":true}}"#).is_err() || stdin.flush().is_err() {
                return ApprovalReviewOutcome::Failed;
            }
            return match dialog.wait_status() {
                Ok(status) if status.success() => ApprovalReviewOutcome::Submitted(result),
                Ok(_) | Err(_) => ApprovalReviewOutcome::Failed,
            };
        }

        if let Some(validator) = validate {
            match validator(&result) {
                Ok(()) => {
                    if writeln!(stdin, r#"{{"valid":true}}"#).is_err() || stdin.flush().is_err() {
                        return ApprovalReviewOutcome::Failed;
                    }
                    return match dialog.wait_status() {
                        Ok(status) if status.success() => ApprovalReviewOutcome::Submitted(result),
                        Ok(_) | Err(_) => ApprovalReviewOutcome::Failed,
                    };
                }

                Err(error) => {
                    let response = serde_json::json!({"valid": false, "error": error});
                    if writeln!(stdin, "{response}").is_err() || stdin.flush().is_err() {
                        return ApprovalReviewOutcome::Failed;
                    }
                }
            }
        } else {
            if writeln!(stdin, r#"{{"valid":true}}"#).is_err() || stdin.flush().is_err() {
                return ApprovalReviewOutcome::Failed;
            }
            return match dialog.wait_status() {
                Ok(status) if status.success() => ApprovalReviewOutcome::Submitted(result),
                Ok(_) | Err(_) => ApprovalReviewOutcome::Failed,
            };
        }
    }
}

fn parse_review_result(raw: &[u8]) -> Option<ApprovalFormResult> {
    if raw.len() > MAX_REVIEW_RESULT_BYTES {
        return None;
    }

    let value: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let object = value.as_object()?;

    let action = match object.get("action")?.as_str()? {
        "allow" => Some(super::options::PromptAction::Allow),
        "deny" => Some(super::options::PromptAction::Deny),
        "cancel" => None,
        _ => return None,
    };

    let scope = object.get("scope")?.as_str()?.parse().ok()?;
    let raw_values = object.get("values")?.as_object()?;

    if raw_values.len() > 16 {
        return None;
    }

    let mut values = HashMap::with_capacity(raw_values.len());

    for (key, value) in raw_values {
        let value = value.as_str()?;

        if key.is_empty()
            || key.len() > 64
            || value.len() > MAX_REVIEW_VALUE_BYTES
            || values.insert(key.clone(), value.to_owned()).is_some()
        {
            return None;
        }
    }

    Some(ApprovalFormResult {
        action,
        scope,
        values,
    })
}

fn resolve_qt_dialog(env: &HashMap<String, String>) -> Option<String> {
    if let Some(p) = env.get("AGENT_SANDBOX_QT_DIALOG") {
        let path = std::path::Path::new(p);

        if path.is_file() {
            return Some(p.clone());
        }
    }

    tool_path("AGENT_SANDBOX_QT_DIALOG", "agent-sandbox-qt-dialog")
}

fn run_graphical_dialog(
    binary: &str,
    args: &[String],
    env: &HashMap<String, String>,
) -> Option<String> {
    let _lock = GRAPHICAL_LOCK.lock().ok()?;

    let output = Command::new(binary)
        .args(args)
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;

    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
        .map(|raw| raw.trim().to_owned())
}

fn qt_dialog_select(
    binary: &str,
    title: &str,
    options: &[&str],
    env: &HashMap<String, String>,
) -> Option<String> {
    let mut args = vec![
        "--title".into(),
        "agent-sandbox".into(),
        "--text".into(),
        title.into(),
    ];

    for label in options {
        args.push("--option".into());
        args.push((*label).into());
    }

    let trimmed = run_graphical_dialog(binary, &args, env)?;
    options.contains(&trimmed.as_str()).then_some(trimmed)
}

fn qt_dialog_input(
    binary: &str,
    title: &str,
    default_text: &str,
    env: &HashMap<String, String>,
) -> Option<String> {
    let args = vec![
        "--title".into(),
        "agent-sandbox".into(),
        "--text".into(),
        title.into(),
        "--input".into(),
        default_text.into(),
    ];

    let trimmed = run_graphical_dialog(binary, &args, env)?;
    (!trimmed.is_empty()).then_some(trimmed)
}

fn resolve_zenity(env: &HashMap<String, String>) -> Option<String> {
    if let Some(p) = env.get("AGENT_SANDBOX_ZENITY") {
        let path = std::path::Path::new(p);

        if path.is_file() {
            return Some(p.clone());
        }
    }

    tool_path("AGENT_SANDBOX_ZENITY", "zenity")
}

fn zenity_select(
    binary: &str,
    title: &str,
    options: &[&str],
    env: &HashMap<String, String>,
) -> Option<String> {
    let mut args = vec![
        "--list".into(),
        "--title".into(),
        "agent-sandbox".into(),
        "--text".into(),
        title.into(),
        "--column".into(),
        "Options".into(),
    ];

    args.extend(options.iter().map(|option| (*option).into()));
    let trimmed = run_graphical_dialog(binary, &args, env)?;
    options.contains(&trimmed.as_str()).then_some(trimmed)
}

fn zenity_input(
    binary: &str,
    title: &str,
    default_text: &str,
    env: &HashMap<String, String>,
) -> Option<String> {
    let args = vec![
        "--entry".into(),
        "--title".into(),
        "agent-sandbox".into(),
        "--text".into(),
        title.into(),
        "--entry-text".into(),
        default_text.into(),
    ];

    let trimmed = run_graphical_dialog(binary, &args, env)?;
    (!trimmed.is_empty()).then_some(trimmed)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io::Write as _, os::unix::fs::PermissionsExt};

    use agent_sandbox_core::ApprovalScope;
    use tempfile::{NamedTempFile, TempPath};

    use super::{
        ApprovalFormRequest, ApprovalReviewOutcome, parse_review_result, qt_dialog_review,
    };
    use crate::ui::options::{ApprovalFormContext, ReviewValidator, scope_only_options};

    struct EofReviewHelper {
        executable: TempPath,
        pid_file: TempPath,
    }

    fn fake_review_helper() -> TempPath {
        let mut helper = NamedTempFile::new().expect("create fake review helper");

        helper
            .write_all(
                br#"#!/bin/sh
IFS= read -r request || exit 10
printf '%s\n' '{"action":"allow","scope":"project","values":{"target":"bad"}}'
IFS= read -r response || exit 11
if [ "$MODE" = "none" ]; then
    case "$response" in
        *'"valid":true'*) exit 0 ;;
        *) exit 12 ;;
    esac
fi
case "$response" in
    *'"valid":false'*) ;;
    *) exit 13 ;;
esac
printf '%s\n' '{"action":"allow","scope":"project","values":{"target":"good"}}'
IFS= read -r response || exit 14
case "$response" in
    *'"valid":true'*) exit 0 ;;
    *) exit 15 ;;
    esac
"#,
            )
            .expect("write fake review helper");

        let mut permissions = helper
            .as_file()
            .metadata()
            .expect("stat fake review helper")
            .permissions();

        permissions.set_mode(0o700);

        helper
            .as_file()
            .set_permissions(permissions)
            .expect("make fake review helper executable");

        helper.into_temp_path()
    }

    fn eof_review_helper() -> EofReviewHelper {
        let mut helper = NamedTempFile::new().expect("create EOF review helper");
        let pid_file = NamedTempFile::new().expect("create PID file");

        helper
            .write_all(
                br#"#!/bin/sh
IFS= read -r request || exit 10
printf '%s' "$$" > "$PID_FILE"
"#,
            )
            .expect("write EOF review helper");

        let mut permissions = helper
            .as_file()
            .metadata()
            .expect("stat EOF review helper")
            .permissions();

        permissions.set_mode(0o700);

        helper
            .as_file()
            .set_permissions(permissions)
            .expect("make EOF review helper executable");

        EofReviewHelper {
            executable: helper.into_temp_path(),
            pid_file: pid_file.into_temp_path(),
        }
    }

    fn review_request() -> ApprovalFormRequest {
        ApprovalFormRequest::new(
            "test review",
            Vec::<ApprovalFormContext>::new(),
            None,
            vec![ApprovalScope::Once, ApprovalScope::Project],
            Vec::new(),
        )
    }

    fn target_validator() -> ReviewValidator {
        Box::new(|result| {
            if result.values.get("target").map(String::as_str) == Some("good") {
                Ok(())
            } else {
                Err("target mismatch".into())
            }
        })
    }

    #[test]
    fn qt_dialog_review_retries_after_validation_error() {
        let helper = fake_review_helper();
        let mut env = HashMap::new();
        env.insert("MODE".into(), "multi".into());
        let request = review_request();

        let outcome = qt_dialog_review(
            helper.to_str().expect("helper path is UTF-8"),
            &request,
            &env,
            Some(&target_validator()),
        );
        let ApprovalReviewOutcome::Submitted(result) = outcome else {
            panic!("review helper should return corrected result, got {outcome:?}");
        };

        assert_eq!(result.values["target"], "good");
    }

    #[test]
    fn qt_dialog_review_acknowledges_without_validator() {
        let helper = fake_review_helper();
        let mut env = HashMap::new();
        env.insert("MODE".into(), "none".into());
        let request = review_request();

        let outcome = qt_dialog_review(
            helper.to_str().expect("helper path is UTF-8"),
            &request,
            &env,
            None,
        );
        let ApprovalReviewOutcome::Submitted(result) = outcome else {
            panic!("review helper should receive an automatic acknowledgement, got {outcome:?}");
        };

        assert_eq!(result.values["target"], "bad");
    }

    #[test]
    fn qt_dialog_review_reaps_helper_when_stdout_closes() {
        let helper = eof_review_helper();
        let mut env = HashMap::new();

        env.insert(
            "PID_FILE".into(),
            helper
                .pid_file
                .to_str()
                .expect("PID file path is UTF-8")
                .into(),
        );

        let outcome = qt_dialog_review(
            helper.executable.to_str().expect("helper path is UTF-8"),
            &review_request(),
            &env,
            None,
        );

        assert_eq!(outcome, ApprovalReviewOutcome::Cancelled);

        let pid = std::fs::read_to_string(&helper.pid_file)
            .expect("helper should write its PID")
            .parse::<u32>()
            .expect("helper PID should be numeric");

        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "helper process {pid} should be reaped"
        );
    }
    #[test]
    fn qt_dialog_review_reports_failed_when_helper_missing() {
        let outcome = qt_dialog_review(
            "/nonexistent/agent-sandbox-qt-dialog-helper",
            &review_request(),
            &HashMap::new(),
            None,
        );
        assert_eq!(outcome, ApprovalReviewOutcome::Failed);
    }

    #[test]
    fn review_result_parses_typed_values() {
        let result = parse_review_result(
            br#"{"action":"allow","scope":"project","values":{"method":"get_head","url":"https://example.com/a"}}"#,
        )
        .expect("valid review result");

        assert_eq!(result.action, Some(crate::ui::options::PromptAction::Allow));
        assert_eq!(result.scope, ApprovalScope::Project);
        assert_eq!(result.values["method"], "get_head");
    }

    #[test]
    fn review_result_rejects_unknown_action_scope_and_non_string_fields() {
        assert!(
            parse_review_result(br#"{"action":"approve","scope":"once","values":{}}"#).is_none()
        );

        assert!(
            parse_review_result(br#"{"action":"deny","scope":"forever","values":{}}"#).is_none()
        );

        assert!(
            parse_review_result(br#"{"action":"deny","scope":"once","values":{"target":42}}"#)
                .is_none()
        );
    }

    #[test]
    fn review_result_is_bounded() {
        let oversized = vec![b' '; super::MAX_REVIEW_RESULT_BYTES + 1];
        assert!(parse_review_result(&oversized).is_none());
    }

    #[test]
    fn review_request_carries_six_scope_ladder_with_once_first() {
        // Attributed session in a project: all six scopes in ladder order,
        // most specific first, with once first so the Qt helper's
        // first-item-must-be-once anchor preselects it.
        let scopes: Vec<ApprovalScope> = scope_only_options(true, true)
            .into_iter()
            .map(|option| option.scope)
            .collect();

        assert_eq!(
            scopes,
            vec![
                ApprovalScope::Once,
                ApprovalScope::Session,
                ApprovalScope::ProjectPackage,
                ApprovalScope::Project,
                ApprovalScope::GlobalPackage,
                ApprovalScope::Global,
            ],
            "once must be first (preselected), project_package between session and project, \
             global_package between project and global"
        );

        let request = ApprovalFormRequest::new("test review", Vec::new(), None, scopes, Vec::new());
        let json = request.to_json();
        let scopes_json = json["scopes"].as_array().expect("scopes array");

        let values: Vec<&str> = scopes_json
            .iter()
            .map(|scope| scope["value"].as_str().expect("scope value"))
            .collect();

        assert_eq!(values, vec![
            "once",
            "session",
            "project_package",
            "project",
            "global_package",
            "global"
        ]);

        assert_eq!(scopes_json[0]["label"], "Once");
        assert_eq!(scopes_json[2]["label"], "This project, this package");
        assert_eq!(scopes_json[4]["label"], "All projects, this package");
    }

    #[test]
    fn review_request_omits_package_scope_for_unattributed_session() {
        let scopes: Vec<ApprovalScope> = scope_only_options(true, false)
            .into_iter()
            .map(|option| option.scope)
            .collect();

        assert_eq!(scopes, vec![
            ApprovalScope::Once,
            ApprovalScope::Session,
            ApprovalScope::Project,
            ApprovalScope::Global,
        ]);
    }
}

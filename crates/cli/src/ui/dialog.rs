use std::{
    collections::HashMap,
    io::{BufRead, Write},
    path::Path,
    process::{Command, Stdio},
    sync::LazyLock,
};

use agent_sandbox_core::{graphical_session_env, tool_path};
use tracing::info;

use super::options::{
    ApprovalFormAction, ApprovalFormRequest, ApprovalFormResult, ReviewValidator,
    scope_from_form_value,
};

const MAX_REVIEW_REQUEST_BYTES: usize = 64 * 1024;
const MAX_REVIEW_RESULT_BYTES: usize = 16 * 1024;
const MAX_REVIEW_VALUE_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalReviewOutcome {
    Unavailable,
    Cancelled,
    Submitted(ApprovalFormResult),
}

/// Mutex serialising graphical prompts: only one prompt UI at a time.
static GRAPHICAL_LOCK: LazyLock<std::sync::Mutex<()>> = LazyLock::new(|| std::sync::Mutex::new(()));
trait PolicyUiBackend {
    fn select_option(&self, title: &str, options: &[&str]) -> Option<String>;
    fn input_text(&self, title: &str, default_text: &str) -> Option<String>;
}

struct QtDialogBackend<'a> {
    binary: String,
    env: &'a HashMap<String, String>,
}

impl PolicyUiBackend for QtDialogBackend<'_> {
    fn select_option(&self, title: &str, options: &[&str]) -> Option<String> {
        qt_dialog_select(&self.binary, title, options, self.env)
    }

    fn input_text(&self, title: &str, default_text: &str) -> Option<String> {
        qt_dialog_input(&self.binary, title, default_text, self.env)
    }
}

struct ZenityBackend<'a> {
    binary: String,
    env: &'a HashMap<String, String>,
}

impl PolicyUiBackend for ZenityBackend<'_> {
    fn select_option(&self, title: &str, options: &[&str]) -> Option<String> {
        zenity_select(&self.binary, title, options, self.env)
    }

    fn input_text(&self, title: &str, default_text: &str) -> Option<String> {
        zenity_input(&self.binary, title, default_text, self.env)
    }
}

pub fn pick_option(title: &str, options: &[&str]) -> Option<String> {
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
pub fn pick_text(title: &str, default_text: &str) -> Option<String> {
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

fn first_selected_option<'a>(
    backends: impl IntoIterator<Item = &'a dyn PolicyUiBackend>,
    title: &str,
    options: &[&str],
) -> Option<String> {
    backends
        .into_iter()
        .find_map(|backend| backend.select_option(title, options))
}

fn first_input_text<'a>(
    backends: impl IntoIterator<Item = &'a dyn PolicyUiBackend>,
    title: &str,
    default_text: &str,
) -> Option<String> {
    backends
        .into_iter()
        .find_map(|backend| backend.input_text(title, default_text))
}

fn graphical_env() -> HashMap<String, String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    let uid = nix::unistd::getuid().as_raw();
    if uid > 0 {
        env.extend(graphical_session_env(uid, env.get("HOME").map(Path::new)));
    }
    env
}

fn graphical_backends(env: &HashMap<String, String>) -> Vec<Box<dyn PolicyUiBackend + '_>> {
    match env.get("AGENT_SANDBOX_UI_BACKEND").map(String::as_str) {
        Some("qt-dialog") => resolve_qt_dialog(env)
            .map(|binary| {
                vec![Box::new(QtDialogBackend { binary, env }) as Box<dyn PolicyUiBackend + '_>]
            })
            .unwrap_or_default(),
        Some("zenity") => resolve_zenity(env)
            .map(|binary| {
                vec![Box::new(ZenityBackend { binary, env }) as Box<dyn PolicyUiBackend + '_>]
            })
            .unwrap_or_default(),
        Some("none") => Vec::new(),
        Some(_) | None => {
            let mut backends: Vec<Box<dyn PolicyUiBackend + '_>> = Vec::new();
            if let Some(binary) = resolve_qt_dialog(env) {
                backends.push(Box::new(QtDialogBackend { binary, env }));
            }
            if let Some(binary) = resolve_zenity(env) {
                backends.push(Box::new(ZenityBackend { binary, env }));
            }
            backends
        }
    }
}

fn pick_with_backends(title: &str, options: &[&str]) -> Option<String> {
    let env = graphical_env();
    let backends = graphical_backends(&env);
    first_selected_option(backends.iter().map(Box::as_ref), title, options)
}

fn input_with_backends(title: &str, default_text: &str) -> Option<String> {
    let env = graphical_env();
    let backends = graphical_backends(&env);
    first_input_text(backends.iter().map(Box::as_ref), title, default_text)
}
pub fn review_approval(
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
    qt_dialog_review(&binary, request, &env, validate).map_or(
        ApprovalReviewOutcome::Cancelled,
        ApprovalReviewOutcome::Submitted,
    )
}

fn qt_dialog_review(
    binary: &str,
    request: &ApprovalFormRequest,
    env: &HashMap<String, String>,
    validate: Option<&ReviewValidator>,
) -> Option<ApprovalFormResult> {
    let mut encoded = serde_json::to_vec(&request.to_json()).ok()?;
    encoded.push(b'\n');
    if encoded.len() > MAX_REVIEW_REQUEST_BYTES {
        return None;
    }

    let _lock = GRAPHICAL_LOCK.lock().ok()?;
    let mut child = Command::new(binary)
        .arg("--review")
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let stdin = child.stdin.as_mut()?;
    stdin.write_all(&encoded).ok()?;
    stdin.flush().ok()?;

    let stdout = child.stdout.take()?;
    let mut reader = std::io::BufReader::new(stdout);

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            let _ = child.wait();
            return None;
        }
        let result = parse_review_result(line.as_bytes())?;

        // Cancel exits without validation. Deny with a persistent scope
        // still needs a valid target to create the deny rule.
        if result.action == ApprovalFormAction::Cancel {
            if !child.wait().ok()?.success() {
                return None;
            }
            return Some(result);
        }

        if validate.is_none() {
            writeln!(stdin, r#"{{"valid":true}}"#).ok()?;
            stdin.flush().ok()?;
            if !child.wait().ok()?.success() {
                return None;
            }
            return Some(result);
        }
        let validator = validate?;

        match validator(&result) {
            Ok(()) => {
                writeln!(stdin, r#"{{"valid":true}}"#).ok()?;
                stdin.flush().ok()?;
                if !child.wait().ok()?.success() {
                    return None;
                }
                return Some(result);
            }
            Err(error) => {
                let response = serde_json::json!({"valid": false, "error": error});
                writeln!(stdin, "{response}").ok()?;
                stdin.flush().ok()?;
            }
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
        "allow" => ApprovalFormAction::Allow,
        "deny" => ApprovalFormAction::Deny,
        "cancel" => ApprovalFormAction::Cancel,
        _ => return None,
    };
    let scope = scope_from_form_value(object.get("scope")?.as_str()?)?;
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

fn qt_dialog_select(
    binary: &str,
    title: &str,
    options: &[&str],
    env: &HashMap<String, String>,
) -> Option<String> {
    let mut args = vec![
        binary.to_string(),
        "--title".into(),
        "agent-sandbox".into(),
        "--text".into(),
        title.to_string(),
    ];
    for label in options {
        args.push("--option".into());
        args.push((*label).to_string());
    }

    let _lock = GRAPHICAL_LOCK.lock().ok()?;
    let output = Command::new(&args[0])
        .args(&args[1..])
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if options.contains(&trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn qt_dialog_input(
    binary: &str,
    title: &str,
    default_text: &str,
    env: &HashMap<String, String>,
) -> Option<String> {
    let args = [
        binary,
        "--title",
        "agent-sandbox",
        "--text",
        title,
        "--input",
        default_text,
    ];

    let _lock = GRAPHICAL_LOCK.lock().ok()?;
    let output = Command::new(args[0])
        .args(&args[1..])
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
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
    // zenity --list --title "agent-sandbox" --text "..." --column "Options" <opt1>
    // <opt2> ...
    let mut args = vec![
        binary.to_string(),
        "--list".into(),
        "--title".into(),
        "agent-sandbox".into(),
        "--text".into(),
        title.to_string(),
        "--column".into(),
        "Options".into(),
    ];
    args.extend(options.iter().map(|s| (*s).to_string()));

    let _lock = GRAPHICAL_LOCK.lock().ok()?;
    let output = Command::new(&args[0])
        .args(&args[1..])
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if options.contains(&trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn zenity_input(
    binary: &str,
    title: &str,
    default_text: &str,
    env: &HashMap<String, String>,
) -> Option<String> {
    let args = [
        binary,
        "--entry",
        "--title",
        "agent-sandbox",
        "--text",
        title,
        "--entry-text",
        default_text,
    ];

    let _lock = GRAPHICAL_LOCK.lock().ok()?;
    let output = Command::new(args[0])
        .args(&args[1..])
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io::Write as _, os::unix::fs::PermissionsExt};

    use agent_sandbox_core::ApprovalScope;
    use tempfile::{NamedTempFile, TempPath};

    use super::{
        ApprovalFormRequest, PolicyUiBackend, first_input_text, first_selected_option,
        parse_review_result, qt_dialog_review,
    };
    use crate::ui::options::{ApprovalFormAction, ApprovalFormContext, ReviewValidator};

    struct EofReviewHelper {
        executable: TempPath,
        pid_file: TempPath,
    }

    struct FakeBackend {
        select_result: Option<String>,
        input_result: Option<String>,
    }

    impl PolicyUiBackend for FakeBackend {
        fn select_option(&self, _title: &str, _options: &[&str]) -> Option<String> {
            self.select_result.clone()
        }

        fn input_text(&self, _title: &str, _default_text: &str) -> Option<String> {
            self.input_result.clone()
        }
    }

    struct PanicSelectBackend;

    impl PolicyUiBackend for PanicSelectBackend {
        fn select_option(&self, _title: &str, _options: &[&str]) -> Option<String> {
            panic!("backend should not be called after first success");
        }

        fn input_text(&self, _title: &str, _default_text: &str) -> Option<String> {
            None
        }
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
        ApprovalFormRequest {
            summary: "test review".into(),
            context: Vec::<ApprovalFormContext>::new(),
            presentation: None,
            scopes: vec![ApprovalScope::Once, ApprovalScope::Project],
            fields: Vec::new(),
        }
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
        let result = qt_dialog_review(
            helper.to_str().expect("helper path is UTF-8"),
            &request,
            &env,
            Some(&target_validator()),
        )
        .expect("review helper should return corrected result");

        assert_eq!(result.values["target"], "good");
    }

    #[test]
    fn qt_dialog_review_acknowledges_without_validator() {
        let helper = fake_review_helper();
        let mut env = HashMap::new();
        env.insert("MODE".into(), "none".into());
        let request = review_request();
        let result = qt_dialog_review(
            helper.to_str().expect("helper path is UTF-8"),
            &request,
            &env,
            None,
        )
        .expect("review helper should receive an automatic acknowledgement");

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

        let result = qt_dialog_review(
            helper.executable.to_str().expect("helper path is UTF-8"),
            &review_request(),
            &env,
            None,
        );

        assert!(result.is_none());
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
    fn select_option_uses_first_successful_backend() {
        let a = FakeBackend {
            select_result: None,
            input_result: None,
        };
        let b = FakeBackend {
            select_result: Some("Allow once".to_string()),
            input_result: None,
        };
        let backends: [&dyn PolicyUiBackend; 2] = [&a, &b];

        let result = first_selected_option(backends, "title", &["Allow once"]);

        assert_eq!(result, Some("Allow once".to_string()));
    }

    #[test]
    fn input_text_uses_first_successful_backend() {
        let a = FakeBackend {
            select_result: None,
            input_result: None,
        };
        let b = FakeBackend {
            select_result: None,
            input_result: Some("./src".to_string()),
        };
        let backends: [&dyn PolicyUiBackend; 2] = [&a, &b];

        let result = first_input_text(backends, "title", "./");

        assert_eq!(result, Some("./src".to_string()));
    }

    #[test]
    fn select_option_stops_after_first_success() {
        let a = FakeBackend {
            select_result: Some("A".to_string()),
            input_result: None,
        };
        let b = PanicSelectBackend;
        let backends: [&dyn PolicyUiBackend; 2] = [&a, &b];

        let result = first_selected_option(backends, "title", &["A", "B"]);

        assert_eq!(result, Some("A".to_string()));
    }
    #[test]
    fn review_result_parses_typed_values() {
        let result = parse_review_result(
            br#"{"action":"allow","scope":"project","values":{"method":"get_head","url":"https://example.com/a"}}"#,
        )
        .expect("valid review result");

        assert_eq!(result.action, ApprovalFormAction::Allow);
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
}

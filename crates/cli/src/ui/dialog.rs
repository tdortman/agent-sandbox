use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::LazyLock;

use agent_sandbox_core::{graphical_session_env, tool_path};
use tracing::info;

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

/// Prompt for free-form text (e.g. an editable policy path). Returns the trimmed
/// user input on success.
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
    // zenity --list --title "agent-sandbox" --text "..." --column "Options" <opt1> <opt2> ...
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
    use super::{PolicyUiBackend, first_input_text, first_selected_option};

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
}

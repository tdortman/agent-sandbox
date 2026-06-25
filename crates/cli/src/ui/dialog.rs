use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::LazyLock;

use agent_sandbox_core::{graphical_session_env, tool_path};
use tracing::info;

/// Mutex serialising graphical prompts: only one prompt UI at a time.
static GRAPHICAL_LOCK: LazyLock<std::sync::Mutex<()>> = LazyLock::new(|| std::sync::Mutex::new(()));

pub(crate) fn pick_option(title: &str, options: &[&str]) -> Option<String> {
    if prefer_graphical() {
        if let Some(c) = graphical_select(title, options) {
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

/// Try each graphical backend in priority order. Returns the selected label on success.
/// If AGENT_SANDBOX_UI_BACKEND is set to a specific backend, only that backend
/// is tried. Unset or unrecognised values use the auto fallback: qt-dialog, zenity.
fn graphical_select(title: &str, options: &[&str]) -> Option<String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    let uid = nix::unistd::getuid().as_raw();
    if uid > 0 {
        env.extend(graphical_session_env(
            uid,
            env.get("HOME").map(String::as_str),
        ));
    }

    match env.get("AGENT_SANDBOX_UI_BACKEND").map(String::as_str) {
        Some("qt-dialog") => {
            let qt = resolve_qt_dialog(&env)?;
            return qt_dialog_select(&qt, title, options, &env);
        }
        Some("zenity") => {
            let z = resolve_zenity(&env)?;
            return zenity_select(&z, title, options, &env);
        }
        Some("none") => return None,
        Some(_) | None => {}
    }

    // No explicit backend, try in priority order.
    if let Some(qt_dialog) = resolve_qt_dialog(&env)
        && let Some(choice) = qt_dialog_select(&qt_dialog, title, options, &env)
    {
        return Some(choice);
    }

    if let Some(zenity) = resolve_zenity(&env)
        && let Some(choice) = zenity_select(&zenity, title, options, &env)
    {
        return Some(choice);
    }

    // No graphical backend available.
    None
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

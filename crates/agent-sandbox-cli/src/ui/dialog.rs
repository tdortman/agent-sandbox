use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::process::{Command, Stdio};
use std::sync::LazyLock;

use agent_sandbox_core::{graphical_session_env, tool_path};
use tracing::info;

static KDIALOG_LOCK: LazyLock<std::sync::Mutex<()>> = LazyLock::new(|| std::sync::Mutex::new(()));

pub(crate) fn pick_option(title: &str, options: &[&str]) -> Option<String> {
    if prefer_graphical() {
        if let Some(c) = graphical_select(title, options) {
            return Some(c);
        }
        info!("kdialog unavailable; trying /dev/tty");
    }
    tty_select(title, options).ok().flatten()
}

fn prefer_graphical() -> bool {
    if std::env::var("AGENT_SANDBOX_UI_PREFER_GRAPHICAL").as_deref() == Ok("1") {
        return true;
    }
    std::env::var("WAYLAND_DISPLAY").is_ok() || std::env::var("DISPLAY").is_ok()
}

fn graphical_select(title: &str, options: &[&str]) -> Option<String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    let uid = nix::unistd::getuid().as_raw();
    if uid > 0 {
        env.extend(graphical_session_env(
            uid,
            env.get("HOME").map(String::as_str),
        ));
    }
    let kdialog = resolve_kdialog(&env)?;
    let geometry = kdialog_menu_geometry(options.len());
    let mut args = vec![
        kdialog,
        "--title".into(),
        "agent-sandbox".into(),
        "--menu".into(),
        title.to_string(),
    ];
    if let Some(g) = geometry {
        args.push("--geometry".into());
        args.push(g);
    }
    for (i, label) in options.iter().enumerate() {
        args.push((i + 1).to_string());
        args.push((*label).to_string());
    }
    let out_file = tempfile::NamedTempFile::new().ok()?;
    let out_path = out_file.path().to_path_buf();
    let _lock = KDIALOG_LOCK.lock().ok()?;
    let status = Command::new(&args[0])
        .args(&args[1..])
        .envs(&env)
        .stdout(Stdio::from(std::fs::File::create(&out_path).ok()?))
        .stderr(Stdio::piped())
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    let raw = std::fs::read_to_string(out_path).ok()?;
    let num: usize = raw.trim().parse().ok()?;
    options.get(num.saturating_sub(1)).map(|s| (*s).to_string())
}

fn kdialog_menu_geometry(num_options: usize) -> Option<String> {
    if let Ok(explicit) = std::env::var("AGENT_SANDBOX_KDIALOG_GEOMETRY") {
        let explicit = explicit.trim();
        if !explicit.is_empty() {
            return Some(explicit.to_string());
        }
    }
    if num_options == 0 {
        return None;
    }
    let height = 110 + num_options * 34;
    Some(format!("580x{height}"))
}

fn resolve_kdialog(env: &HashMap<String, String>) -> Option<String> {
    if let Ok(explicit) = std::env::var("AGENT_SANDBOX_KDIALOG") {
        let p = std::path::Path::new(&explicit);
        if p.is_file() {
            return Some(explicit);
        }
    }
    if let Some(p) = env.get("AGENT_SANDBOX_KDIALOG") {
        return Some(p.clone());
    }
    tool_path("AGENT_SANDBOX_KDIALOG", "kdialog")
}

fn tty_select(title: &str, options: &[&str]) -> Result<Option<String>, ()> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| ())?;
    let lines: String = options
        .iter()
        .enumerate()
        .map(|(i, l)| format!("  {}) {l}", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    let mut tty_w = tty.try_clone().map_err(|_| ())?;
    write!(
        tty_w,
        "\n\x1b[1m{title}\x1b[0m\n{lines}\n\nChoice [1-{}], Enter=Deny: ",
        options.len()
    )
    .map_err(|_| ())?;
    let mut raw = String::new();
    std::io::BufReader::new(tty)
        .read_line(&mut raw)
        .map_err(|_| ())?;
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let num: usize = raw.parse().map_err(|_| ())?;
    Ok(options.get(num.saturating_sub(1)).map(|s| (*s).to_string()))
}

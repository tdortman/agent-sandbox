//! Environment for Qt/KDE dialogs spawned outside the user's shell.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

const PLASMA_COMM_NAMES: &[&str] = &["plasmashell", "kwin_wayland", "kwin_x11"];

const ENV_INHERIT: &[&str] = &[
    "PATH",
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_CURRENT_DESKTOP",
    "XDG_DATA_DIRS",
    "XDG_CONFIG_DIRS",
    "DESKTOP_SESSION",
    "KDE_FULL_SESSION",
    "KDE_SESSION_VERSION",
    "KDE_APPLICATIONS_AS_SCOPE",
    "QT_QPA_PLATFORM",
    "QT_QPA_PLATFORMTHEME",
    "QT_PLUGIN_PATH",
    "QML2_IMPORT_PATH",
    "QT_STYLE_OVERRIDE",
    "COLORSCHEME",
    "GTK_THEME",
    "GTK2_RC_FILES",
    "XDG_SESSION_TYPE",
    "XDG_SESSION_DESKTOP",
    "LD_LIBRARY_PATH",
];

pub type ToolPathFn = fn(&str, &str) -> Option<String>;

#[must_use]
pub fn tool_path(env_key: &str, binary: &str) -> Option<String> {
    if let Ok(explicit) = std::env::var(env_key) {
        let path = Path::new(&explicit);
        if path.is_file() && is_executable(path) {
            return Some(explicit);
        }
    }
    which::which(binary)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

fn environ_for_pid(pid: u32) -> HashMap<String, String> {
    let path = format!("/proc/{pid}/environ");
    let Ok(raw) = std::fs::read(&path) else {
        return HashMap::new();
    };
    let mut env = HashMap::new();
    for item in raw.split(|&b| b == 0) {
        if let Some(eq) = item.iter().position(|&b| b == b'=') {
            let (key, value) = item.split_at(eq);
            let value = &value[1..];
            if let (Ok(k), Ok(v)) = (std::str::from_utf8(key), std::str::from_utf8(value)) {
                env.insert(k.to_string(), v.to_string());
            }
        }
    }
    env
}

pub fn inherit_plasma_env(uid: u32) -> HashMap<String, String> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return HashMap::new();
    };
    let mut pids: Vec<u32> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
        .collect();
    pids.sort_unstable();

    for pid in pids {
        let Ok(meta) = std::fs::metadata(format!("/proc/{pid}")) else {
            continue;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != uid {
                continue;
            }
        }
        let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) else {
            continue;
        };
        let comm = comm.trim();
        if !PLASMA_COMM_NAMES.contains(&comm) {
            continue;
        }
        let proc_env = environ_for_pid(pid);
        return ENV_INHERIT
            .iter()
            .filter_map(|key| proc_env.get(*key).map(|v| ((*key).to_string(), v.clone())))
            .collect();
    }
    HashMap::new()
}

fn kde_session_defaults() -> HashMap<String, String> {
    HashMap::from([
        ("XDG_CURRENT_DESKTOP".into(), "KDE".into()),
        ("DESKTOP_SESSION".into(), "plasma".into()),
        ("KDE_FULL_SESSION".into(), "true".into()),
        ("QT_QPA_PLATFORMTHEME".into(), "kde".into()),
    ])
}

#[must_use]
pub fn x11_display_for_uid(uid: u32) -> Option<String> {
    let loginctl = tool_path("AGENT_SANDBOX_LOGINCTL", "loginctl")?;
    let output = Command::new(&loginctl)
        .args(["list-sessions", "--uid", &uid.to_string(), "--no-legend"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sessions = String::from_utf8_lossy(&output.stdout);
    for line in sessions.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 2 || !parts.contains(&"active") {
            continue;
        }
        let sid = parts[0];
        let display_out = Command::new(&loginctl)
            .args(["show-session", sid, "-pDisplay", "--value"])
            .output()
            .ok()?;
        if !display_out.status.success() {
            continue;
        }
        let display = String::from_utf8_lossy(&display_out.stdout)
            .trim()
            .to_string();
        if display.is_empty() {
            continue;
        }
        if display.chars().all(|c| c.is_ascii_digit()) {
            return Some(format!(":{display}"));
        }
        if display.starts_with(':') || display.contains('.') {
            return Some(display);
        }
        return Some(format!(":{display}"));
    }
    None
}

#[must_use]
pub fn kde_color_scheme_from_config(home: Option<&Path>) -> Option<String> {
    let home = home?;
    let paths = [
        home.join(".config").join("kdeglobals"),
        home.join(".config").join("kdedefaults").join("kdeglobals"),
    ];

    for path in paths {
        if let Ok(content) = std::fs::read_to_string(&path) {
            let mut in_general = false;
            for line in content.lines() {
                let line = line.trim();
                if line == "[General]" {
                    in_general = true;
                    continue;
                }
                if line.starts_with('[') && line.ends_with(']') {
                    in_general = false;
                    continue;
                }
                if in_general && let Some(scheme) = line.strip_prefix("ColorScheme=") {
                    let scheme = scheme.trim();
                    if !scheme.is_empty() {
                        return Some(scheme.to_string());
                    }
                }
            }
        }
    }
    None
}

#[must_use]
pub fn graphical_session_env(uid: u32, home: Option<&Path>) -> HashMap<String, String> {
    let mut env = kde_session_defaults();
    env.extend(inherit_plasma_env(uid));
    if !env.contains_key("COLORSCHEME")
        && let Some(scheme) = kde_color_scheme_from_config(home)
    {
        env.insert("COLORSCHEME".into(), scheme);
    }

    let runtime = format!("/run/user/{uid}");
    if !Path::new(&runtime).is_dir() {
        return env;
    }

    env.entry("XDG_RUNTIME_DIR".into())
        .or_insert_with(|| runtime.clone());

    if !env.contains_key("WAYLAND_DISPLAY") {
        for name in ["wayland-0", "wayland-1"] {
            if Path::new(&runtime).join(name).exists() {
                env.insert("WAYLAND_DISPLAY".into(), name.into());
                env.entry("QT_QPA_PLATFORM".into())
                    .or_insert_with(|| "wayland".into());
                break;
            }
        }
    }
    if !env.contains_key("WAYLAND_DISPLAY")
        && !env.contains_key("DISPLAY")
        && let Some(display) = x11_display_for_uid(uid)
    {
        env.insert("DISPLAY".into(), display);
        env.entry("QT_QPA_PLATFORM".into())
            .or_insert_with(|| "xcb".into());
    }
    env.entry("QT_QPA_PLATFORMTHEME".into())
        .or_insert_with(|| "kde".into());
    let bus = format!("{runtime}/bus");
    if Path::new(&bus).exists() {
        env.entry("DBUS_SESSION_BUS_ADDRESS".into())
            .or_insert_with(|| format!("unix:path={bus}"));
    }
    env.entry("PATH".into())
        .or_insert_with(|| "/run/current-system/sw/bin".into());
    env
}

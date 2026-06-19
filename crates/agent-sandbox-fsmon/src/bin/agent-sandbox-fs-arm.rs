//! Arm helper: runs inside the sandbox before the real agent.
//!
//! Connects to policyd, sends `StartFilesystemMonitor { ctx, static_allow }`,
//! waits for an active ok, then execvp the real command after `--`.

#![allow(unsafe_code)]

use agent_sandbox_core::{FileAccess, FilesystemRule, RequestContext};
use agent_sandbox_fsmon::rpc_client;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process;

fn expand_home_static_allow(static_allow: &mut [FilesystemRule], home: Option<&str>) {
    let Some(home) = home else {
        return;
    };
    for rule in static_allow {
        if let Some(rest) = rule.path.strip_prefix("~/") {
            rule.path = format!("{}/{}", home.trim_end_matches('/'), rest);
        } else if rule.path == "~" {
            home.clone_into(&mut rule.path);
        }
    }
}

fn add_project_static_allow(static_allow: &mut Vec<FilesystemRule>, project_root: Option<&str>) {
    if let Some(project_root) = project_root.map(str::trim).filter(|path| !path.is_empty()) {
        static_allow.push(FilesystemRule::new(
            project_root,
            FileAccess::All,
            "project",
        ));
    }
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();

    // Find the `--` separator; everything after is the real command.
    let sep_pos = args.iter().position(|a| a == "--");
    let real_args = if let Some(pos) = sep_pos {
        &args[pos + 1..]
    } else {
        eprintln!("usage: agent-sandbox-fs-arm [flags] -- <command> [args...]");
        process::exit(1);
    };

    if real_args.is_empty() {
        eprintln!("error: no command specified after --");
        process::exit(1);
    }

    // Gather context from environment (set by bubblewrap wrapper).
    let cwd = std::env::var("AGENT_SANDBOX_CWD").ok();
    let home = std::env::var("AGENT_SANDBOX_HOME").ok();
    let project_root = std::env::var("AGENT_SANDBOX_PROJECT_ROOT").ok();
    let socket_path = std::env::var("AGENT_SANDBOX_POLICY_SOCKET")
        .unwrap_or_else(|_| "/run/agent-sandbox/policy.sock".to_owned());

    let ctx = RequestContext {
        cwd: cwd.clone(),
        home: home.clone(),
        project_root,
        pid: None,
        uid: None,
    };

    // Parse static allow rules from environment (set by Nix wrapper).
    let mut static_allow: Vec<FilesystemRule> = std::env::var("AGENT_SANDBOX_FS_STATIC_ALLOW")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    expand_home_static_allow(&mut static_allow, home.as_deref());
    add_project_static_allow(&mut static_allow, project_root.as_deref());

    // Connect to policyd and request monitor startup.
    let reply = rpc_client::start_monitor(Path::new(&socket_path), ctx, static_allow)
        .unwrap_or_else(|e| {
            eprintln!("agent-sandbox-fs-arm: failed to start filesystem monitor: {e}");
            process::exit(1);
        });

    // SAFETY: fs-arm is still single-threaded here; removing private environment
    // keys before exec cannot race another Rust thread reading environment.
    unsafe {
        std::env::remove_var("AGENT_SANDBOX_FS_STATIC_ALLOW");
    }

    if !reply.active {
        eprintln!(
            "agent-sandbox-fs-arm: monitor did not activate: {}",
            reply.error.as_deref().unwrap_or("unknown error")
        );
        process::exit(1);
    }

    // Exec the real command.
    let cargs: Vec<CString> = real_args
        .iter()
        .map(|a| CString::new(a.as_os_str().as_bytes()).expect("arg contains null byte"))
        .collect();
    let mut argv: Vec<*const libc::c_char> = cargs.iter().map(|arg| arg.as_ptr()).collect();
    argv.push(std::ptr::null());

    // execvp replaces the process.
    unsafe {
        libc::execvp(cargs[0].as_ptr(), argv.as_ptr());
    }

    // If execvp returns, it failed.
    eprintln!(
        "agent-sandbox-fs-arm: execvp failed: {}",
        std::io::Error::last_os_error()
    );
    process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_home_static_allow_rules() {
        let mut rules = vec![
            FilesystemRule::new("~/dotfiles", FileAccess::Read, ""),
            FilesystemRule::new("~", FileAccess::Read, ""),
        ];

        expand_home_static_allow(&mut rules, Some("/home/user"));

        assert_eq!(rules[0].path, "/home/user/dotfiles");
        assert_eq!(rules[1].path, "/home/user");
    }

    #[test]
    fn adds_project_root_as_full_static_allow() {
        let mut rules = vec![FilesystemRule::new("/home/user/.omp", FileAccess::Read, "")];

        add_project_static_allow(&mut rules, Some("/home/user/project"));

        assert!(
            rules.iter().any(|rule| {
                rule.path == "/home/user/project" && rule.access == FileAccess::All
            })
        );
    }
}

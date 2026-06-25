//! Arm helper: runs inside the sandbox before the real agent.
//!
//! Connects to policyd, sends `StartFilesystemMonitor { ctx, static_allow }`,
//! waits for an active ok, then execvp the real command. A `--` separator
//! before the command is accepted but not required.
#![allow(unsafe_code)]

use agent_sandbox_core::{FileAccess, FilesystemRule, RequestContext};
use agent_sandbox_fsmon::rpc_client;
use clap::Parser as _;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process;

#[derive(clap::Parser, Debug)]
#[command(
    name = "agent-sandbox-fs-arm",
    version,
    about = "Connect to policyd, start the fanotify filesystem monitor, then execvp the real command",
    long_about = "Runs INSIDE the sandbox as the first process in the dynamic-FS path. Connects \
        to policyd over the policy socket, registers a fanotify filesystem monitor for the \
        current sandbox session, then execvp the real command. The policy socket path comes \
        from the env var AGENT_SANDBOX_POLICY_SOCKET (default /run/agent-sandbox/policy.sock). \
        The session id, working directory, home, and project root come from \
        AGENT_SANDBOX_SESSION_ID, AGENT_SANDBOX_CWD, AGENT_SANDBOX_HOME, and \
        AGENT_SANDBOX_PROJECT_ROOT respectively. The static allow rule set is read from \
        AGENT_SANDBOX_FS_STATIC_ALLOW as a JSON array of FilesystemRule objects.\n\n\
    EXAMPLES:\n\
        # Start the monitor, then exec python3. The `--` is optional.\n\
        agent-sandbox-fs-arm /usr/bin/python3 -i\n\n\
        # Start the monitor, then exec a wrapped agent.\n\
        agent-sandbox-fs-arm /home/user/bin/my-agent --verbose"
)]
struct Cli {
    /// The command to exec after the monitor is active. Everything after the flags is forwarded verbatim to execvp, including values that look like flags. A `--` separator is accepted but not required.
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    command: Vec<OsString>,
}

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
    let cli = Cli::parse();
    let real_args = cli.command;

    // Gather context from environment (set by bubblewrap wrapper).
    let cwd = std::env::var("AGENT_SANDBOX_CWD").ok();
    let home = std::env::var("AGENT_SANDBOX_HOME").ok();
    let project_root = std::env::var("AGENT_SANDBOX_PROJECT_ROOT").ok();
    let sandbox_session_id = std::env::var("AGENT_SANDBOX_SESSION_ID").ok();
    let socket_path = std::env::var("AGENT_SANDBOX_POLICY_SOCKET")
        .unwrap_or_else(|_| "/run/agent-sandbox/policy.sock".to_owned());

    let ctx = RequestContext {
        cwd,
        home: home.clone(),
        project_root: project_root.clone(),
        pid: None,
        uid: None,
        sandbox_session_id,
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

    // SAFETY: fs-arm is still single-threaded here. Removing private environment
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
    // Reserved for future integration tests. The current implementation reads
    // the policy socket from the environment, which is awkward to set up in a
    // pure unit test, and the entrypoint is exercised end-to-end by the
    // NixOS integration test harness.
}

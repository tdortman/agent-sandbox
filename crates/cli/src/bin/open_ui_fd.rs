//! Pre-register a policy UI connection on the host policy socket, then exec a
//! launcher command.
//!
//! **Security constraint:** the approval-capable UI socket and session id must
//! never be passed into the sandboxed agent process. A prior version exported
//! `AGENT_SANDBOX_UI_FD` / `AGENT_SANDBOX_UI_SESSION_ID` through bwrap `--setenv`,
//! which let any in-jail process approve pending root elevations. This binary
//! no longer injects those variables; use a host-side `agent-sandbox-ui` process
//! (or a future sibling-process holder) for approvals instead.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process;

use agent_sandbox_core::{RequestContext, RpcRequest};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-open-ui-fd")]
struct Cli {
    #[arg(long)]
    socket: PathBuf,

    #[arg(long)]
    cwd: PathBuf,

    #[arg(long)]
    home: PathBuf,

    #[arg(long)]
    project_root: Option<PathBuf>,

    #[arg(long)]
    sandbox_session_id: String,

    /// Everything after "--" is the launcher command.
    #[arg(last = true)]
    launcher: Vec<String>,
}

fn die(msg: &str, err: &io::Error) -> ! {
    eprintln!("agent-sandbox-open-ui-fd: {msg}: {err}");
    process::exit(1);
}

fn fatal(msg: &str) -> ! {
    eprintln!("agent-sandbox-open-ui-fd: {msg}");
    process::exit(1);
}

fn cstring(s: impl AsRef<[u8]>) -> CString {
    CString::new(s.as_ref()).expect("interior NUL in argv token")
}

/// Build the child argv from launcher args, inserting only the sandbox session
/// id before the bwrap `--` command separator. Approval fds are not exported.
fn build_child_args(args: &[String], sandbox_session_id: &str) -> Option<Vec<CString>> {
    let bwrap_sep = args.iter().position(|a| a == "--")?;
    let mut v: Vec<CString> = args[..bwrap_sep]
        .iter()
        .map(|s| cstring(s.as_bytes()))
        .collect();
    v.push(cstring("--setenv"));
    v.push(cstring("AGENT_SANDBOX_SESSION_ID"));
    v.push(cstring(sandbox_session_id.as_bytes()));
    v.push(cstring("--"));
    for s in &args[(bwrap_sep + 1)..] {
        v.push(cstring(s.as_bytes()));
    }
    Some(v)
}

fn exec_cstrings(args: &[CString]) -> ! {
    match nix::unistd::execvp(
        args[0].as_c_str(),
        &args.iter().map(CString::as_c_str).collect::<Vec<_>>(),
    ) {
        Err(err) => die("execvp", &io::Error::from(err)),
        Ok(infallible) => match infallible {},
    }
}

fn exec_child(args: &[String], sandbox_session_id: &str) -> ! {
    build_child_args(args, sandbox_session_id).map_or_else(
        || {
            agent_sandbox_sysutil::pre_exec_set_var("AGENT_SANDBOX_SESSION_ID", sandbox_session_id);
            let child_args: Vec<CString> = args.iter().map(|s| cstring(s.as_bytes())).collect();
            exec_cstrings(&child_args);
        },
        |child_args| {
            exec_cstrings(&child_args);
        },
    )
}

fn main() {
    let cli = Cli::parse();

    let launcher = cli.launcher;
    let launcher_args = if launcher.first().is_some_and(|arg| arg == "--") {
        &launcher[1..]
    } else {
        &launcher[..]
    };
    if launcher_args.is_empty() {
        fatal("missing launcher command after --");
    }

    // 1. Connect to host policy socket.
    let stream =
        UnixStream::connect(&cli.socket).unwrap_or_else(|e| die("connect host socket", &e));

    // 2. Send RegisterUi JSON line.
    let register = RpcRequest::RegisterUi {
        ui_client: Some("standalone".into()),
        ctx: RequestContext {
            cwd: Some(cli.cwd),
            home: Some(cli.home),
            project_root: cli.project_root,
            pid: None,
            uid: None,
            sandbox_session_id: Some(cli.sandbox_session_id.clone()),
        },
    };
    let line = serde_json::to_string(&register).expect("serialize RegisterUi") + "\n";
    let mut stream = stream;
    stream
        .write_all(line.as_bytes())
        .unwrap_or_else(|e| die("write RegisterUi", &e));

    // 3. Read exactly one response line byte-by-byte (no BufReader — RegisterUi
    //    may trigger pending UiPush lines and over-reading would drop them).
    let mut resp_buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .unwrap_or_else(|e| die("read response", &e));
        resp_buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    let resp_line = String::from_utf8(resp_buf).unwrap_or_else(|_| fatal("non-UTF8 response"));

    // 4. Parse the response; require RegisterUi reply with ok == true.
    let reply: serde_json::Value =
        serde_json::from_str(&resp_line).unwrap_or_else(|_| fatal("invalid JSON response"));
    let ok = reply["ok"].as_bool().unwrap_or(false);

    if !ok {
        let err = reply["error"].as_str().unwrap_or("unknown error");
        fatal(&format!("UI registration failed: {err}"));
    }

    // 5. Hold the registered connection only in this process until exec replaces
    //    it. Do not pass the approval fd into the sandboxed agent.
    drop(stream);

    // 6. Build child argv and exec without approval-capable env vars.
    exec_child(launcher_args, &cli.sandbox_session_id);
}

#[cfg(test)]
mod tests {
    use super::build_child_args;

    #[test]
    fn inserts_session_id_before_bwrap_separator_without_ui_fd() {
        let args: Vec<String> = [
            "bwrap",
            "--bind",
            "/",
            "/",
            "--clearenv",
            "--",
            "/bin/sh",
            "-c",
            "echo hi",
        ]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
        let result = build_child_args(&args, "sandbox-sid-abc").expect("should have -- separator");
        let strs: Vec<String> = result
            .iter()
            .map(|c| c.to_str().expect("valid utf-8 argv token").to_string())
            .collect();

        assert!(!strs.contains(&"AGENT_SANDBOX_UI_FD".to_string()));
        assert!(!strs.contains(&"AGENT_SANDBOX_UI_SESSION_ID".to_string()));
        assert!(strs.contains(&"AGENT_SANDBOX_SESSION_ID".to_string()));
        assert!(strs.contains(&"sandbox-sid-abc".to_string()));

        let setenv_pos = strs
            .iter()
            .position(|s| s == "--setenv")
            .expect("--setenv in argv");
        let cmd_sep = strs
            .windows(2)
            .position(|w| w[0] == "--" && w[1] == "/bin/sh")
            .expect("command -- separator");
        assert!(
            setenv_pos < cmd_sep,
            "--setenv must be before command -- separator"
        );
    }

    #[test]
    fn no_separator_returns_none() {
        let args: Vec<String> = ["/bin/sh", "-c", "echo hi"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert!(build_child_args(&args, "ssid").is_none());
    }
}

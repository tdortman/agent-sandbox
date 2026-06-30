#![allow(unsafe_code)]

//! Pre-register a policy UI connection on the host policy socket, then
//! exec the sandbox launcher with the connected stream on a
//! kernel-assigned fd communicated via `AGENT_SANDBOX_UI_FD`.
//!
//! The inherited fd is the ONLY approval path into the sandbox.  Future sandbox
//! socket connections cannot register UI or approve.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
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

/// Build the child argv from launcher args, inserting --sync-fd and --setenv
/// lines before the bwrap `--` command separator so the policy UI client
/// receives the inherited stream. When no `--` separator is present, returns
/// None (caller sets env vars).
fn build_child_args(
    args: &[String],
    ui_fd: libc::c_int,
    session_id: &str,
    sandbox_session_id: &str,
) -> Option<Vec<CString>> {
    let bwrap_sep = args.iter().position(|a| a == "--")?;
    let mut v: Vec<CString> = args[..bwrap_sep]
        .iter()
        .map(|s| cstring(s.as_bytes()))
        .collect();
    v.push(cstring("--sync-fd"));
    v.push(cstring(ui_fd.to_string()));
    v.push(cstring("--setenv"));
    v.push(cstring("AGENT_SANDBOX_UI_FD"));
    v.push(cstring(ui_fd.to_string()));
    v.push(cstring("--setenv"));
    v.push(cstring("AGENT_SANDBOX_UI_SESSION_ID"));
    v.push(cstring(session_id.as_bytes()));
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
    let mut exec_argv: Vec<*const libc::c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
    exec_argv.push(std::ptr::null());
    // SAFETY: argv is null-terminated and points at live CString storage.
    unsafe {
        libc::execvp(exec_argv[0], exec_argv.as_ptr());
    }
    die("execvp", &io::Error::last_os_error());
}

fn exec_child(
    args: &[String],
    ui_fd: libc::c_int,
    session_id: &str,
    sandbox_session_id: &str,
) -> ! {
    build_child_args(args, ui_fd, session_id, sandbox_session_id).map_or_else(
        || {
            // No bwrap separator. Set env vars in current process before exec.
            // SAFETY: single-threaded, about to exec.
            unsafe {
                std::env::set_var("AGENT_SANDBOX_UI_FD", ui_fd.to_string());
                std::env::set_var("AGENT_SANDBOX_UI_SESSION_ID", session_id);
                std::env::set_var("AGENT_SANDBOX_SESSION_ID", sandbox_session_id);
            }
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
    let session_id = reply["session_id"].as_str().map(String::from);

    if !ok {
        let err = reply["error"].as_str().unwrap_or("unknown error");
        fatal(&format!("UI registration failed: {err}"));
    }

    let session_id = session_id.unwrap_or_else(|| fatal("no session_id in RegisterUi reply"));

    // 5. Duplicate the connected stream to a kernel-assigned fd ≥ 3.
    //    Using F_DUPFD_CLOEXEC gives us a fresh fd with CLOEXEC set;
    //    we then clear CLOEXEC so it survives exec → bwrap → the UI client.
    // SAFETY: fcntl F_DUPFD_CLOEXEC on a valid fd.
    let ui_fd = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if ui_fd < 0 {
        die("fcntl F_DUPFD_CLOEXEC", &io::Error::last_os_error());
    }
    // Close the original; ui_fd now owns the connection.
    drop(stream);

    // 6. Clear FD_CLOEXEC so the fd survives exec.
    //    The UI client must clear CLOEXEC on the wrapped socket after receiving the fd.
    // SAFETY: fcntl F_GETFD / F_SETFD on a valid fd.
    let flags = unsafe { libc::fcntl(ui_fd, libc::F_GETFD) };
    if flags < 0 {
        die("fcntl F_GETFD", &io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(ui_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        die("fcntl F_SETFD", &io::Error::last_os_error());
    }

    // 7. Build child argv and exec.
    exec_child(launcher_args, ui_fd, &session_id, &cli.sandbox_session_id);
}

#[cfg(test)]
mod tests {
    use super::build_child_args;

    #[test]
    fn inserts_env_before_bwrap_separator() {
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
        let result = build_child_args(&args, 7, "sid-abc", "sandbox-sid-abc")
            .expect("should have -- separator");
        let strs: Vec<String> = result
            .iter()
            .map(|c| c.to_str().expect("valid utf-8 argv token").to_string())
            .collect();

        assert!(strs.contains(&"--setenv".to_string()));
        assert!(strs.contains(&"AGENT_SANDBOX_UI_FD".to_string()));
        assert!(strs.contains(&"7".to_string()));
        assert!(strs.contains(&"AGENT_SANDBOX_UI_SESSION_ID".to_string()));
        assert!(strs.contains(&"sid-abc".to_string()));
        assert!(strs.contains(&"AGENT_SANDBOX_SESSION_ID".to_string()));
        assert!(strs.contains(&"sandbox-sid-abc".to_string()));

        let sync_pos = strs
            .iter()
            .position(|s| s == "--sync-fd")
            .expect("--sync-fd in argv");
        assert_eq!(strs.get(sync_pos + 1).map(String::as_str), Some("7"));

        // bwrap options must appear before the command separator.
        let cmd_sep = strs
            .windows(2)
            .position(|w| w[0] == "--" && w[1] == "/bin/sh");
        assert!(cmd_sep.is_some(), "command -- separator not found");
        let cmd_sep = cmd_sep.expect("command -- separator");
        let setenv_pos = strs
            .iter()
            .position(|s| s == "--setenv")
            .expect("--setenv in argv");
        assert!(
            sync_pos < cmd_sep,
            "--sync-fd must be before command -- separator"
        );
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
        assert!(build_child_args(&args, 7, "sid", "ssid").is_none());
    }
}

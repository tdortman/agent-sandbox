//! Black-box contract tests for the `agent-sandbox-syscall-arm` binary.
//!
//! Exercises the CLI end to end via `CARGO_BIN_EXE_` to lock down its
//! argument handling and exit behaviour without holding a sandbox open.
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agent-sandbox-syscall-arm"))
        .args(args)
        .output()
        .expect("syscall-arm should start")
}

#[test]
fn help_describes_forwarded_command_without_installing_filter() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: agent-sandbox-syscall-arm [OPTIONS] [COMMAND]..."));
    assert!(stdout.contains("--filesystem"));
    assert!(stdout.contains("Everything after the flags is forwarded verbatim"));
    assert!(stdout.contains("AGENT_SANDBOX_POLICY_SOCKET"));
}

#[test]
fn missing_command_reports_usage_before_seccomp_setup() {
    let output = run(&[]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("agent-sandbox-syscall-arm: missing command"));
    assert!(stderr.contains("USAGE:"));
}

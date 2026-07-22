use std::process::Command;

fn run(binary: &str, args: &[&str]) -> std::process::Output {
    Command::new(binary)
        .args(args)
        .output()
        .expect("binary should start")
}

#[test]
fn elevate_without_command_reports_usage_without_contacting_policyd() {
    let output = run(env!("CARGO_BIN_EXE_agent-sandbox-elevate"), &[]);

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("agent-sandbox: usage: sudo <command>"));
}

#[test]
fn approve_rejects_unknown_subcommand() {
    let output = run(env!("CARGO_BIN_EXE_agent-sandbox-approve"), &[
        "not-a-command",
    ]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error: unrecognized subcommand 'not-a-command'"));
    assert!(stderr.contains("Usage: agent-sandbox-approve"));
}

#[test]
fn ui_help_describes_context_options() {
    let output = run(env!("CARGO_BIN_EXE_agent-sandbox-ui"), &["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: agent-sandbox-ui [OPTIONS]"));
    assert!(stdout.contains("--sandbox-session-id <ID>"));
    assert!(stdout.contains("--project-root <DIR>"));
}

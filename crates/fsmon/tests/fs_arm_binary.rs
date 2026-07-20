use std::process::Command;

#[test]
fn help_describes_command_and_policy_environment() {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-sandbox-fs-arm"))
        .arg("--help")
        .output()
        .expect("start fs-arm help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("agent-sandbox-fs-arm"));
    assert!(stdout.contains("AGENT_SANDBOX_POLICY_SOCKET"));
    assert!(stdout.contains("COMMAND"));
}

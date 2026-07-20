use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agent-sandbox-nfq"))
        .args(args)
        .output()
        .expect("NFQUEUE daemon should start")
}

#[test]
fn help_exposes_policy_and_queue_configuration() {
    let output = run(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: agent-sandbox-nfq [OPTIONS]"));
    assert!(stdout.contains("--policy-socket <SOCKET>"));
    assert!(stdout.contains("--queue-len <PACKETS>"));
    assert!(stdout.contains("--proxy-mode"));
}

#[test]
fn invalid_queue_number_is_rejected_before_opening_nfqueue() {
    let output = run(&["--queue", "not-a-number"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid value 'not-a-number'"));
    assert!(stderr.contains("--queue <NUM>"));
}

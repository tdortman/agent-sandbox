use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agent-sandbox-dns-forwarder"))
        .args(args)
        .output()
        .expect("DNS forwarder should start")
}

#[test]
fn help_exposes_forwarder_configuration() {
    let output = run(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: agent-sandbox-dns-forwarder [OPTIONS]"));
    assert!(stdout.contains("--listen-port <LISTEN_PORT>"));
    assert!(stdout.contains("--forward-target <FORWARD_TARGET>"));
    assert!(stdout.contains("--cache-client-ip <CACHE_CLIENT_IP>"));
}

#[test]
fn invalid_port_is_rejected_before_starting_listeners() {
    let output = run(&["--listen-port", "not-a-port"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid value 'not-a-port'"));
    assert!(stderr.contains("--listen-port <LISTEN_PORT>"));
}

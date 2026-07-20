use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agent-sandbox-enter"))
        .args(args)
        .output()
        .expect("enter wrapper should start")
}

#[test]
fn help_describes_namespace_and_forwarded_command() {
    let output = run(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: agent-sandbox-enter <NETNS> [COMMAND]..."));
    assert!(stdout.contains("Name of the network namespace"));
    assert!(stdout.contains("Everything after the netns name is forwarded verbatim"));
}

#[test]
fn missing_namespace_is_rejected_without_touching_namespace_state() {
    let output = run(&[]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("the following required arguments were not provided"));
    assert!(stderr.contains("<NETNS>"));
}

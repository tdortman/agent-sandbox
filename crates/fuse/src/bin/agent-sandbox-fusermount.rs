//! `fusermount3` stand-in for sandboxes: asks policyd to mount and unmount.

fn main() -> std::process::ExitCode {
    agent_sandbox_fuse::fusermount::run(std::env::args_os())
}

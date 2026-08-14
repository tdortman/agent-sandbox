//! Entry point for the privileged elevation helper.
//!
//! Delegates to `agent_sandbox_cli::elevate::run`, which performs the
//! privileged policy-store operations on behalf of an unprivileged caller.
#[tokio::main]
async fn main() -> Result<(), agent_sandbox_cli::elevate::ElevateCliError> {
    agent_sandbox_cli::elevate::run().await
}

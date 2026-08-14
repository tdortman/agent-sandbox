//! Entry point for the interactive approval UI.
//!
//! Delegates to `agent_sandbox_cli::approve::run`, which connects to policyd
//! and renders permission prompts.
#[tokio::main]
async fn main() -> Result<(), agent_sandbox_cli::approve::ApproveCliError> {
    agent_sandbox_cli::approve::run().await
}

#[tokio::main]
async fn main() -> Result<(), agent_sandbox_cli::approve::ApproveCliError> {
    agent_sandbox_cli::approve::run().await
}

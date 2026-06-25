#[tokio::main]
async fn main() -> Result<(), agent_sandbox_cli::elevate::ElevateCliError> {
    agent_sandbox_cli::elevate::run().await
}

#[tokio::main]
async fn main() -> Result<(), agent_sandbox_cli::ui::UiCliError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agent_sandbox_ui=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();

    agent_sandbox_cli::ui::run().await
}

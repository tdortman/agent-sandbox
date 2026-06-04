use agent_sandbox_core::RpcClientError;

#[derive(Debug, thiserror::Error)]
pub enum UiCliError {
    #[error("{0}")]
    Register(String),
    #[error(transparent)]
    Rpc(#[from] RpcClientError),
}

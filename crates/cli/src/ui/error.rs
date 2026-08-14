use agent_sandbox_core::RpcClientError;

/// Errors produced by the long-lived UI client.
#[derive(Debug, thiserror::Error)]
pub enum UiCliError {
    /// A general UI client error with the given message.
    #[error("{0}")]
    Register(String),

    /// An error from the underlying RPC client.
    #[error(transparent)]
    Rpc(#[from] RpcClientError),
}

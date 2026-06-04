use agent_sandbox_core::RpcClientError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProxyClientError {
    #[error(transparent)]
    Rpc(#[from] RpcClientError),
    #[error("client closed")]
    Closed,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

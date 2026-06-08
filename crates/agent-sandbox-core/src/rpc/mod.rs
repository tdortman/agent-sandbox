//! JSON-line RPC types for policyd (OMP extension and CLIs depend on these shapes).

mod message;
mod push;
mod reply;
mod request;
mod scope;

#[cfg(test)]
mod tests;

pub use message::RpcMessage;
pub use push::{PendingSummary, UiPush};
pub use reply::{
    CheckReply, ElevateReply, ErrorReply, RegisterUiReply, RpcReply, ScopeActionReply,
    SimpleOkReply, StatusReply,
};
pub use request::{ApprovalTarget, RequestContext, RpcRequest};
pub use scope::ApprovalScope;

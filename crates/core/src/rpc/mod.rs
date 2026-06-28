//! JSON-line RPC types for policyd (UI clients and CLIs depend on these shapes).

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
    CheckReply, ElevateReply, ErrorReply, FilesystemCheckReply, FilesystemMonitorReply,
    FilesystemScopeActionReply, RegisterUiReply, RpcReply, ScopeActionReply, SimpleOkReply,
    StatusReply,
};
pub use request::{
    AliasSplit, ApprovalTarget, RequestContext, RpcRequest, attach_check_aliases,
    attach_ui_aliases, split_check_aliases, split_ui_aliases,
};
pub use scope::ApprovalScope;

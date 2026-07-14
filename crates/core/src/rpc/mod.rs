//! JSON-line RPC types for policyd (UI clients and CLIs depend on these shapes).

mod message;
mod proxy;
mod push;
mod reply;
mod request;
mod scope;

#[cfg(test)]
mod tests;

pub use message::RpcMessage;
pub use proxy::{
    AttributionToken, FlowContext, FlowProtocol, FlowRegistration, HttpApprovalRequest,
    HttpCheckRequest, NetworkFlowKey, NormalizedPolicyHost, ProcessIdentity, ProcessStartTimeTicks,
    ProxyConnectionId, ProxyRequestId, ProxySessionToken, SocketIdentity, SocketInode,
};
pub use push::{PendingSummary, UiPush};
pub use reply::{
    CheckReply, ElevateReply, ErrorReply, FilesystemCheckReply, FilesystemMonitorReply,
    FilesystemScopeActionReply, FlowClaimReply, HttpCheckReply, HttpScopeActionReply,
    NetworkFlowCheckReply, ProxyReply, ProxyReplyBody, ProxySessionReply, RegisterUiReply,
    ResourceCheckReply, ResourceScopeActionReply, RpcReply, ScopeActionReply, SimpleOkReply,
    StatusReply, Verdict, VerdictSource,
};
pub use request::{
    AliasSplit, ApprovalTarget, RequestContext, RpcRequest, attach_check_aliases,
    attach_ui_aliases, split_check_aliases, split_ui_aliases,
};
pub use scope::ApprovalScope;

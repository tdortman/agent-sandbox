//! JSON-line RPC types for policyd (UI clients and CLIs depend on these
//! shapes).

mod message;

mod proxy;
mod push;
mod reply;
mod request;
mod scope;

#[cfg(test)]
mod tests;

pub use message::{Heartbeat, RpcMessage};
pub use proxy::{
    AttributionToken, FlowContext, FlowRegistration, NetworkFlowKey, NetworkFlowSelector,
    NormalizedPolicyHost, ProcessIdentity, ProcessStartTimeTicks, ProxyConnectionId,
    ProxyRequestId, ProxySessionToken, SocketIdentity, SocketInode,
};
pub use push::{PendingSummary, UiPush};
pub use reply::{
    CheckReply, DbusCheckReply, ElevateReply, ErrorReply, FilesystemCheckReply,
    FilesystemMonitorReply, FlowClaimReply, HttpCheckReply, NetworkFlowCheckReply, ProxyReply,
    ProxyReplyBody, ProxySessionReply, RegisterUiReply, ResourceCheckReply, RpcReply,
    SandboxPackageReply, ScopeActionReply, SecretCheckReply, SimpleOkReply, StatusReply, Verdict,
    VerdictSource,
};
pub use request::{
    AliasSplit, ApprovalTarget, HEARTBEAT_FIELD, RequestContext, RpcEnvelope, RpcRequest,
    attach_check_aliases, parse_rpc_envelope, split_check_aliases,
};
pub use scope::ApprovalScope;

pub use crate::transport::FlowProtocol;

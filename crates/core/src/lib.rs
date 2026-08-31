//! Shared policy merge, host normalization, session context, and RPC types for
//! agent-sandbox.

pub mod approved_bindings;

pub mod context;
pub mod dns_cache;
pub mod dns_wire;
pub mod error;
pub mod graphical_env;
pub mod hosts;
pub mod http;
pub mod merge_policy;
pub mod policy;
pub mod rpc;
pub mod rpc_client;
pub mod scope_target;
pub mod socket_owner;
pub mod transport;
pub use approved_bindings::{APPROVED_BINDINGS_PATH, APPROVED_BINDINGS_TTL_SECS, ApprovedBindings};
pub use context::{
    PeerCredentials, ProcContext, ProcessIds, ResolvedRequestContext, SandboxPaths, SessionContext,
    daemon_context, discover_git_project_root, home_from_uid, is_descendant_of, is_path_descendant,
    peer_context, peer_cred_unix, persist_session_paths, read_proc_environ,
    sandbox_session_id_from_pid, wire_context,
};
pub use dns_cache::{DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache, lookup_dns_cache};
pub use dns_wire::{DnsMapping, EchRewrite, mappings_from_response, rewrite_ech_config};
pub use error::{InvalidScopeError, ProjectPolicyError, ScopeResolveError};
pub use graphical_env::{graphical_session_env, tool_path};
pub use hosts::{
    DnsNameError, HostResolution, NetworkRuleKey, NetworkSortKey, host_pattern_matches,
    is_ip_literal, normalize_dns_name, normalize_host, policy_host_for_connect,
};
pub use http::{
    HttpAuthority, HttpContextKey, HttpHost, HttpMethod, HttpMethodMatcher, HttpParseError,
    HttpRequest, HttpRule, HttpRuleTarget, HttpScheme, HttpSessionMetadata, HttpTarget, HttpUrl,
    NormalizedHttpPath, PendingHttpId,
};
pub use merge_policy::{
    ProjectPolicyContext, atomic_write_policy, chown_policy_path, load_policy, merge_layers,
    resolve_policy_write_path, trusted_project_policy_path,
};
pub use policy::{
    DbusBus, DbusFdMetadata, DbusMessageKind, DbusRule, DbusSection, DbusTarget, DeviceAccess,
    DirectNetworkSection, FileAccess, FilesystemRule, FilesystemRuleKey, FilesystemSection,
    HttpSection, InodeIdentity, NetworkRule, NetworkSection, Policy, ResourceAccess, ResourceKind,
    ResourceRule, ResourceRuleKey, ResourceSection, SocketAccess, SudoRule, SudoSection,
    contains_glob_syntax, contract_home_path, contract_project_path, expand_home_path,
    expand_policy_path, filesystem_approval_paths, normalize_directory_traverse_access,
    open_flags_to_file_access,
};
pub use rpc::{
    ActivationHandle, AliasSplit, ApprovalScope, ApprovalTarget, AttachmentHandle,
    AttributionToken, BindingHandle, CONTEXT_ADAPTER_PROTOCOL_MAJOR, CheckReply, ClaimHandle,
    ContextAdapterErrorCode, ContextAdapterMessage, ContextAdapterRequest, DbusCheckReply,
    DbusScopeActionReply, ElevateReply, ErrorReply, ExternalOperationKey, ExternalSessionKey,
    FilesystemCheckReply, FilesystemMonitorReply, FilesystemScopeActionReply, FlowClaimReply,
    FlowContext, FlowProtocol, FlowRegistration, HttpApprovalRequest, HttpCheckReply,
    HttpCheckRequest, HttpScopeActionReply, MAX_CONTEXT_KEY_BYTES, NetworkFlowCheckReply,
    NetworkFlowKey, NetworkFlowSelector, NormalizedPolicyHost, PendingSummary, ProcessIdentity,
    ProcessStartTimeTicks, ProxyConnectionId, ProxyReply, ProxyReplyBody, ProxyRequestId,
    ProxySessionReply, ProxySessionToken, RegisterUiReply, ReleasableHandle, RequestContext,
    ResourceCheckReply, ResourceScopeActionReply, RpcMessage, RpcReply, RpcRequest,
    ScopeActionReply, SimpleOkReply, SocketIdentity, SocketInode, StatusReply, UiPush, Verdict,
    VerdictSource, WorkspaceActivation, attach_check_aliases, parse_rpc_request,
    split_check_aliases,
};
pub use rpc_client::{PersistentRpcClient, RpcClientError, RpcConnection, policy_rpc};
pub use scope_target::{ScopeContext, ScopeTarget};
pub use socket_owner::{
    OwnerResolution, OwnerSnapshot, SocketProtocol, SocketTuple, resolve_owner_snapshot,
};
pub use transport::{FlowOwner, NetworkOwnership, is_http_service_port, scheme_for};

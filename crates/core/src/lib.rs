//! Shared policy merge, host normalization, session context, and RPC types for
//! agent-sandbox.

pub mod agent_context;
pub mod approved_bindings;
pub mod dns_cache;
pub mod dns_wire;
pub mod error;
pub mod graphical_env;
pub mod hosts;
pub mod http;
pub mod merge_policy;
pub mod policy;
pub mod proc_context;
pub mod rpc;
pub mod rpc_client;
pub mod scope_target;
pub mod session_context;
pub mod socket_owner;

pub use agent_context::{
    ProcessIds, ResolvedRequestContext, SandboxPaths, peer_sandbox_paths, persist_session_paths,
    resolve_daemon_paths, resolve_sandbox_paths,
};
pub use approved_bindings::{APPROVED_BINDINGS_PATH, APPROVED_BINDINGS_TTL_SECS, ApprovedBindings};
pub use dns_cache::{DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache, lookup_dns_cache};
pub use dns_wire::{DnsMapping, mappings_from_response};
pub use error::{InvalidScopeError, ProjectPolicyError, ScopeResolveError};
pub use graphical_env::{graphical_session_env, tool_path};
pub use hosts::{
    DnsNameError, HostResolution, NetworkRuleKey, NetworkSortKey, approval_host_patterns,
    host_pattern_matches, is_ip_literal, normalize_dns_name, normalize_host,
    policy_host_for_connect, reverse_hostname,
};
pub use http::{
    HttpAuthority, HttpContextKey, HttpHost, HttpMethod, HttpMethodMatcher, HttpParseError,
    HttpRequest, HttpRule, HttpRuleTarget, HttpScheme, HttpTarget, HttpUrl, NormalizedHttpPath,
    PendingHttpId,
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
pub use proc_context::{
    PeerCredentials, ProcContext, context_from_pid, discover_git_project_root, home_from_uid,
    is_descendant_of, is_path_descendant, peer_cred_unix, read_proc_environ,
    sandbox_session_id_from_pid, trusted_context_from_pid,
};
pub use rpc::{
    AliasSplit, ApprovalScope, ApprovalTarget, AttributionToken, CheckReply, DbusCheckReply,
    DbusScopeActionReply, ElevateReply, ErrorReply, FilesystemCheckReply, FilesystemMonitorReply,
    FilesystemScopeActionReply, FlowClaimReply, FlowContext, FlowProtocol, FlowRegistration,
    HttpApprovalRequest, HttpCheckReply, HttpCheckRequest, HttpScopeActionReply,
    NetworkFlowCheckReply, NetworkFlowKey, NormalizedPolicyHost, PendingSummary, ProcessIdentity,
    ProcessStartTimeTicks, ProxyConnectionId, ProxyReply, ProxyReplyBody, ProxyRequestId,
    ProxySessionReply, ProxySessionToken, RegisterUiReply, RequestContext, ResourceCheckReply,
    ResourceScopeActionReply, RpcMessage, RpcReply, RpcRequest, ScopeActionReply, SimpleOkReply,
    SocketIdentity, SocketInode, StatusReply, UiPush, Verdict, VerdictSource, attach_check_aliases,
    split_check_aliases,
};
pub use rpc_client::{PersistentRpcClient, RpcClientError, RpcConnection, policy_rpc};
pub use scope_target::{ScopeContext, ScopeTarget};
pub use session_context::SessionContext;
pub use socket_owner::{
    OwnerResolution, OwnerSnapshot, SocketProtocol, SocketTuple, resolve_owner_snapshot,
};

//! Shared policy merge, host normalization, session context, and RPC types for agent-sandbox.

pub mod agent_context;
pub mod dns_cache;
pub mod dns_wire;
pub mod error;
pub mod graphical_env;
pub mod hosts;
pub mod merge_policy;
pub mod policy;
pub mod proc_context;
pub mod rpc;
pub mod rpc_client;
pub mod scope_target;
pub mod session_context;

pub use agent_context::{
    ProcessIds, SandboxPaths, peer_sandbox_paths, persist_session_paths, resolve_daemon_paths,
    resolve_sandbox_paths,
};
pub use dns_cache::{DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache, lookup_dns_cache};
pub use dns_wire::{DnsMapping, mappings_from_response};
pub use error::{InvalidScopeError, ProjectPolicyError, ScopeResolveError};
pub use graphical_env::{graphical_session_env, tool_path};
pub use hosts::{
    HostResolution, NetworkRuleKey, NetworkSortKey, allow_keys, approval_host_patterns,
    is_ip_literal, normalize_host, policy_host_for_connect, reverse_hostname,
};
pub use merge_policy::{
    ProjectPolicyContext, atomic_write_policy, load_policy, merge_layers, resolve_policy_write_path,
};
pub use policy::{
    FileAccess, FilesystemRule, FilesystemRuleKey, FilesystemSection, FilesystemSortKey,
    NetworkRule, NetworkSection, Policy, SudoRule, SudoSection, contract_home_path,
    expand_home_path, filesystem_approval_paths,
};
pub use proc_context::{
    PeerCredentials, ProcContext, context_from_pid, home_from_uid, is_blocked_sandbox_policy_tool,
    is_descendant_of, looks_like_omp_ui_process, namespace_inode, omp_ui_owner_for_pid, peer_cred,
    peer_cred_unix, peer_in_different_mount_ns, peer_in_netns, read_proc_cmdline, read_proc_exe,
    sandbox_session_id_from_pid,
};
pub use rpc::{
    ApprovalScope, ApprovalTarget, CheckReply, ElevateReply, ErrorReply, FilesystemCheckReply,
    FilesystemMonitorReply, FilesystemScopeActionReply, PendingSummary, RegisterUiReply,
    RequestContext, RpcMessage, RpcReply, RpcRequest, ScopeActionReply, SimpleOkReply, StatusReply,
    UiPush,
};
pub use rpc_client::{RpcClientError, RpcConnection, policy_rpc};
pub use scope_target::{ScopeContext, ScopeTarget};
pub use session_context::{SessionContext, read_session_context, write_session_context};

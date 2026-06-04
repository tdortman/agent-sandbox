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
    ProcessIds, SandboxPaths, peer_sandbox_paths, persist_session_paths, resolve_proxy_paths,
    resolve_sandbox_paths,
};
pub use dns_cache::{DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache, lookup_dns_cache};
pub use dns_wire::mappings_from_response;
pub use error::{InvalidScopeError, ProjectPolicyError, ScopeResolveError};
pub use graphical_env::{graphical_session_env, tool_path};
pub use hosts::{
    allow_keys, is_ipv4_literal, normalize_host, parse_tls_sni, policy_host_for_connect,
    reverse_hostname,
};
pub use merge_policy::{
    atomic_write_policy, discover_project_policy, infer_home_from_paths, is_ephemeral_cwd,
    is_valid_project_root, load_policy, merge_layers, network_rule_key, project_policy_paths,
    resolve_project_policy_path, sudo_rule_key,
};
pub use policy::{NetworkRule, NetworkSection, Policy, SudoRule, SudoSection, sudo_argv_matches};
pub use proc_context::{context_from_pid, home_from_uid, peer_cred};
pub use rpc::{
    ApprovalScope, CheckReply, ElevateReply, ErrorReply, PendingSummary, RegisterUiReply,
    RpcMessage, RpcReply, RpcRequest, ScopeActionReply, SimpleOkReply, StatusReply, UiPush,
};
pub use rpc_client::{RpcClientError, RpcConnection, policy_rpc};
pub use scope_target::{ScopeContext, ScopeTarget};
pub use session_context::{SessionContext, read_session_context, write_session_context};

//! Host CLI for pending policy approvals.

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_sandbox_core::{
    ApprovalScope, DbusBus, DbusMessageKind, HttpMethod, HttpMethodMatcher, HttpRuleTarget,
    HttpUrl, PendingSummary, RequestContext, RpcReply, RpcRequest, SandboxPaths,
    contract_project_path, policy_rpc,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-approve",
    version,
    about = "Inspect and resolve pending policy approval requests",
    long_about = "Host-side helper for resolving pending policyd approval requests. Connects \
        to the policyd Unix socket, lists requests waiting on user input, and approves or \
        denies them at the chosen scope. Normally driven by \"agent-sandbox-ui\" (a long-lived UI client), but the same \
        commands are usable from a terminal or from automation scripts.\n\n\
        EXAMPLES:\n\
        # Show every pending approval routed through this host.\n\
        agent-sandbox-approve pending\n\n\
        # Approve a network request for the current session only.\n\
        agent-sandbox-approve approve <request-id> session --session-id session-2024-05-01-abc\n\n\
        # Pre-approve 1.1.1.1 on port 53 globally so all sandboxes can use the Cloudflare DNS.\n\
        agent-sandbox-approve approve-host 1.1.1.1 53 global --home /home/user"
)]
struct Cli {
    /// Path to the policyd Unix domain socket the CLI talks to.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List every pending approval request.
    Pending {
        /// Home directory inside the sandbox. Used to scope "global" rules to the right "policy.json". Defaults to the env var `AGENT_SANDBOX_HOME`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_HOME")]
        home: Option<PathBuf>,

        /// Working directory inside the sandbox. Used to scope per-project rules. Defaults to the env var `AGENT_SANDBOX_CWD`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_CWD")]
        cwd: Option<PathBuf>,

        /// Project root inside the sandbox. Required for "project" scope. Defaults to the env var `AGENT_SANDBOX_PROJECT_ROOT`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_PROJECT_ROOT")]
        project_root: Option<PathBuf>,
    },
    /// Approve a pending request and persist the rule at the requested scope.
    Approve {
        /// Request id printed by "pending". Identifies the queued elevation, network, or filesystem request.
        id: String,

        /// Where to persist the rule: "once" (this request only, default for "deny"), "session", "project", or "global".
        #[arg(value_name = "SCOPE")]
        scope: ApprovalScope,

        /// Session id the request belongs to. Required when the scope is "session" and the policy is keyed by session.
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,

        /// Home directory inside the sandbox. Used to scope "global" rules. Defaults to the env var `AGENT_SANDBOX_HOME`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_HOME")]
        home: Option<PathBuf>,

        /// Working directory inside the sandbox. Used to scope per-project rules. Defaults to the env var `AGENT_SANDBOX_CWD`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_CWD")]
        cwd: Option<PathBuf>,

        /// Project root inside the sandbox. Required for "project" scope. Defaults to the env var `AGENT_SANDBOX_PROJECT_ROOT`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_PROJECT_ROOT")]
        project_root: Option<PathBuf>,
    },
    /// Pre-approve a single (host, port) pair without an outstanding request. Writes the rule directly to policyd.
    ApproveHost {
        /// Destination host. Either a literal IPv4/IPv6 address (e.g. "1.1.1.1") or a hostname (e.g. "example.com").
        host: String,

        /// Destination port. Use the well-known port for the scheme (e.g. 443 for HTTPS, 53 for DNS).
        port: u16,

        /// Where to persist the rule: "once", "session", "project", or "global".
        #[arg(value_name = "SCOPE")]
        scope: ApprovalScope,

        /// Session id the rule applies to. Required when the scope is "session".
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,
        /// Home directory inside the sandbox. Used to scope "global" rules. Defaults to the env var `AGENT_SANDBOX_HOME`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_HOME")]
        home: Option<PathBuf>,

        /// Working directory inside the sandbox. Used to scope per-project rules. Defaults to the env var `AGENT_SANDBOX_CWD`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_CWD")]
        cwd: Option<PathBuf>,

        /// Project root inside the sandbox. Required for "project" scope. Defaults to the env var `AGENT_SANDBOX_PROJECT_ROOT`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_PROJECT_ROOT")]
        project_root: Option<PathBuf>,
    },
    /// Pre-approve a decoded HTTP method and URL target.
    ApproveHttp {
        /// URL or URL pattern without a query string or fragment.
        url: String,

        /// Where to persist the HTTP rule.
        #[arg(value_name = "SCOPE")]
        scope: ApprovalScope,

        /// Exact HTTP method. Mutually exclusive with --all-methods.
        #[arg(long, value_name = "METHOD", conflicts_with = "all_methods")]
        method: Option<String>,

        /// Match every HTTP method at this URL.
        #[arg(long, conflicts_with = "method")]
        all_methods: bool,

        #[arg(long, value_name = "ID")]
        session_id: Option<String>,

        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,

        #[arg(long, value_name = "DIR")]
        cwd: Option<PathBuf>,

        #[arg(long, value_name = "DIR")]
        project_root: Option<PathBuf>,
    },
    /// Deny a pending request and persist the deny rule at the requested scope.
    Deny {
        /// Request id printed by "pending".
        id: String,

        /// Where to persist the deny rule. Defaults to "once" so a denial only affects this single request.
        #[arg(value_name = "SCOPE", default_value = "once")]
        scope: ApprovalScope,

        /// Session id the request belongs to. Required when the scope is "session".
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,

        /// Home directory inside the sandbox. Used to scope "global" rules. Defaults to the env var `AGENT_SANDBOX_HOME`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_HOME")]
        home: Option<PathBuf>,

        /// Working directory inside the sandbox. Used to scope per-project rules. Defaults to the env var `AGENT_SANDBOX_CWD`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_CWD")]
        cwd: Option<PathBuf>,

        /// Project root inside the sandbox. Required for "project" scope. Defaults to the env var `AGENT_SANDBOX_PROJECT_ROOT`.
        #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_PROJECT_ROOT")]
        project_root: Option<PathBuf>,
    },
}
/// Parse CLI args, dispatch to the matching subcommand handler, and print the result.
///
/// # Errors
/// Returns [`ApproveCliError::Rpc`] when the RPC to policyd fails,
/// [`ApproveCliError::Json`] when JSON serialization fails,
/// or [`ApproveCliError::Policyd`] when policyd returns a denial or error response.
pub async fn run() -> Result<(), ApproveCliError> {
    let cli = Cli::parse();
    dispatch(&cli.socket, cli.cmd).await
}

async fn dispatch(socket: &Path, command: Command) -> Result<(), ApproveCliError> {
    match command {
        Command::Pending {
            home,
            cwd,
            project_root,
        } => handle_pending(socket, home, cwd, project_root).await,
        Command::Approve {
            id,
            scope,
            session_id,
            home,
            cwd,
            project_root,
        } => {
            let ctx = request_context(cwd, home, project_root);
            handle_approve(socket, id, scope, session_id, ctx).await
        }
        Command::ApproveHost {
            host,
            port,
            scope,
            session_id,
            home,
            cwd,
            project_root,
        } => {
            let ctx = request_context(cwd, home, project_root);
            handle_approve_host(socket, host, port, scope, session_id, ctx).await
        }
        Command::ApproveHttp {
            url,
            scope,
            method,
            all_methods,
            session_id,
            home,
            cwd,
            project_root,
        } => {
            let ctx = request_context(cwd, home, project_root);
            handle_approve_http(socket, url, scope, method, all_methods, session_id, ctx).await
        }
        Command::Deny {
            id,
            scope,
            session_id,
            home,
            cwd,
            project_root,
        } => {
            let ctx = request_context(cwd, home, project_root);
            handle_deny(socket, id, scope, session_id, ctx).await
        }
    }
}

fn request_context(
    cwd: Option<PathBuf>,
    home: Option<PathBuf>,
    project_root: Option<PathBuf>,
) -> RequestContext {
    let paths = SandboxPaths::from_wire(cwd, home, project_root);
    RequestContext::from(&paths)
}

async fn handle_approve(
    socket: &Path,
    id: String,
    scope: ApprovalScope,
    session_id: Option<String>,
    ctx: RequestContext,
) -> Result<(), ApproveCliError> {
    let req = RpcRequest::Approve {
        id,
        scope,
        session_id,
        target: None,
        comment: None,
        ctx,
    };
    print_json(&rpc(socket, req).await?)
}

async fn handle_approve_host(
    socket: &Path,
    host: String,
    port: u16,
    scope: ApprovalScope,
    session_id: Option<String>,
    ctx: RequestContext,
) -> Result<(), ApproveCliError> {
    let req = RpcRequest::ApproveHost {
        host,
        port,
        scope,
        session_id,
        ctx,
    };
    print_json(&rpc(socket, req).await?)
}

async fn handle_approve_http(
    socket: &Path,
    url: String,
    scope: ApprovalScope,
    method: Option<String>,
    all_methods: bool,
    session_id: Option<String>,
    ctx: RequestContext,
) -> Result<(), ApproveCliError> {
    if scope == ApprovalScope::Once {
        return Err(ApproveCliError::Policyd(
            "HTTP pre-approval requires a persistent scope".into(),
        ));
    }
    if scope == ApprovalScope::Session && session_id.is_none() {
        return Err(ApproveCliError::Policyd(
            "session scope requires --session-id".into(),
        ));
    }
    let matcher = match (method, all_methods) {
        (Some(method), false) => HttpMethod::parse(&method)
            .map(HttpMethodMatcher::Exact)
            .map_err(|error| ApproveCliError::Policyd(error.to_string()))?,
        (None, true) => HttpMethodMatcher::All,
        _ => {
            return Err(ApproveCliError::Policyd(
                "specify exactly one of --method or --all-methods".into(),
            ));
        }
    };
    let url = HttpUrl::parse_pattern(&url)
        .map_err(|error| ApproveCliError::Policyd(error.to_string()))?;
    let target = HttpRuleTarget::new(matcher, url)
        .map_err(|error| ApproveCliError::Policyd(error.to_string()))?;
    let req = RpcRequest::ApproveHttp {
        target,
        scope,
        session_id,
        ctx,
    };
    print_json(&rpc(socket, req).await?)
}

async fn handle_deny(
    socket: &Path,
    id: String,
    scope: ApprovalScope,
    session_id: Option<String>,
    ctx: RequestContext,
) -> Result<(), ApproveCliError> {
    let req = RpcRequest::Deny {
        id,
        scope,
        session_id,
        target: None,
        comment: None,
        ctx,
    };
    print_json(&rpc(socket, req).await?)
}
/// Fetch and display the list of pending approval requests.
async fn handle_pending(
    socket: &Path,
    home: Option<PathBuf>,
    cwd: Option<PathBuf>,
    project_root: Option<PathBuf>,
) -> Result<(), ApproveCliError> {
    let p = SandboxPaths::from_wire(cwd, home, project_root);
    let req = RpcRequest::Status {
        ctx: RequestContext::from(&p),
    };
    let resp = rpc(socket, req).await?;
    let RpcReply::Status(body) = resp else {
        return Err(approve_error(&resp));
    };
    if body.pending.is_empty() {
        println!("No pending approvals.");
        return Ok(());
    }
    for item in body.pending {
        match item {
            PendingSummary::Elevation { id, argv, .. } => {
                let argv = argv.unwrap_or_default();
                println!("{id}\televation\t\t{}", argv.join(" "));
            }
            PendingSummary::Network { id, host, port, .. } => {
                let host = host.unwrap_or_default();
                let port = port.unwrap_or(0);
                println!("{id}\tnetwork\t\t{host}:{port}");
            }
            PendingSummary::Http { id, request, .. } => {
                println!("{id}\thttp\t{}\t{}", request.method.as_str(), request.url);
            }
            PendingSummary::Filesystem {
                id, path, access, ..
            } => {
                let path = path.unwrap_or_default();
                let access = access.map_or_else(String::new, |value| value.to_string());
                println!("{id}\tfilesystem\t{access}\t{}", path.display());
            }
            PendingSummary::Resource {
                id,
                resource_kind,
                path,
                access,
                ..
            } => {
                let kind = resource_kind.to_string();
                let path = contract_project_path(&path.unwrap_or_default(), p.project_root());
                let access = access.map_or_else(String::new, |value| value.to_string());
                println!("{id}\tresource\t{kind}\t{access}\t{}", path.display());
            }
            PendingSummary::Dbus { id, target, .. } => {
                println!(
                    "{id}\tdbus\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    dbus_bus_name(target.bus),
                    target.destination,
                    target.object_path,
                    target.interface,
                    target.member,
                    dbus_message_kind_name(target.message_kind),
                    dbus_signature_display(&target.signature),
                    target.fd_metadata.len(),
                    dbus_fd_metadata_display(&target),
                );
            }
        }
    }
    Ok(())
}

const fn dbus_bus_name(bus: DbusBus) -> &'static str {
    match bus {
        DbusBus::Session => "session",
        DbusBus::System => "system",
    }
}

const fn dbus_message_kind_name(kind: DbusMessageKind) -> &'static str {
    match kind {
        DbusMessageKind::MethodCall => "method_call",
        DbusMessageKind::MethodReturn => "method_return",
        DbusMessageKind::Error => "error",
        DbusMessageKind::Signal => "signal",
    }
}

const fn dbus_signature_display(signature: &str) -> &str {
    if signature.is_empty() {
        "<empty>"
    } else {
        signature
    }
}

fn dbus_fd_metadata_display(target: &agent_sandbox_core::DbusTarget) -> String {
    target
        .fd_metadata
        .iter()
        .enumerate()
        .map(|(index, metadata)| {
            format!(
                "{index}: kind={}, read_only={}",
                metadata.kind, metadata.read_only
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn rpc(socket: &Path, req: RpcRequest) -> Result<RpcReply, ApproveCliError> {
    policy_rpc(socket, req, Duration::from_secs(30))
        .await
        .map_err(ApproveCliError::Rpc)
}

fn print_json(resp: &RpcReply) -> Result<(), ApproveCliError> {
    println!("{}", serde_json::to_string_pretty(resp)?);
    if resp.is_ok() {
        Ok(())
    } else {
        Err(approve_error(resp))
    }
}

fn approve_error(resp: &RpcReply) -> ApproveCliError {
    match resp {
        RpcReply::Error(e) => ApproveCliError::Policyd(e.error.clone()),
        _ => ApproveCliError::Policyd("request failed".into()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApproveCliError {
    #[error(transparent)]
    Rpc(#[from] agent_sandbox_core::RpcClientError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Policyd(String),
}

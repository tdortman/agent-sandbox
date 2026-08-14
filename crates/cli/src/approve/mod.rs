//! Host CLI for pending policy approvals.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use agent_sandbox_core::{
    ApprovalScope, HttpMethod, HttpMethodMatcher, HttpRuleTarget, HttpUrl, PendingSummary,
    RequestContext, RpcReply, RpcRequest, SandboxPaths, contract_project_path, policy_rpc,
};
use clap::{Args, Parser, Subcommand};

use crate::ui::{bus_name, dbus_fd_display, message_kind_name, signature_display};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-approve",
    version,
    about = "Inspect and resolve pending policy approval requests",
    long_about = r#"Host-side helper for resolving pending policyd approval requests.
Connects to the policyd Unix socket, lists requests waiting on user input, and approves or denies them at the chosen scope.
Normally driven by "agent-sandbox-ui" (a long-lived UI client), but the same commands are usable from a terminal or from automation scripts.

Scopes, most specific first: once, session, project_package, project, global_package, global.

EXAMPLES:
# Show every pending approval routed through this host.
agent-sandbox-approve pending

# Approve a network request for the current session only.
agent-sandbox-approve approve <request-id> session --session-id session-2024-05-01-abc

# Pre-approve 1.1.1.1 on port 53 for one package across all projects.
agent-sandbox-approve approve-host 1.1.1.1 53 global_package --home /home/user

# Pre-approve 1.1.1.1 on port 53 globally so all sandboxes can use the Cloudflare DNS.
agent-sandbox-approve approve-host 1.1.1.1 53 global --home /home/user"#
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

#[derive(Args, Debug)]
struct ContextArgs {
    /// Home directory inside the sandbox. Used to scope "global" rules.
    /// Defaults to the env var `AGENT_SANDBOX_HOME`.
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_HOME")]
    home: Option<PathBuf>,

    /// Working directory inside the sandbox. Used to scope per-project rules.
    /// Defaults to the env var `AGENT_SANDBOX_CWD`.
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_CWD")]
    cwd: Option<PathBuf>,

    /// Project root inside the sandbox. Required for "project" scope.
    /// Defaults to the env var `AGENT_SANDBOX_PROJECT_ROOT`.
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_PROJECT_ROOT")]
    project_root: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List every pending approval request.
    Pending {
        #[command(flatten)]
        context: ContextArgs,
    },

    /// Approve a pending request and persist the rule at the requested scope.
    Approve {
        /// Request id printed by "pending". Identifies the queued elevation,
        /// network, or filesystem request.
        id: String,

        /// Where to persist the rule: "once" (this request only, default for
        /// "deny"), "session", "`project_package`", "project",
        /// "`global_package`", or "global".
        #[arg(value_name = "SCOPE")]
        scope: ApprovalScope,

        /// Session id the request belongs to. Required when the scope is
        /// "session" and the policy is keyed by session.
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,

        #[command(flatten)]
        context: ContextArgs,
    },

    /// Pre-approve a single (host, port) pair without an outstanding request.
    /// Writes the rule directly to policyd.
    ApproveHost {
        /// Destination host. Either a literal IPv4/IPv6 address (e.g.
        /// "1.1.1.1") or a hostname (e.g. "example.com").
        host: String,

        /// Destination port. Use the well-known port for the scheme (e.g. 443
        /// for HTTPS, 53 for DNS).
        port: u16,

        /// Where to persist the rule: "once", "session", "`project_package`",
        /// "project", "`global_package`", or "global".
        #[arg(value_name = "SCOPE")]
        scope: ApprovalScope,

        /// Session id the rule applies to. Required when the scope is
        /// "session".
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,

        #[command(flatten)]
        context: ContextArgs,
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

        #[command(flatten)]
        context: ContextArgs,
    },

    /// Register a sandbox session's package identity with policyd.
    ///
    /// Wrappers call this on the host socket before the sandbox starts so
    /// that policy requests in the session are attributed to the package.
    RegisterSandbox {
        /// Session id the sandbox runs under (`AGENT_SANDBOX_SESSION_ID`).
        session_id: String,

        /// Package name the session is attributed to.
        #[arg(long, value_name = "NAME")]
        package: String,

        /// PID of the launcher process spawning the sandbox (the wrapper
        /// script's `$$`). policyd verifies it against this process's real
        /// parent.
        #[arg(long, value_name = "PID", value_parser = clap::value_parser!(u32).range(1..))]
        launcher_pid: u32,
    },

    /// Deny a pending request and persist the deny rule at the requested scope.
    Deny {
        /// Request id printed by "pending".
        id: String,

        /// Where to persist the deny rule. Defaults to "once" so a denial only
        /// affects this single request.
        #[arg(value_name = "SCOPE", default_value = "once")]
        scope: ApprovalScope,

        /// Session id the request belongs to. Required when the scope is
        /// "session".
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,

        #[command(flatten)]
        context: ContextArgs,
    },
}

/// Parse CLI args, dispatch to the matching subcommand handler, and print the
/// result.
///
/// # Errors
/// Returns [`ApproveCliError::Rpc`] when the RPC to policyd fails,
/// [`ApproveCliError::Json`] when JSON serialization fails,
/// or [`ApproveCliError::Policyd`] when policyd returns a denial or error
/// response.
pub async fn run() -> Result<(), ApproveCliError> {
    let cli = Cli::parse();
    dispatch(&cli.socket, cli.cmd).await
}

async fn dispatch(socket: &Path, command: Command) -> Result<(), ApproveCliError> {
    match command {
        Command::Pending { context } => {
            let ContextArgs {
                home,
                cwd,
                project_root,
            } = context;
            handle_pending(socket, home, cwd, project_root).await
        }

        Command::Approve {
            id,
            scope,
            session_id,
            context,
        } => {
            let ctx = request_context(context);
            handle_approve(socket, id, scope, session_id, ctx).await
        }

        Command::ApproveHost {
            host,
            port,
            scope,
            session_id,
            context,
        } => {
            let ctx = request_context(context);
            handle_approve_host(socket, host, port, scope, session_id, ctx).await
        }

        Command::ApproveHttp {
            url,
            scope,
            method,
            all_methods,
            session_id,
            context,
        } => {
            let ctx = request_context(context);
            handle_approve_http(socket, url, scope, method, all_methods, session_id, ctx).await
        }

        Command::RegisterSandbox {
            session_id,
            package,
            launcher_pid,
        } => handle_register_sandbox(socket, session_id, package, launcher_pid).await,

        Command::Deny {
            id,
            scope,
            session_id,
            context,
        } => {
            let ctx = request_context(context);
            handle_deny(socket, id, scope, session_id, ctx).await
        }
    }
}

fn request_context(context: ContextArgs) -> RequestContext {
    let paths = SandboxPaths::from_wire(context.cwd, context.home, context.project_root);
    RequestContext::from(&paths)
}

const fn register_sandbox_request(
    session_id: String,
    package: String,
    launcher_pid: u32,
) -> RpcRequest {
    RpcRequest::RegisterSandbox {
        session_id,
        package,
        launcher_pid,
    }
}

async fn handle_register_sandbox(
    socket: &Path,
    session_id: String,
    package: String,
    launcher_pid: u32,
) -> Result<(), ApproveCliError> {
    print_json(
        &rpc(
            socket,
            register_sandbox_request(session_id, package, launcher_pid),
        )
        .await?,
    )
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
            PendingSummary::Elevation {
                id, argv, package, ..
            } => {
                let argv = argv.unwrap_or_default();
                let package = package.unwrap_or_default();
                println!("{id}\televation\t\t{package}\t{}", argv.join(" "));
            }

            PendingSummary::Network {
                id,
                host,
                port,
                package,
                ..
            } => {
                let host = host.unwrap_or_default();
                let port = port.unwrap_or(0);
                let package = package.unwrap_or_default();
                println!("{id}\tnetwork\t\t{package}\t{host}:{port}");
            }

            PendingSummary::Http {
                id,
                request,
                package,
                ..
            } => {
                let package = package.unwrap_or_default();
                println!(
                    "{id}\thttp\t{}\t{package}\t{}",
                    request.method.as_str(),
                    request.url
                );
            }

            PendingSummary::Filesystem {
                id,
                path,
                access,
                package,
                ..
            } => {
                let path = path.unwrap_or_default();
                let access = access.map_or_else(String::new, |value| value.to_string());
                let package = package.unwrap_or_default();
                println!("{id}\tfilesystem\t{access}\t{package}\t{}", path.display());
            }

            PendingSummary::Resource {
                id,
                resource_kind,
                path,
                access,
                package,
                ..
            } => {
                let kind = resource_kind.to_string();
                let path = contract_project_path(&path.unwrap_or_default(), p.project_root());
                let access = access.map_or_else(String::new, |value| value.to_string());
                let package = package.unwrap_or_default();
                println!(
                    "{id}\tresource\t{kind}\t{access}\t{package}\t{}",
                    path.display()
                );
            }

            PendingSummary::Dbus {
                id,
                target,
                package,
                ..
            } => {
                let package = package.unwrap_or_default();
                println!(
                    "{id}\tdbus\t{package}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    bus_name(target.bus),
                    target.destination,
                    target.object_path,
                    target.interface,
                    target.member,
                    message_kind_name(target.message_kind),
                    signature_display(&target.signature),
                    target.fd_metadata.len(),
                    dbus_fd_display(&target),
                );
            }
        }
    }

    Ok(())
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

/// Errors produced by the approval CLI.
#[derive(Debug, thiserror::Error)]
pub enum ApproveCliError {
    /// An error from the underlying RPC client.
    #[error(transparent)]
    Rpc(#[from] agent_sandbox_core::RpcClientError),

    /// A JSON (de)serialization error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// A policyd error or request/usage problem, with the message describing
    /// it.
    #[error("{0}")]
    Policyd(String),
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::RpcRequest;
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn register_sandbox_builds_register_request() {
        let req = super::register_sandbox_request("sandbox-1".into(), "omp".into(), 1234);

        match &req {
            RpcRequest::RegisterSandbox {
                session_id,
                package,
                launcher_pid,
            } => {
                assert_eq!(session_id, "sandbox-1");
                assert_eq!(package, "omp");
                assert_eq!(*launcher_pid, 1234);
            }

            _ => panic!("expected RegisterSandbox request"),
        }

        let wire = serde_json::to_value(&req).expect("serialize register request");
        assert_eq!(wire["op"], "register_sandbox");
        assert_eq!(wire["launcher_pid"], 1234);
    }

    #[test]
    fn register_sandbox_rejects_missing_or_zero_launcher_pid() {
        use clap::Parser;

        let missing = Cli::try_parse_from([
            "agent-sandbox-approve",
            "register-sandbox",
            "sandbox-1",
            "--package",
            "omp",
        ]);

        assert!(
            missing.is_err(),
            "register-sandbox without --launcher-pid must be rejected"
        );

        let zero = Cli::try_parse_from([
            "agent-sandbox-approve",
            "register-sandbox",
            "sandbox-1",
            "--package",
            "omp",
            "--launcher-pid",
            "0",
        ]);

        assert!(
            zero.is_err(),
            "register-sandbox with --launcher-pid 0 must be rejected"
        );
    }

    #[test]
    fn context_arguments_declare_environment_defaults() {
        let command = Cli::command();

        for name in ["pending", "approve", "approve-host", "approve-http", "deny"] {
            let subcommand = command
                .find_subcommand(name)
                .expect("context subcommand should exist");

            for (argument, environment) in [
                ("home", "AGENT_SANDBOX_HOME"),
                ("cwd", "AGENT_SANDBOX_CWD"),
                ("project_root", "AGENT_SANDBOX_PROJECT_ROOT"),
            ] {
                let argument = subcommand
                    .get_arguments()
                    .find(|candidate| candidate.get_id().as_str() == argument)
                    .expect("context argument should exist");

                assert_eq!(
                    argument.get_env().and_then(|value| value.to_str()),
                    Some(environment)
                );
            }
        }
    }
}

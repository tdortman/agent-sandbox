use agent_sandbox_core::{ApprovalScope, ApprovalTarget, SudoRule, approval_host_patterns};

pub(crate) const ACTION_OPTIONS: &[&str] = &["Allow", "Deny"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromptAction {
    Allow,
    Deny,
}

impl PromptAction {
    pub(crate) fn from_label(label: &str) -> Option<Self> {
        match label {
            "Allow" => Some(Self::Allow),
            "Deny" => Some(Self::Deny),
            _ => None,
        }
    }

    pub(crate) const fn verb(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ScopeOption {
    pub(crate) label: String,
    pub(crate) scope: ApprovalScope,
    pub(crate) target: Option<ApprovalTarget>,
}

pub(crate) fn network_scope_options(host: &str, session_available: bool) -> Vec<ScopeOption> {
    let mut options = vec![ScopeOption {
        label: "This connection only".into(),
        scope: ApprovalScope::Once,
        target: None,
    }];
    let hosts = approval_host_patterns(host);
    if session_available {
        push_network_options(&mut options, ApprovalScope::Session, &hosts);
    }
    push_network_options(&mut options, ApprovalScope::Project, &hosts);
    push_network_options(&mut options, ApprovalScope::Global, &hosts);
    options
}

pub(crate) fn sudo_scope_options(argv: &[String], session_available: bool) -> Vec<ScopeOption> {
    let mut options = vec![ScopeOption {
        label: "This command only".into(),
        scope: ApprovalScope::Once,
        target: None,
    }];
    let prefixes = SudoRule::approval_prefixes(argv);
    if session_available {
        push_sudo_options(&mut options, ApprovalScope::Session, &prefixes);
    }
    push_sudo_options(&mut options, ApprovalScope::Project, &prefixes);
    push_sudo_options(&mut options, ApprovalScope::Global, &prefixes);
    options
}

fn push_network_options(options: &mut Vec<ScopeOption>, scope: ApprovalScope, hosts: &[String]) {
    for host in hosts {
        options.push(ScopeOption {
            label: format!("{} — {host}", scope_label(scope)),
            scope,
            target: Some(ApprovalTarget::NetworkHost { host: host.clone() }),
        });
    }
}

fn push_sudo_options(
    options: &mut Vec<ScopeOption>,
    scope: ApprovalScope,
    prefixes: &[Vec<String>],
) {
    for argv in prefixes {
        options.push(ScopeOption {
            label: format!("{} — {}", scope_label(scope), format_command(argv)),
            scope,
            target: Some(ApprovalTarget::SudoCommand { argv: argv.clone() }),
        });
    }
}

fn scope_label(scope: ApprovalScope) -> &'static str {
    match scope {
        ApprovalScope::Once => "Once",
        ApprovalScope::Session => "This session",
        ApprovalScope::Project => "This project",
        ApprovalScope::Global => "Globally",
    }
}

fn format_command(argv: &[String]) -> String {
    if argv.is_empty() {
        "sudo".into()
    } else {
        format!("sudo {}", argv.join(" "))
    }
}

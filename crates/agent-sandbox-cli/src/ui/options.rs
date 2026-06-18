use agent_sandbox_core::{ApprovalScope, ApprovalTarget, SudoRule};

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

pub(crate) fn scope_only_options(session_available: bool) -> Vec<ScopeOption> {
    let mut options = vec![ScopeOption {
        label: "Once".into(),
        scope: ApprovalScope::Once,
        target: None,
    }];
    if session_available {
        options.push(ScopeOption {
            label: "This session".into(),
            scope: ApprovalScope::Session,
            target: None,
        });
    }
    options.push(ScopeOption {
        label: "This project".into(),
        scope: ApprovalScope::Project,
        target: None,
    });
    options.push(ScopeOption {
        label: "Globally".into(),
        scope: ApprovalScope::Global,
        target: None,
    });
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

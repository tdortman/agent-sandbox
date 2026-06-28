use agent_sandbox_core::{ApprovalScope, ApprovalTarget, SudoRule};

pub const ACTION_OPTIONS: &[&str] = &["Allow", "Deny"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptAction {
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
pub struct ScopeOption {
    pub(crate) label: String,
    pub(crate) scope: ApprovalScope,
    pub(crate) target: Option<ApprovalTarget>,
}

pub fn scope_only_options(session_available: bool) -> Vec<ScopeOption> {
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

/// Command prefix options for a single scope (step 3 of 3-step flow).
pub fn sudo_target_options(argv: &[String], scope: ApprovalScope) -> Vec<ScopeOption> {
    let prefixes = SudoRule::approval_prefixes(argv);
    let mut options = Vec::with_capacity(prefixes.len());
    for argv in &prefixes {
        options.push(ScopeOption {
            label: format_command(argv),
            scope,
            target: Some(ApprovalTarget::SudoCommand { argv: argv.clone() }),
        });
    }
    options
}

fn format_command(argv: &[String]) -> String {
    if argv.is_empty() {
        "sudo".into()
    } else {
        format!("sudo {}", argv.join(" "))
    }
}

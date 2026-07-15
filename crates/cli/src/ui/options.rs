use std::collections::HashMap;

use agent_sandbox_core::{ApprovalScope, ApprovalTarget, SudoRule};
use serde_json::{Value, json};

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

#[derive(Debug, Clone)]
pub struct ApprovalFormContext {
    pub(crate) label: String,
    pub(crate) value: String,
}
#[derive(Debug, Clone)]
pub struct ApprovalFormPresentation {
    pub(crate) heading: String,
    pub(crate) subject: String,
}

#[derive(Debug, Clone)]
pub struct ApprovalFormOption {
    pub(crate) value: String,
    pub(crate) label: String,
}

#[derive(Debug, Clone)]
pub struct ApprovalScopeFormValue {
    pub(crate) value: &'static str,
    pub(crate) label: &'static str,
}

#[derive(Debug, Clone)]
pub struct ApprovalFormRequest {
    pub(crate) summary: String,
    pub(crate) context: Vec<ApprovalFormContext>,
    pub(crate) presentation: Option<ApprovalFormPresentation>,
    pub(crate) scopes: Vec<ApprovalScope>,
    pub(crate) fields: Vec<ApprovalFormField>,
}

#[derive(Debug, Clone)]
pub struct ApprovalFormField {
    pub(crate) id: &'static str,
    pub(crate) label: String,
    pub(crate) control: ApprovalFormControl,
}

#[derive(Debug, Clone)]
pub enum ApprovalFormControl {
    Text {
        value: String,
    },
    Choice {
        value: String,
        options: Vec<ApprovalFormOption>,
    },
}

impl ApprovalFormRequest {
    pub(crate) fn to_json(&self) -> Value {
        let scopes = self
            .scopes
            .iter()
            .map(|scope| {
                let form_value = scope_form_value(*scope);
                json!({ "value": form_value.value, "label": form_value.label })
            })
            .collect::<Vec<_>>();
        let fields = self
            .fields
            .iter()
            .map(|field| match &field.control {
                ApprovalFormControl::Text { value } => json!({
                    "id": field.id,
                    "label": field.label,
                    "kind": "text",
                    "value": value,
                }),
                ApprovalFormControl::Choice { value, options } => json!({
                    "id": field.id,
                    "label": field.label,
                    "kind": "choice",
                    "value": value,
                    "options": options.iter().map(|option| {
                        json!({ "value": option.value, "label": option.label })
                    }).collect::<Vec<_>>(),
                }),
            })
            .collect::<Vec<_>>();
        let mut request = json!({
            "version": 1,
            "summary": self.summary,
            "context": self.context.iter().map(|context| {
                json!({ "label": context.label, "value": context.value })
            }).collect::<Vec<_>>(),
            "scopes": scopes,
            "fields": fields,
        });
        if let Some(presentation) = &self.presentation {
            request["presentation"] = json!({
                "heading": presentation.heading,
                "subject": presentation.subject,
            });
        }
        request
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalFormResult {
    pub(crate) action: ApprovalFormAction,
    pub(crate) scope: ApprovalScope,
    pub(crate) values: HashMap<String, String>,
}

/// Validates a review candidate inside the Qt dialog loop.
/// Returns `Ok(())` to accept, `Err(message)` to send the error back
/// so the user can fix the input and resubmit.
pub type ReviewValidator = Box<dyn Fn(&ApprovalFormResult) -> Result<(), String> + Send + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalFormAction {
    Allow,
    Deny,
    Cancel,
}

impl ApprovalFormAction {
    pub(crate) const fn prompt_action(self) -> Option<PromptAction> {
        match self {
            Self::Allow => Some(PromptAction::Allow),
            Self::Deny => Some(PromptAction::Deny),
            Self::Cancel => None,
        }
    }
}

pub const fn scope_form_value(scope: ApprovalScope) -> ApprovalScopeFormValue {
    match scope {
        ApprovalScope::Once => ApprovalScopeFormValue {
            value: "once",
            label: "Once",
        },
        ApprovalScope::Session => ApprovalScopeFormValue {
            value: "session",
            label: "This session",
        },
        ApprovalScope::Project => ApprovalScopeFormValue {
            value: "project",
            label: "This project",
        },
        ApprovalScope::Global => ApprovalScopeFormValue {
            value: "global",
            label: "Globally",
        },
    }
}

pub fn scope_from_form_value(value: &str) -> Option<ApprovalScope> {
    match value {
        "once" => Some(ApprovalScope::Once),
        "session" => Some(ApprovalScope::Session),
        "project" => Some(ApprovalScope::Project),
        "global" => Some(ApprovalScope::Global),
        _ => None,
    }
}

#[must_use]
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

#[must_use]
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

pub fn format_command(argv: &[String]) -> String {
    if argv.is_empty() {
        "sudo".into()
    } else {
        format!("sudo {}", argv.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalFormContext, ApprovalFormControl, ApprovalFormField, ApprovalFormOption,
        ApprovalFormRequest, ApprovalScope,
    };

    #[test]
    fn review_request_serializes_generic_scopes_and_fields() {
        let request = ApprovalFormRequest {
            summary: "HTTP GET https://example.com/path".into(),
            context: vec![ApprovalFormContext {
                label: "Project".into(),
                value: "/work/project".into(),
            }],
            presentation: None,
            scopes: vec![ApprovalScope::Once, ApprovalScope::Project],
            fields: vec![ApprovalFormField {
                id: "method",
                label: "Methods".into(),
                control: ApprovalFormControl::Choice {
                    value: "exact".into(),
                    options: vec![
                        ApprovalFormOption {
                            value: "exact".into(),
                            label: "GET only".into(),
                        },
                        ApprovalFormOption {
                            value: "all".into(),
                            label: "All methods".into(),
                        },
                    ],
                },
            }],
        };

        let json = request.to_json();

        assert_eq!(json["version"], 1);
        assert_eq!(json["scopes"][0]["value"], "once");
        assert_eq!(json["fields"][0]["kind"], "choice");
        assert_eq!(json["fields"][0]["options"][1]["value"], "all");
    }
}

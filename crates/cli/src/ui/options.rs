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
    pub(crate) comment: Option<String>,
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
    pub(crate) fn new(
        summary: impl Into<String>,
        context: Vec<ApprovalFormContext>,
        presentation: Option<ApprovalFormPresentation>,
        scopes: Vec<ApprovalScope>,
        fields: Vec<ApprovalFormField>,
    ) -> Self {
        Self {
            summary: summary.into(),
            context,
            presentation,
            scopes,
            fields,
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        let scopes = self
            .scopes
            .iter()
            .map(|scope| {
                let label = match scope {
                    ApprovalScope::Once => "Once",
                    ApprovalScope::Session => "This session",
                    ApprovalScope::Project => "This project",
                    ApprovalScope::Global => "Globally",
                };
                json!({ "value": scope.as_str(), "label": label })
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
    pub(crate) action: Option<PromptAction>,
    pub(crate) scope: ApprovalScope,
    pub(crate) values: HashMap<String, String>,
}

/// Validates a review candidate inside the Qt dialog loop.
/// Returns `Ok(())` to accept, `Err(message)` to send the error back
/// so the user can fix the input and resubmit.
pub type ReviewValidator = Box<dyn Fn(&ApprovalFormResult) -> Result<(), String> + Send + 'static>;

#[must_use]
pub fn scope_only_options(session_available: bool) -> Vec<ScopeOption> {
    let mut options = vec![ScopeOption {
        label: "Once".into(),
        scope: ApprovalScope::Once,
        target: None,
        comment: None,
    }];
    if session_available {
        options.push(ScopeOption {
            label: "This session".into(),
            scope: ApprovalScope::Session,
            target: None,
            comment: None,
        });
    }
    options.push(ScopeOption {
        label: "This project".into(),
        scope: ApprovalScope::Project,
        target: None,
        comment: None,
    });
    options.push(ScopeOption {
        label: "Globally".into(),
        scope: ApprovalScope::Global,
        target: None,
        comment: None,
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
            comment: None,
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
        let request = ApprovalFormRequest::new(
            "HTTP GET https://example.com/path",
            vec![ApprovalFormContext {
                label: "Project".into(),
                value: "/work/project".into(),
            }],
            None,
            vec![ApprovalScope::Once, ApprovalScope::Project],
            vec![ApprovalFormField {
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
        );

        let json = request.to_json();

        assert_eq!(json["version"], 1);
        assert_eq!(json["scopes"][0]["value"], "once");
        assert_eq!(json["fields"][0]["kind"], "choice");
        assert_eq!(json["fields"][0]["options"][1]["value"], "all");
    }
}

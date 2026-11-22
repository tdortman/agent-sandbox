use std::collections::HashMap;

use agent_sandbox_core::{ApprovalScope, ApprovalTarget};
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

/// A decision ready to send to policyd: the user's action with its scope,
/// target and comment.
#[derive(Debug, Clone)]
pub struct ReviewedChoice {
    pub(crate) action: PromptAction,
    pub(crate) choice: ScopeOption,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalFormContext {
    pub(crate) label: String,
    pub(crate) value: String,
}

#[derive(Debug, Clone)]
pub struct ApprovalFormPresentation {
    pub(crate) heading: String,
    pub(crate) subject: String,
    pub(crate) details: Vec<ApprovalFormContext>,
    pub(crate) warning: Option<String>,
}

impl ApprovalFormPresentation {
    pub(crate) fn new(heading: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            heading: heading.into(),
            subject: subject.into(),
            details: Vec::new(),
            warning: None,
        }
    }
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
            .map(|scope| json!({ "value": scope.as_str(), "label": scope_label(*scope) }))
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
            let mut pres = json!({
                "heading": presentation.heading,
                "subject": presentation.subject,
            });
            if !presentation.details.is_empty() {
                pres["details"] = json!(
                    presentation
                        .details
                        .iter()
                        .map(|detail| json!({ "label": detail.label, "value": detail.value }))
                        .collect::<Vec<_>>()
                );
            }
            if let Some(warning) = &presentation.warning {
                pres["warning"] = json!(warning);
            }
            request["presentation"] = pres;
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

const fn scope_label(scope: ApprovalScope) -> &'static str {
    match scope {
        ApprovalScope::Once => "Once",
        ApprovalScope::Session => "This session",
        ApprovalScope::ProjectPackage => "This project, this package",
        ApprovalScope::Project => "This project, all packages",
        ApprovalScope::GlobalPackage => "All projects, this package",
        ApprovalScope::Global => "Everywhere",
    }
}

#[must_use]
pub fn scope_only_options(session_available: bool, package_available: bool) -> Vec<ScopeOption> {
    ApprovalScope::LADDER
        .into_iter()
        .filter(|scope| scope.is_available(session_available, package_available))
        .map(|scope| ScopeOption {
            label: scope_label(scope).into(),
            scope,
            target: None,
            comment: None,
        })
        .collect()
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
        ApprovalFormPresentation, ApprovalFormRequest, ApprovalScope, scope_only_options,
    };

    #[test]
    fn review_request_serializes_presentation_details_and_warning_when_present() {
        let minimal = ApprovalFormRequest::new(
            "summary",
            Vec::new(),
            Some(ApprovalFormPresentation::new("Allow?", "target")),
            vec![ApprovalScope::Once],
            Vec::new(),
        )
        .to_json();
        assert_eq!(minimal["presentation"]["heading"], "Allow?");
        assert_eq!(minimal["presentation"]["subject"], "target");
        assert!(minimal["presentation"].get("details").is_none());
        assert!(minimal["presentation"].get("warning").is_none());

        let rich = ApprovalFormRequest::new(
            "summary",
            Vec::new(),
            Some(ApprovalFormPresentation {
                heading: "Delete?".into(),
                subject: "GitHub token".into(),
                details: vec![ApprovalFormContext {
                    label: "Keyring".into(),
                    value: "kdewallet (default)".into(),
                }],
                warning: Some("Permanent delete.".into()),
            }),
            vec![ApprovalScope::Once],
            Vec::new(),
        )
        .to_json();
        assert_eq!(rich["presentation"]["details"][0]["label"], "Keyring");
        assert_eq!(
            rich["presentation"]["details"][0]["value"],
            "kdewallet (default)"
        );
        assert_eq!(rich["presentation"]["warning"], "Permanent delete.");
    }

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

    fn labels(session_available: bool, package_available: bool) -> Vec<String> {
        scope_only_options(session_available, package_available)
            .into_iter()
            .map(|option| option.label)
            .collect()
    }

    #[test]
    fn scope_options_follow_ladder_order_and_availability() {
        assert_eq!(labels(true, true), [
            "Once",
            "This session",
            "This project, this package",
            "This project, all packages",
            "All projects, this package",
            "Everywhere",
        ]);

        assert_eq!(labels(true, false), [
            "Once",
            "This session",
            "This project, all packages",
            "Everywhere",
        ]);

        assert_eq!(labels(false, true), [
            "Once",
            "This project, this package",
            "This project, all packages",
            "All projects, this package",
            "Everywhere",
        ]);
    }
}

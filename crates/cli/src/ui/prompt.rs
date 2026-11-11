//! Data describing one approval prompt, and the form helpers every request
//! kind shares.
//!
//! A [`Prompt`] is built by a pure per-kind function in [`super::kinds`]; the
//! settlement driver in [`super::settle`] decides what to show and what to
//! tell policyd.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, HttpRequest, SandboxPaths, contract_project_path,
};

use super::options::{
    ApprovalFormContext, ApprovalFormControl, ApprovalFormField, ApprovalFormOption,
    ApprovalFormRequest, ApprovalFormResult, PromptAction, scope_only_options,
};

/// Turns the values of a submitted review form into the rule target they
/// describe, or `None` when the form does not describe a target that covers
/// the request.
pub type TargetParser = Arc<dyn Fn(&ApprovalFormResult) -> Option<ApprovalTarget> + Send + Sync>;

/// Turns free text typed into the fallback prompt into a rule target.
pub type TextTargetParser = Arc<dyn Fn(&str) -> Option<ApprovalTarget> + Send + Sync>;

/// The identity of the UI client a push reached, shared by every prompt it
/// shows.
pub struct ClientContext<'a> {
    pub socket: &'a Path,
    pub paths: &'a SandboxPaths,

    /// Policyd session of this UI client; `None` until registration settles.
    pub session_id: Option<&'a str>,
    pub sandbox_session_id: Option<&'a str>,
}

/// Who and what a prompt is about, as carried by the push.
pub struct Origin {
    pub id: String,
    pub sandbox_session_id: Option<String>,
    pub package: Option<String>,

    /// The client's paths merged with the push's cwd, home and project root.
    pub paths: SandboxPaths,
}

/// Everything the driver needs to settle one pending request.
pub struct Prompt {
    pub origin: Origin,

    /// Form shown by the graphical review dialog.
    pub review: ApprovalFormRequest,

    /// Maps a submitted form to the rule target; also validates the form
    /// while the dialog is open.
    pub parse_target: TargetParser,

    /// Questions asked in sequence when no review dialog is available.
    pub fallback: Fallback,
}

/// Sequential action, scope and target questions for the fallback prompt.
pub struct Fallback {
    /// Title of the allow/deny question.
    pub action_title: String,

    /// Names the request kind in the scope question title.
    pub scope_phrase: String,
    pub target: FallbackTarget,
}

/// How the fallback prompt obtains the target of a non-`Once` decision.
pub enum FallbackTarget {
    /// The request's own target; nothing to ask.
    Fixed(ApprovalTarget),

    /// One text question.
    Text(TextTarget),

    /// A method choice followed by an editable URL, re-asked until it covers
    /// the request.
    Http(HttpRequest),
}

pub struct TextTarget {
    pub title: TextTitle,
    pub default: String,
    pub parse: TextTargetParser,
}

pub enum TextTitle {
    /// A complete title, independent of the chosen action.
    Fixed(String),

    /// `"{tag}: {allow|deny} {noun}?"`.
    ForAction { tag: String, noun: String },
}

impl TextTitle {
    pub fn render(&self, action: PromptAction) -> String {
        match self {
            Self::Fixed(title) => title.clone(),
            Self::ForAction { tag, noun } => format!("{tag}: {} {noun}?", action.verb()),
        }
    }
}

/// Default project-relative rule path shown in approval prompts.
pub fn suggest_project_rule_path(path: &Path, project_root: Option<&Path>) -> String {
    contract_project_path(path, project_root)
        .display()
        .to_string()
}

pub fn valid_rule_path(value: &str) -> Option<PathBuf> {
    let value = value.trim();
    (!value.is_empty() && !value.contains('\0')).then(|| PathBuf::from(value))
}

/// Prompt identity prefix: "agent-sandbox" or "agent-sandbox (omp)".
///
/// The package name identifies the sandboxed application (omp, codex, ...);
/// showing it in every prompt title and dialog summary lets the user tell
/// requests from concurrently running packages apart.
pub fn prompt_tag(package: Option<&str>) -> String {
    package.map_or_else(
        || "agent-sandbox".to_owned(),
        |p| format!("agent-sandbox ({p})"),
    )
}

/// Review form for `fields` plus the context rows and scope choices every
/// kind shows.
pub fn review_form(
    origin: &Origin,
    session_id: Option<&str>,
    presentation: super::options::ApprovalFormPresentation,
    fields: Vec<ApprovalFormField>,
) -> ApprovalFormRequest {
    let package = origin.package.as_deref();

    ApprovalFormRequest::new(
        prompt_tag(package),
        approval_context(&origin.paths, session_id, package),
        Some(presentation),
        approval_scopes(session_id.is_some(), package.is_some()),
        fields,
    )
}

fn approval_context(
    paths: &SandboxPaths,
    session_id: Option<&str>,
    package: Option<&str>,
) -> Vec<ApprovalFormContext> {
    let mut context = Vec::new();
    let project_root = paths.project_root();

    if let Some(package) = package {
        context.push(ApprovalFormContext {
            label: "Package".into(),
            value: package.into(),
        });
    }

    if let Some(project) = project_root {
        context.push(ApprovalFormContext {
            label: "Project".into(),
            value: project.display().to_string(),
        });
    }

    if let Some(cwd) = paths.cwd()
        && project_root.is_none_or(|project| project != cwd)
    {
        context.push(ApprovalFormContext {
            label: "Working directory".into(),
            value: cwd.display().to_string(),
        });
    }

    context.push(ApprovalFormContext {
        label: "Session".into(),
        value: session_id.map_or_else(|| "Unavailable".into(), str::to_owned),
    });

    context
}

fn approval_scopes(session_available: bool, package_available: bool) -> Vec<ApprovalScope> {
    scope_only_options(session_available, package_available)
        .into_iter()
        .map(|option| option.scope)
        .collect()
}

pub fn text_field(id: &'static str, label: &str, value: String) -> ApprovalFormField {
    ApprovalFormField {
        id,
        label: label.into(),
        control: ApprovalFormControl::Text { value },
    }
}

pub fn comment_field() -> ApprovalFormField {
    text_field("comment", "Policy comment (optional)", String::new())
}

pub fn choice_field(
    id: &'static str,
    label: &str,
    value: &str,
    options: Vec<ApprovalFormOption>,
) -> ApprovalFormField {
    ApprovalFormField {
        id,
        label: label.into(),
        control: ApprovalFormControl::Choice {
            value: value.into(),
            options,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use agent_sandbox_core::SandboxPaths;

    use super::{TextTitle, approval_context, suggest_project_rule_path, valid_rule_path};
    use crate::ui::options::PromptAction;

    #[test]
    fn suggest_project_rule_path_shows_relative_unix_socket_path() {
        assert_eq!(
            suggest_project_rule_path(
                Path::new("/home/user/repo/.agent.sock"),
                Some(Path::new("/home/user/repo")),
            ),
            "./.agent.sock"
        );
    }

    #[test]
    fn approval_context_omits_cwd_when_it_matches_project() {
        let paths = SandboxPaths::new("/work/project", "/home/user", "/work/project");
        let context = approval_context(&paths, Some("session-id"), None);
        assert_eq!(context.len(), 2);
        assert_eq!(context[0].label, "Project");
        assert_eq!(context[1].label, "Session");
    }

    #[test]
    fn approval_context_keeps_distinct_cwd() {
        let paths = SandboxPaths::new("/work/project/src", "/home/user", "/work/project");
        let context = approval_context(&paths, Some("session-id"), None);
        assert_eq!(context.len(), 3);
        assert_eq!(context[1].label, "Working directory");
    }

    #[test]
    fn approval_context_leads_with_the_package() {
        let paths = SandboxPaths::new("/work/project", "/home/user", "/work/project");
        let context = approval_context(&paths, Some("session-id"), Some("omp"));
        assert_eq!(context[0].label, "Package");
        assert_eq!(context[0].value, "omp");
    }

    #[test]
    fn approval_context_marks_a_missing_session() {
        let paths = SandboxPaths::new("/work/project", "/home/user", "/work/project");
        let context = approval_context(&paths, None, None);
        assert_eq!(
            context.last().map(|row| row.value.as_str()),
            Some("Unavailable")
        );
    }

    #[test]
    fn rule_path_text_is_trimmed_and_rejects_blank() {
        assert!(valid_rule_path("   ").is_none());
        assert!(valid_rule_path("a\0b").is_none());

        assert_eq!(
            valid_rule_path(" ./src "),
            Some(Path::new("./src").to_path_buf())
        );
    }

    #[test]
    fn text_title_names_the_chosen_action() {
        let title = TextTitle::ForAction {
            tag: "agent-sandbox".into(),
            noun: "sudo command".into(),
        };

        assert_eq!(
            title.render(PromptAction::Deny),
            "agent-sandbox: deny sudo command?"
        );

        assert_eq!(
            TextTitle::Fixed("fixed".into()).render(PromptAction::Allow),
            "fixed"
        );
    }
}

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use agent_sandbox_core::{ApprovalTarget, FileAccess, FilesystemRule};

use crate::ui::{
    options::{ApprovalFormPresentation, ApprovalFormResult},
    prompt::{
        Fallback, FallbackTarget, Origin, Prompt, TextTarget, TextTitle, comment_field, prompt_tag,
        review_form, suggest_project_rule_path, text_field, valid_rule_path,
    },
};

/// The fields of a filesystem push that shape its prompt.
pub struct FilesystemRequest {
    pub path: PathBuf,
    pub access: FileAccess,
}

pub fn prompt(session_id: Option<&str>, origin: Origin, request: FilesystemRequest) -> Prompt {
    let FilesystemRequest { path, access } = request;
    let default_rule_path = suggest_project_rule_path(&path, origin.paths.project_root());
    let tag = prompt_tag(origin.package.as_deref());

    let review = review_form(
        &origin,
        session_id,
        filesystem_presentation(access, &default_rule_path),
        vec![
            text_field("target", "Path or pattern", default_rule_path.clone()),
            comment_field(),
        ],
    );

    let fallback = Fallback {
        action_title: format!("{tag}: filesystem {access} action?"),
        scope_phrase: "filesystem".into(),
        target: FallbackTarget::Text(TextTarget {
            title: TextTitle::Fixed(format!("{tag}: allow filesystem {access} path?")),
            default: default_rule_path,
            parse: Arc::new(|text| {
                Some(ApprovalTarget::FilesystemPath {
                    path: PathBuf::from(text),
                })
            }),
        }),
    };

    let project_root = origin.paths.project_root_path();

    Prompt {
        origin,
        review,
        parse_target: Arc::new(move |result| {
            parse_filesystem_target(result, &path, project_root.as_deref())
        }),
        fallback,
    }
}

fn filesystem_presentation(access: FileAccess, subject: &str) -> ApprovalFormPresentation {
    let heading = match access {
        FileAccess::Read => "Read this file?",
        FileAccess::Write => "Write to this file?",
        FileAccess::ReadWrite => "Read and write this file?",
        FileAccess::Execute => "Execute this file?",
        FileAccess::All => "Allow full access to this file?",
    };

    ApprovalFormPresentation {
        heading: heading.into(),
        subject: subject.into(),
    }
}

/// Parse and validate an editable filesystem path against the request.
fn parse_filesystem_target(
    result: &ApprovalFormResult,
    requested_path: &Path,
    project_root: Option<&Path>,
) -> Option<ApprovalTarget> {
    let path = valid_rule_path(result.values.get("target")?)?;

    if !FilesystemRule::new(path.clone(), FileAccess::Read, "")
        .path_matches(requested_path, project_root)
    {
        return None;
    }

    Some(ApprovalTarget::FilesystemPath { path })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use agent_sandbox_core::{ApprovalTarget, FileAccess};

    use super::{FilesystemRequest, filesystem_presentation, parse_filesystem_target, prompt};
    use crate::ui::{
        kinds::test_support::{form_result, origin},
        prompt::FallbackTarget,
    };

    #[test]
    fn filesystem_presentation_names_the_access() {
        let presentation = filesystem_presentation(FileAccess::ReadWrite, "./a");
        assert_eq!(presentation.heading, "Read and write this file?");
        assert_eq!(presentation.subject, "./a");
    }

    #[test]
    fn filesystem_target_rejects_typo_path() {
        let result = form_result("./some/.conff");

        assert!(
            parse_filesystem_target(
                &result,
                Path::new("/home/user/repo/some/.conf"),
                Some(Path::new("/home/user/repo"))
            )
            .is_none()
        );
    }

    #[test]
    fn filesystem_target_accepts_exact_path() {
        let result = form_result("./config/.conf");

        assert_eq!(
            parse_filesystem_target(
                &result,
                Path::new("/home/user/repo/config/.conf"),
                Some(Path::new("/home/user/repo"))
            ),
            Some(ApprovalTarget::FilesystemPath {
                path: "./config/.conf".into(),
            })
        );
    }

    #[test]
    fn filesystem_target_accepts_ancestor_glob() {
        let result = form_result("./config/*");

        assert!(
            parse_filesystem_target(
                &result,
                Path::new("/home/user/repo/config/.conf"),
                Some(Path::new("/home/user/repo"))
            )
            .is_some()
        );
    }

    #[test]
    fn prompt_suggests_a_project_relative_path_and_validates_against_the_project() {
        let prompt = prompt(Some("session"), origin(None), FilesystemRequest {
            path: "/home/user/repo/config/.conf".into(),
            access: FileAccess::Read,
        });

        let presentation = prompt.review.presentation.as_ref().expect("presentation");
        assert_eq!(presentation.subject, "./config/.conf");

        assert!((prompt.parse_target)(&form_result("./config/*")).is_some());
        assert!((prompt.parse_target)(&form_result("./other/*")).is_none());

        assert_eq!(
            prompt.fallback.action_title,
            "agent-sandbox: filesystem read action?"
        );

        let FallbackTarget::Text(text) = &prompt.fallback.target else {
            panic!("filesystem fallback asks for text");
        };

        assert_eq!(text.default, "./config/.conf");
    }
}

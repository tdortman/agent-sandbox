use std::sync::Arc;

use agent_sandbox_core::{ApprovalTarget, SudoRule};

use crate::ui::{
    choice::format_elevation_title,
    options::{ApprovalFormPresentation, ApprovalFormResult, format_command},
    prompt::{
        Fallback, FallbackTarget, Origin, Prompt, TextTarget, TextTitle, comment_field, prompt_tag,
        review_form, text_field,
    },
};

pub fn prompt(session_id: Option<&str>, origin: Origin, argv: Vec<String>) -> Prompt {
    let tag = prompt_tag(origin.package.as_deref());

    let review = review_form(&origin, session_id, elevation_presentation(&argv), vec![
        text_field("target", "Command or pattern", argv.join(" ")),
        comment_field(),
    ]);

    let fallback = Fallback {
        action_title: format!("{tag}: {}", format_elevation_title(&argv)),
        scope_phrase: "sudo".into(),
        target: FallbackTarget::Text(TextTarget {
            title: TextTitle::ForAction {
                tag,
                noun: "sudo command".into(),
            },
            default: argv.join(" "),
            parse: Arc::new(|text| {
                parse_sudo_argv(text).map(|argv| ApprovalTarget::SudoCommand { argv })
            }),
        }),
    };

    Prompt {
        origin,
        review,
        parse_target: Arc::new(move |result| parse_sudo_target(result, &argv)),
        fallback,
    }
}

fn elevation_presentation(argv: &[String]) -> ApprovalFormPresentation {
    ApprovalFormPresentation {
        heading: "Run this command with elevated privileges?".into(),
        subject: format_command(argv),
    }
}

fn parse_sudo_argv(value: &str) -> Option<Vec<String>> {
    let mut tokens: Vec<&str> = value.split_whitespace().collect();
    if tokens.first() == Some(&"sudo") {
        tokens.remove(0);
    }
    (!tokens.is_empty() && tokens.iter().all(|token| !token.contains('\0')))
        .then(|| tokens.into_iter().map(str::to_owned).collect())
}

/// Parse and validate an editable sudo command prefix or pattern against the
/// request.
fn parse_sudo_target(
    result: &ApprovalFormResult,
    requested_argv: &[String],
) -> Option<ApprovalTarget> {
    let argv = parse_sudo_argv(result.values.get("target")?)?;

    if !SudoRule::new(argv.clone(), "").matches(requested_argv) {
        return None;
    }

    Some(ApprovalTarget::SudoCommand { argv })
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::ApprovalTarget;

    use super::{elevation_presentation, parse_sudo_argv, parse_sudo_target, prompt};
    use crate::ui::{
        kinds::test_support::{form_result, origin},
        prompt::FallbackTarget,
    };

    #[test]
    fn elevation_presentation_uses_full_sudo_command() {
        let argv = vec!["nixos-rebuild".into(), "switch".into()];
        let presentation = elevation_presentation(&argv);

        assert_eq!(
            presentation.heading,
            "Run this command with elevated privileges?"
        );

        assert_eq!(presentation.subject, "sudo nixos-rebuild switch");
    }

    #[test]
    fn sudo_text_drops_a_leading_sudo_and_rejects_empty_input() {
        assert_eq!(
            parse_sudo_argv("sudo id -u"),
            Some(vec!["id".to_owned(), "-u".to_owned()])
        );

        assert!(parse_sudo_argv("  sudo  ").is_none());
        assert!(parse_sudo_argv("").is_none());
    }

    #[test]
    fn sudo_target_accepts_prefix_and_glob_and_rejects_mismatch() {
        let requested = vec![
            "systemctl".to_string(),
            "restart".to_string(),
            "nginx-staging".to_string(),
        ];

        assert_eq!(
            parse_sudo_target(&form_result("systemctl restart"), &requested),
            Some(ApprovalTarget::SudoCommand {
                argv: vec!["systemctl".into(), "restart".into()],
            })
        );

        assert_eq!(
            parse_sudo_target(&form_result("sudo systemctl restart nginx*"), &requested),
            Some(ApprovalTarget::SudoCommand {
                argv: vec!["systemctl".into(), "restart".into(), "nginx*".into()],
            })
        );

        assert!(parse_sudo_target(&form_result("systemctl stop"), &requested).is_none());
    }

    #[test]
    fn prompt_asks_for_the_command_text_in_the_fallback() {
        let prompt = prompt(Some("session"), origin(None), vec![
            "systemctl".into(),
            "restart".into(),
            "nginx".into(),
        ]);

        assert_eq!(
            prompt.fallback.action_title,
            "agent-sandbox: agent-sandbox: sudo systemctl restart nginx"
        );

        let FallbackTarget::Text(text) = &prompt.fallback.target else {
            panic!("sudo fallback asks for text");
        };

        assert_eq!(text.default, "systemctl restart nginx");

        assert_eq!(
            (text.parse)("systemctl restart"),
            Some(ApprovalTarget::SudoCommand {
                argv: vec!["systemctl".into(), "restart".into()],
            })
        );

        assert!((text.parse)("").is_none());
    }
}

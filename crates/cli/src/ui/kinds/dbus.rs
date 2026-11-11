use std::sync::Arc;

use agent_sandbox_core::{ApprovalTarget, DbusRule, DbusTarget};

use crate::ui::{
    bus_name, dbus_fd_display, message_kind_name,
    options::{ApprovalFormPresentation, ApprovalFormResult},
    prompt::{
        Fallback, FallbackTarget, Origin, Prompt, comment_field, prompt_tag, review_form,
        text_field,
    },
    signature_display,
};

pub fn prompt(session_id: Option<&str>, origin: Origin, target: DbusTarget) -> Prompt {
    let tag = prompt_tag(origin.package.as_deref());

    let review = review_form(&origin, session_id, dbus_presentation(&target), vec![
        text_field("bus", "Bus", bus_name(target.bus).into()),
        text_field("destination", "Destination", target.destination.clone()),
        text_field("object_path", "Object path", target.object_path.clone()),
        text_field("interface", "Interface", target.interface.clone()),
        text_field("member", "Member", target.member.clone()),
        text_field(
            "message_kind",
            "Message kind",
            message_kind_name(target.message_kind).into(),
        ),
        text_field(
            "signature",
            "Signature",
            signature_display(&target.signature).into(),
        ),
        text_field("fd_metadata", "FD metadata", dbus_fd_display(&target)),
        comment_field(),
    ]);

    let fallback = Fallback {
        action_title: format!(
            "{tag}: D-Bus {} {}",
            message_kind_name(target.message_kind),
            target.member,
        ),
        scope_phrase: "D-Bus".into(),
        target: FallbackTarget::Fixed(ApprovalTarget::Dbus {
            target: target.clone(),
        }),
    };

    Prompt {
        origin,
        review,
        parse_target: Arc::new(move |result| parse_dbus_target(result, &target)),
        fallback,
    }
}

fn dbus_presentation(target: &DbusTarget) -> ApprovalFormPresentation {
    let fds = if target.fd_metadata.is_empty() {
        "count=0".to_owned()
    } else {
        format!(
            "count={}; {}",
            target.fd_metadata.len(),
            dbus_fd_display(target)
        )
    };

    ApprovalFormPresentation {
        heading: "Allow this D-Bus message?".into(),
        subject: format!(
            "bus: {}\ndestination: {}\nobject path: {}\ninterface: {}\nmember: {}\nmessage kind: \
             {}\nsignature: {}\nFDs: {fds}",
            bus_name(target.bus),
            target.destination,
            target.object_path,
            target.interface,
            target.member,
            message_kind_name(target.message_kind),
            signature_display(&target.signature),
        ),
    }
}

/// Parse and validate an editable D-Bus target against the request.
fn parse_dbus_target(
    result: &ApprovalFormResult,
    requested: &DbusTarget,
) -> Option<ApprovalTarget> {
    let fd_metadata = result.values.get("fd_metadata")?;
    let any_fd_metadata = fd_metadata == "*";
    if result.values.get("bus")? != bus_name(requested.bus)
        || result.values.get("message_kind")? != message_kind_name(requested.message_kind)
        || (!any_fd_metadata && fd_metadata != &dbus_fd_display(requested))
    {
        return None;
    }

    let target = DbusTarget {
        bus: requested.bus,
        destination: result.values.get("destination")?.clone(),
        object_path: result.values.get("object_path")?.clone(),
        interface: result.values.get("interface")?.clone(),
        member: result.values.get("member")?.clone(),
        message_kind: requested.message_kind,
        signature: match result.values.get("signature")?.as_str() {
            "<empty>" => String::new(),
            signature => signature.to_owned(),
        },
        fd_metadata: if any_fd_metadata {
            Vec::new()
        } else {
            requested.fd_metadata.clone()
        },
        any_fd_metadata,
    };

    if !DbusRule::new(target.clone(), "").matches(requested) {
        return None;
    }

    Some(ApprovalTarget::Dbus { target })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use agent_sandbox_core::{
        ApprovalScope, ApprovalTarget, DbusFdMetadata, DbusMessageKind, DbusRule, DbusTarget,
    };

    use super::{dbus_presentation, parse_dbus_target, prompt};
    use crate::ui::{
        kinds::test_support::origin,
        options::{ApprovalFormResult, PromptAction},
        prompt::FallbackTarget,
    };

    fn introspect() -> DbusTarget {
        DbusTarget::session(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Introspectable",
            "Introspect",
            DbusMessageKind::MethodCall,
            "",
            Vec::new(),
        )
    }

    fn submitted(values: &[[&str; 2]]) -> ApprovalFormResult {
        ApprovalFormResult {
            action: Some(PromptAction::Allow),
            scope: ApprovalScope::Project,
            values: values
                .iter()
                .map(|[key, value]| ((*key).to_owned(), (*value).to_owned()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn dbus_presentation_lists_every_message_field() {
        let presentation = dbus_presentation(&introspect());
        assert_eq!(presentation.heading, "Allow this D-Bus message?");

        assert_eq!(
            presentation.subject,
            "bus: session\ndestination: org.freedesktop.DBus\nobject path: \
             /org/freedesktop/DBus\ninterface: org.freedesktop.DBus.Introspectable\nmember: \
             Introspect\nmessage kind: method_call\nsignature: <empty>\nFDs: count=0"
        );
    }

    #[test]
    fn dbus_target_wildcards_match_requested_message() {
        let requested = introspect();

        let result = submitted(&[
            ["bus", "session"],
            ["destination", "*"],
            ["object_path", "**"],
            ["interface", "org.freedesktop.DBus.Introspectable"],
            ["member", "Introspect"],
            ["message_kind", "method_call"],
            ["signature", "<empty>"],
            ["fd_metadata", ""],
        ]);

        let expected = DbusTarget {
            destination: "*".into(),
            object_path: "**".into(),
            ..requested.clone()
        };

        assert_eq!(
            parse_dbus_target(&result, &requested),
            Some(ApprovalTarget::Dbus { target: expected })
        );
    }

    #[test]
    fn dbus_signature_with_braces_matches_requested_message() {
        let requested = DbusTarget::session(
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets/aliases/default",
            "org.freedesktop.Secret.Collection",
            "SearchItems",
            DbusMessageKind::MethodCall,
            "a{ss}",
            Vec::new(),
        );

        let result = submitted(&[
            ["bus", "session"],
            ["destination", "org.freedesktop.secrets"],
            ["object_path", "/org/freedesktop/secrets/aliases/default"],
            ["interface", "org.freedesktop.Secret.Collection"],
            ["member", "SearchItems"],
            ["message_kind", "method_call"],
            ["signature", "a{ss}"],
            ["fd_metadata", ""],
        ]);

        assert!(parse_dbus_target(&result, &requested).is_some());
    }

    #[test]
    fn dbus_star_signature_and_fd_metadata_match_any_message() {
        let requested = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Send",
            DbusMessageKind::MethodCall,
            "h",
            vec![DbusFdMetadata {
                kind: "unknown".into(),
                read_only: false,
            }],
        );

        let result = submitted(&[
            ["bus", "session"],
            ["destination", "org.example.Service"],
            ["object_path", "/org/example/Object"],
            ["interface", "org.example.Interface"],
            ["member", "Send"],
            ["message_kind", "method_call"],
            ["signature", "*"],
            ["fd_metadata", "*"],
        ]);

        let Some(ApprovalTarget::Dbus { target }) = parse_dbus_target(&result, &requested) else {
            panic!("wildcard D-Bus target rejected");
        };
        let rule = DbusRule::new(target, "");

        let no_fds = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Send",
            DbusMessageKind::MethodCall,
            "",
            Vec::new(),
        );
        assert!(rule.matches(&requested));
        assert!(rule.matches(&no_fds));
    }

    #[test]
    fn dbus_target_rejects_a_changed_bus_or_message_kind() {
        let requested = introspect();

        let result = submitted(&[
            ["bus", "system"],
            ["destination", "org.freedesktop.DBus"],
            ["object_path", "/org/freedesktop/DBus"],
            ["interface", "org.freedesktop.DBus.Introspectable"],
            ["member", "Introspect"],
            ["message_kind", "method_call"],
            ["signature", "<empty>"],
            ["fd_metadata", ""],
        ]);

        assert!(parse_dbus_target(&result, &requested).is_none());
    }

    #[test]
    fn prompt_falls_back_to_the_requested_target_unchanged() {
        let requested = introspect();
        let prompt = prompt(Some("session"), origin(None), requested.clone());

        assert_eq!(
            prompt.fallback.action_title,
            "agent-sandbox: D-Bus method_call Introspect"
        );

        assert_eq!(prompt.fallback.scope_phrase, "D-Bus");

        let FallbackTarget::Fixed(target) = &prompt.fallback.target else {
            panic!("D-Bus fallback keeps the requested target");
        };

        assert_eq!(target, &ApprovalTarget::Dbus { target: requested });
    }
}

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use agent_sandbox_core::{
    ApprovalTarget, DeviceAccess, ResourceAccess, ResourceKind, ResourceRule, SocketAccess,
};

use crate::ui::{
    options::{ApprovalFormPresentation, ApprovalFormResult},
    prompt::{
        Fallback, FallbackTarget, Origin, Prompt, TextTarget, TextTitle, comment_field, prompt_tag,
        review_form, suggest_project_rule_path, text_field, valid_rule_path,
    },
};

/// The fields of a resource push that shape its prompt.
pub struct ResourceRequest {
    pub kind: ResourceKind,
    pub path: PathBuf,
    pub access: ResourceAccess,
}

pub fn prompt(session_id: Option<&str>, origin: Origin, request: ResourceRequest) -> Prompt {
    let ResourceRequest { kind, path, access } = request;
    let display_path = suggest_project_rule_path(&path, origin.paths.project_root());
    let tag = prompt_tag(origin.package.as_deref());

    let review = review_form(
        &origin,
        session_id,
        resource_presentation(access, kind, Path::new(&display_path)),
        vec![
            text_field("target", "Path or pattern", display_path.clone()),
            comment_field(),
        ],
    );

    let fallback = Fallback {
        action_title: format!("{tag}: {kind} {access} {display_path}"),
        scope_phrase: kind.to_string(),
        target: FallbackTarget::Text(TextTarget {
            title: TextTitle::Fixed(format!("{tag}: allow {kind} {access} path?")),
            default: display_path,
            parse: Arc::new(move |text| {
                Some(ApprovalTarget::ResourcePath {
                    resource_kind: kind,
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
            parse_resource_target(result, kind, &path, project_root.as_deref())
        }),
        fallback,
    }
}

fn resource_presentation(
    access: ResourceAccess,
    kind: ResourceKind,
    path: &Path,
) -> ApprovalFormPresentation {
    let kind_label = match kind {
        ResourceKind::UnixSocket => "Unix socket",
        ResourceKind::Device => "device",
    };

    let heading = match access {
        ResourceAccess::Socket(SocketAccess::Connect) => {
            format!("Connect to this {kind_label}?")
        }
        ResourceAccess::Socket(SocketAccess::Send) => {
            format!("Send data to this {kind_label}?")
        }
        ResourceAccess::Socket(SocketAccess::All) => {
            format!("Connect to and send data to this {kind_label}?")
        }
        ResourceAccess::Device(DeviceAccess::Read) => {
            format!("Read from this {kind_label}?")
        }
        ResourceAccess::Device(DeviceAccess::Write) => {
            format!("Write to this {kind_label}?")
        }
        ResourceAccess::Device(DeviceAccess::ReadWrite) => {
            format!("Read and write this {kind_label}?")
        }
    };

    ApprovalFormPresentation {
        heading,
        subject: path.display().to_string(),
    }
}

/// Parse and validate an editable resource path against the request.
fn parse_resource_target(
    result: &ApprovalFormResult,
    kind: ResourceKind,
    requested_path: &Path,
    project_root: Option<&Path>,
) -> Option<ApprovalTarget> {
    let path = valid_rule_path(result.values.get("target")?)?;

    if !ResourceRule::new(
        kind,
        path.clone(),
        ResourceAccess::Socket(SocketAccess::Connect),
        "",
    )
    .path_matches(requested_path, project_root)
    {
        return None;
    }

    Some(ApprovalTarget::ResourcePath {
        resource_kind: kind,
        path,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use agent_sandbox_core::{
        ApprovalTarget, DeviceAccess, ResourceAccess, ResourceKind, SocketAccess,
    };

    use super::{ResourceRequest, parse_resource_target, prompt, resource_presentation};
    use crate::ui::{
        kinds::test_support::{form_result, origin},
        prompt::FallbackTarget,
    };

    #[test]
    fn resource_presentation_uses_human_readable_unix_socket_label() {
        let presentation = resource_presentation(
            ResourceAccess::Socket(SocketAccess::Connect),
            ResourceKind::UnixSocket,
            Path::new("/run/example.sock"),
        );

        assert_eq!(presentation.heading, "Connect to this Unix socket?");
        assert_eq!(presentation.subject, "/run/example.sock");
    }

    #[test]
    fn resource_presentation_describes_device_access() {
        let presentation = resource_presentation(
            ResourceAccess::Device(DeviceAccess::ReadWrite),
            ResourceKind::Device,
            Path::new("/dev/kvm"),
        );

        assert_eq!(presentation.heading, "Read and write this device?");
    }

    #[test]
    fn resource_target_rejects_nonmatching_path() {
        let result = form_result("/run/other.sock");

        assert!(
            parse_resource_target(
                &result,
                ResourceKind::UnixSocket,
                Path::new("/run/agent-sandbox/proxy-policy.sock"),
                None
            )
            .is_none()
        );
    }

    #[test]
    fn resource_target_accepts_matching_path() {
        let result = form_result("/run/agent-sandbox/*");

        assert_eq!(
            parse_resource_target(
                &result,
                ResourceKind::UnixSocket,
                Path::new("/run/agent-sandbox/proxy-policy.sock"),
                None
            ),
            Some(ApprovalTarget::ResourcePath {
                resource_kind: ResourceKind::UnixSocket,
                path: "/run/agent-sandbox/*".into(),
            })
        );
    }

    #[test]
    fn prompt_keeps_the_resource_kind_in_parsed_and_fallback_targets() {
        let prompt = prompt(Some("session"), origin(None), ResourceRequest {
            kind: ResourceKind::UnixSocket,
            path: "/home/user/repo/.agent.sock".into(),
            access: ResourceAccess::Socket(SocketAccess::Connect),
        });

        assert!((prompt.parse_target)(&form_result("./*.sock")).is_some());

        let FallbackTarget::Text(text) = &prompt.fallback.target else {
            panic!("resource fallback asks for text");
        };

        assert_eq!(text.default, "./.agent.sock");

        assert_eq!(
            (text.parse)("./.agent.sock"),
            Some(ApprovalTarget::ResourcePath {
                resource_kind: ResourceKind::UnixSocket,
                path: "./.agent.sock".into(),
            })
        );
    }
}

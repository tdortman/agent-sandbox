use std::{collections::BTreeMap, sync::Arc};

use agent_sandbox_core::{
    ApprovalTarget, RESERVED_SECRET_ATTRIBUTE_PREFIX, SecretAccess, SecretOperation,
    SecretPartition, SecretRequest, SecretTarget,
};

use crate::ui::{
    options::{
        ApprovalFormContext, ApprovalFormOption, ApprovalFormPresentation, ApprovalFormResult,
        PromptAction,
    },
    prompt::{
        Fallback, FallbackTarget, Origin, Prompt, choice_field, comment_field, prompt_tag,
        review_form, text_field,
    },
};

const ALL_ACCESS_VARIANTS: [SecretAccess; 5] = [
    SecretAccess::Read,
    SecretAccess::Write,
    SecretAccess::ReadWrite,
    SecretAccess::Delete,
    SecretAccess::All,
];

pub fn prompt(session_id: Option<&str>, origin: Origin, request: SecretRequest) -> Prompt {
    let package = origin.package.as_deref();
    let tag = prompt_tag(package);
    let attributed_package = package.is_some();

    let mode_options = vec![
        ApprovalFormOption {
            value: "preset".into(),
            label: preset_mode_label(&request, package),
        },
        ApprovalFormOption {
            value: "custom".into(),
            label: "Custom selector (edit collection / attributes / label below)".into(),
        },
    ];

    let default_access = match request.partition {
        SecretPartition::OwnPackage => SecretAccess::All,
        SecretPartition::Host => request.access,
    };

    let access_options = ALL_ACCESS_VARIANTS
        .iter()
        .copied()
        .filter(|variant| variant.covers(request.access))
        .map(|variant| ApprovalFormOption {
            value: variant.as_str().into(),
            label: access_option_label(variant, request.access),
        })
        .collect();

    let default_collection = if request.is_default_collection {
        "default".to_owned()
    } else {
        request.collection.clone()
    };

    let default_attributes = format_editable_attributes(&request.attributes);
    let default_label = if request.attributes.is_empty() {
        request.label.clone()
    } else {
        "<any>".to_owned()
    };

    let review = review_form(
        &origin,
        session_id,
        secret_presentation(&request, package),
        vec![
            choice_field("mode", "Rule selector", "preset", mode_options),
            choice_field(
                "access",
                "Access level",
                default_access.as_str(),
                access_options,
            ),
            text_field("collection", "Collection", default_collection),
            text_field("attributes", "Attributes", default_attributes),
            text_field("label", "Label", default_label),
            comment_field(),
        ],
    );

    let fallback = Fallback {
        action_title: format!(
            "{tag}: secret {} ({})",
            request.operation, request.partition
        ),
        scope_phrase: "secret".into(),
        target: FallbackTarget::Fixed(ApprovalTarget::Secret {
            target: SecretTarget::exact_for_request(&request),
        }),
    };

    Prompt {
        origin,
        review,
        parse_target: Arc::new(move |result| {
            parse_secret_target(result, &request, attributed_package)
        }),
        fallback,
    }
}

fn preset_mode_label(request: &SecretRequest, package: Option<&str>) -> String {
    match request.partition {
        SecretPartition::OwnPackage => {
            let who = package.unwrap_or("package");
            format!("Entire {who} partition (recommended)")
        }
        SecretPartition::Host => "This exact host secret (recommended)".into(),
    }
}

fn access_option_label(variant: SecretAccess, requested: SecretAccess) -> String {
    let base = match variant {
        SecretAccess::Read => "Read only",
        SecretAccess::Write => "Write only",
        SecretAccess::ReadWrite => "Read & write",
        SecretAccess::Delete => "Delete only",
        SecretAccess::All => "All (read, write, delete)",
    };

    if variant == requested {
        format!("{base} (requested)")
    } else {
        base.to_owned()
    }
}

fn format_editable_attributes(attributes: &BTreeMap<String, String>) -> String {
    if attributes.is_empty() {
        "<any>".to_owned()
    } else {
        attributes
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn secret_presentation(request: &SecretRequest, package: Option<&str>) -> ApprovalFormPresentation {
    let who = package.unwrap_or("sandbox");

    let verb = match request.operation {
        SecretOperation::GetSecret | SecretOperation::GetSecrets => "read",
        SecretOperation::CreateItem if request.replace => "store or replace",
        SecretOperation::CreateItem => "store",
        SecretOperation::SetSecret => "overwrite",
        SecretOperation::SetAttributes => "modify attributes of",
        SecretOperation::SetLabel => "rename",
        SecretOperation::Delete => "delete",
    };

    let target_phrase = match request.partition {
        SecretPartition::OwnPackage => format!("a secret in {who}'s own partition"),
        SecretPartition::Host => "a host secret".to_owned(),
    };

    let mut subject_lines = Vec::new();
    if !request.label.is_empty() {
        subject_lines.push(request.label.clone());
    }
    if !request.attributes.is_empty() {
        let joined = request
            .attributes
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(", ");
        subject_lines.push(joined);
    }
    let subject = if subject_lines.is_empty() {
        "<unnamed secret>".to_owned()
    } else {
        subject_lines.join("\n")
    };

    let collection_display = if request.is_default_collection {
        format!("{} (default)", request.collection)
    } else {
        request.collection.clone()
    };
    let partition_display = match request.partition {
        SecretPartition::OwnPackage => {
            let owner = package.unwrap_or("unattributed");
            format!("{owner} partition")
        }
        SecretPartition::Host => "host keyring".to_owned(),
    };

    let mut details = vec![ApprovalFormContext {
        label: "Keyring".into(),
        value: format!("{collection_display} \u{00b7} {partition_display}"),
    }];

    if let Some(batch) = request.batch {
        details.push(ApprovalFormContext {
            label: "Batch".into(),
            value: format!(
                "item {} of {} (all items must be allowed)",
                batch.index, batch.total
            ),
        });
    }

    let warning =
        if request.partition == SecretPartition::Host && request.access == SecretAccess::Delete {
            Some("Permanently deletes a host secret outside any package partition.".to_owned())
        } else if request.partition == SecretPartition::Host
            && request.operation == SecretOperation::SetSecret
        {
            Some("Overwrites an existing host secret outside any package partition.".to_owned())
        } else if request.operation == SecretOperation::CreateItem
            && request.replace
            && request.partition == SecretPartition::OwnPackage
        {
            Some(
                "replace=true applies only inside this package's own partition; host secrets are \
                 never overwritten."
                    .to_owned(),
            )
        } else if matches!(
            request.operation,
            SecretOperation::SetAttributes | SecretOperation::SetLabel
        ) {
            Some(
                "Changing item metadata requires write permission for both the current and new \
                 secret identities."
                    .to_owned(),
            )
        } else {
            None
        };

    ApprovalFormPresentation {
        heading: format!("Allow {who} to {verb} {target_phrase}?"),
        subject,
        details,
        warning,
    }
}

fn parse_access(value: &str) -> Option<SecretAccess> {
    match value {
        "read" => Some(SecretAccess::Read),
        "write" => Some(SecretAccess::Write),
        "read_write" => Some(SecretAccess::ReadWrite),
        "delete" => Some(SecretAccess::Delete),
        "all" => Some(SecretAccess::All),
        _ => None,
    }
}

fn parse_attributes(raw: &str) -> Option<BTreeMap<String, String>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "<any>" {
        return Some(BTreeMap::new());
    }

    let mut attributes = BTreeMap::new();
    for entry in trimmed.split(['\n', ',']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        let (key, value) = entry.split_once('=')?;
        let key = key.trim();
        let value = value.trim();

        if key.is_empty() || key.starts_with(RESERVED_SECRET_ATTRIBUTE_PREFIX) {
            return None;
        }

        attributes.insert(key.to_owned(), value.to_owned());
    }

    Some(attributes)
}

/// Parse and validate an editable secret target from a Variant C approval form.
fn parse_secret_target(
    result: &ApprovalFormResult,
    requested: &SecretRequest,
    attributed_package: bool,
) -> Option<ApprovalTarget> {
    if let Some(partition) = result.values.get("partition")
        && partition != requested.partition.as_str()
    {
        return None;
    }

    let access = parse_access(result.values.get("access")?.as_str())?;
    let mode = result.values.get("mode")?.as_str();

    let target = match mode {
        "preset" => {
            let collection = if requested.is_default_collection {
                "default".to_owned()
            } else {
                requested.collection.clone()
            };

            match requested.partition {
                SecretPartition::OwnPackage => SecretTarget {
                    partition: SecretPartition::OwnPackage,
                    collection,
                    attributes: BTreeMap::new(),
                    label: None,
                    access,
                },
                SecretPartition::Host => SecretTarget {
                    partition: SecretPartition::Host,
                    collection,
                    attributes: requested.attributes.clone(),
                    label: requested
                        .attributes
                        .is_empty()
                        .then(|| requested.label.clone()),
                    access,
                },
            }
        }

        "custom" => {
            let collection = result.values.get("collection")?.trim().to_owned();
            let attributes = parse_attributes(result.values.get("attributes")?)?;
            let raw_label = result.values.get("label")?.trim();
            let label =
                (!raw_label.is_empty() && raw_label != "<any>").then(|| raw_label.to_owned());

            SecretTarget {
                partition: requested.partition,
                collection,
                attributes,
                label,
                access,
            }
        }

        _ => return None,
    };

    let valid = if result.action == Some(PromptAction::Deny) {
        target.validate().is_ok()
    } else {
        target.validate_for_allow().is_ok()
    };

    if !valid || !target.matches(requested, attributed_package) {
        return None;
    }

    Some(ApprovalTarget::Secret { target })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use agent_sandbox_core::{
        ApprovalScope, ApprovalTarget, SecretAccess, SecretBatchInfo, SecretOperation,
        SecretPartition, SecretRequest, SecretTarget,
    };

    use super::{parse_secret_target, prompt, secret_presentation};
    use crate::ui::{
        kinds::test_support::origin,
        options::{ApprovalFormContext, ApprovalFormControl, ApprovalFormResult, PromptAction},
        prompt::FallbackTarget,
    };

    fn own_create_request() -> SecretRequest {
        SecretRequest {
            partition: SecretPartition::OwnPackage,
            collection: "kdewallet".into(),
            is_default_collection: true,
            attributes: BTreeMap::from([
                ("service".into(), "openai-codex".into()),
                ("username".into(), "tim@example.com".into()),
            ]),
            label: "Codex OAuth Token".into(),
            access: SecretAccess::Write,
            operation: SecretOperation::CreateItem,
            replace: true,
            batch: None,
        }
    }

    fn host_read_request() -> SecretRequest {
        SecretRequest {
            partition: SecretPartition::Host,
            collection: "kdewallet".into(),
            is_default_collection: true,
            attributes: BTreeMap::from([
                ("service".into(), "gh:github.com".into()),
                ("username".into(), "tim".into()),
            ]),
            label: "GitHub token".into(),
            access: SecretAccess::Read,
            operation: SecretOperation::GetSecret,
            replace: false,
            batch: None,
        }
    }

    fn submitted(action: PromptAction, values: &[[&str; 2]]) -> ApprovalFormResult {
        ApprovalFormResult {
            action: Some(action),
            scope: ApprovalScope::ProjectPackage,
            values: values
                .iter()
                .map(|[key, value]| ((*key).to_owned(), (*value).to_owned()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn own_package_prompt_preselects_preset_and_all_access_with_warnings() {
        let request = own_create_request();
        let prompt = prompt(Some("ui-1"), origin(Some("codex")), request);

        let presentation = prompt.review.presentation.as_ref().expect("presentation");
        assert_eq!(
            presentation.heading,
            "Allow codex to store or replace a secret in codex's own partition?"
        );
        assert_eq!(
            presentation.subject,
            "Codex OAuth Token\nservice=openai-codex, username=tim@example.com"
        );
        assert_eq!(presentation.details, vec![ApprovalFormContext {
            label: "Keyring".into(),
            value: "kdewallet (default) \u{00b7} codex partition".into(),
        }]);
        assert!(
            presentation
                .warning
                .as_deref()
                .is_some_and(|w| w.contains("replace=true"))
        );

        let mode = prompt
            .review
            .fields
            .iter()
            .find(|field| field.id == "mode")
            .expect("mode field");
        let ApprovalFormControl::Choice { value, options } = &mode.control else {
            panic!("mode must be a choice field");
        };
        assert_eq!(value, "preset");
        assert_eq!(options[0].label, "Entire codex partition (recommended)");

        let access = prompt
            .review
            .fields
            .iter()
            .find(|field| field.id == "access")
            .expect("access field");
        let ApprovalFormControl::Choice { value, options } = &access.control else {
            panic!("access must be a choice field");
        };
        assert_eq!(value, "all");
        let option_values: Vec<&str> = options.iter().map(|opt| opt.value.as_str()).collect();
        assert_eq!(option_values, vec!["write", "read_write", "all"]);

        let collection = prompt
            .review
            .fields
            .iter()
            .find(|field| field.id == "collection")
            .expect("collection field");
        let ApprovalFormControl::Text { value } = &collection.control else {
            panic!("collection must be a text field");
        };
        assert_eq!(value, "default");

        let label = prompt
            .review
            .fields
            .iter()
            .find(|field| field.id == "label")
            .expect("label field");
        let ApprovalFormControl::Text { value } = &label.control else {
            panic!("label must be a text field");
        };
        assert_eq!(value, "<any>");
    }

    #[test]
    fn host_prompt_preselects_requested_access_and_renders_batch_and_delete_warnings() {
        let mut batch_req = host_read_request();
        batch_req.operation = SecretOperation::GetSecrets;
        batch_req.batch = Some(SecretBatchInfo { index: 2, total: 3 });

        let prompt = prompt(Some("ui-1"), origin(Some("codex")), batch_req);
        let presentation = prompt.review.presentation.as_ref().expect("presentation");
        assert_eq!(presentation.heading, "Allow codex to read a host secret?");
        assert_eq!(
            presentation.subject,
            "GitHub token\nservice=gh:github.com, username=tim"
        );
        assert_eq!(presentation.details, vec![
            ApprovalFormContext {
                label: "Keyring".into(),
                value: "kdewallet (default) \u{00b7} host keyring".into(),
            },
            ApprovalFormContext {
                label: "Batch".into(),
                value: "item 2 of 3 (all items must be allowed)".into(),
            },
        ]);
        assert_eq!(presentation.warning, None);

        let access = prompt
            .review
            .fields
            .iter()
            .find(|field| field.id == "access")
            .expect("access field");
        let ApprovalFormControl::Choice { value, options } = &access.control else {
            panic!("access must be a choice field");
        };
        assert_eq!(value, "read");
        let option_values: Vec<&str> = options.iter().map(|opt| opt.value.as_str()).collect();
        assert_eq!(option_values, vec!["read", "read_write", "all"]);

        let mut delete_req = host_read_request();
        delete_req.operation = SecretOperation::Delete;
        delete_req.access = SecretAccess::Delete;
        let delete_pres = secret_presentation(&delete_req, Some("omp"));
        assert!(
            delete_pres
                .warning
                .as_deref()
                .is_some_and(|w| w.contains("Permanently deletes a host secret"))
        );

        let mut overwrite_req = host_read_request();
        overwrite_req.operation = SecretOperation::SetSecret;
        overwrite_req.access = SecretAccess::Write;
        let overwrite_pres = secret_presentation(&overwrite_req, Some("omp"));
        assert!(
            overwrite_pres
                .warning
                .as_deref()
                .is_some_and(|w| w.contains("Overwrites an existing host secret"))
        );

        let mut set_attr_req = host_read_request();
        set_attr_req.operation = SecretOperation::SetAttributes;
        set_attr_req.access = SecretAccess::Write;
        let set_attr_pres = secret_presentation(&set_attr_req, Some("codex"));
        assert!(
            set_attr_pres
                .warning
                .as_deref()
                .is_some_and(|w| w.contains("current and new secret identities"))
        );
    }

    #[test]
    fn label_only_host_request_prefills_exact_label_and_preset_keeps_label() {
        let request = SecretRequest {
            partition: SecretPartition::Host,
            collection: "login".into(),
            is_default_collection: false,
            attributes: BTreeMap::new(),
            label: "API Key".into(),
            access: SecretAccess::Write,
            operation: SecretOperation::CreateItem,
            replace: false,
            batch: None,
        };

        let prompt = prompt(Some("ui-1"), origin(None), request.clone());
        let label = prompt
            .review
            .fields
            .iter()
            .find(|field| field.id == "label")
            .expect("label field");
        let ApprovalFormControl::Text { value } = &label.control else {
            panic!("label must be a text field");
        };
        assert_eq!(value, "API Key");

        let parsed = parse_secret_target(
            &submitted(PromptAction::Allow, &[
                ["mode", "preset"],
                ["access", "write"],
                ["collection", "login"],
                ["attributes", "<any>"],
                ["label", "API Key"],
            ]),
            &request,
            false,
        );

        assert_eq!(
            parsed,
            Some(ApprovalTarget::Secret {
                target: SecretTarget {
                    partition: SecretPartition::Host,
                    collection: "login".into(),
                    attributes: BTreeMap::new(),
                    label: Some("API Key".into()),
                    access: SecretAccess::Write,
                },
            })
        );
    }

    #[test]
    fn parse_secret_target_validates_presets_custom_edits_and_guardrails() {
        let own_req = own_create_request();
        let own_preset = parse_secret_target(
            &submitted(PromptAction::Allow, &[
                ["mode", "preset"],
                ["access", "all"],
                ["collection", "default"],
                [
                    "attributes",
                    "service=openai-codex, username=tim@example.com",
                ],
                ["label", "<any>"],
            ]),
            &own_req,
            true,
        );
        assert_eq!(
            own_preset,
            Some(ApprovalTarget::Secret {
                target: SecretTarget {
                    partition: SecretPartition::OwnPackage,
                    collection: "default".into(),
                    attributes: BTreeMap::new(),
                    label: None,
                    access: SecretAccess::All,
                },
            })
        );

        let host_req = host_read_request();
        let host_custom = parse_secret_target(
            &submitted(PromptAction::Allow, &[
                ["mode", "custom"],
                ["access", "read_write"],
                ["collection", "*"],
                ["attributes", "service=gh:*\nusername=tim"],
                ["label", "<any>"],
            ]),
            &host_req,
            true,
        );
        assert_eq!(
            host_custom,
            Some(ApprovalTarget::Secret {
                target: SecretTarget {
                    partition: SecretPartition::Host,
                    collection: "*".into(),
                    attributes: BTreeMap::from([
                        ("service".into(), "gh:*".into()),
                        ("username".into(), "tim".into()),
                    ]),
                    label: None,
                    access: SecretAccess::ReadWrite,
                },
            })
        );

        // Reject reserved agent-sandbox:* attribute.
        assert!(
            parse_secret_target(
                &submitted(PromptAction::Allow, &[
                    ["mode", "custom"],
                    ["access", "read"],
                    ["collection", "default"],
                    [
                        "attributes",
                        "agent-sandbox:package=codex, service=gh:github.com"
                    ],
                    ["label", "<any>"],
                ]),
                &host_req,
                true,
            )
            .is_none()
        );

        // Reject malformed attribute entry (no `=`).
        assert!(
            parse_secret_target(
                &submitted(PromptAction::Allow, &[
                    ["mode", "custom"],
                    ["access", "read"],
                    ["collection", "default"],
                    ["attributes", "not-a-pair"],
                    ["label", "<any>"],
                ]),
                &host_req,
                true,
            )
            .is_none()
        );

        // Reject empty collection.
        assert!(
            parse_secret_target(
                &submitted(PromptAction::Allow, &[
                    ["mode", "custom"],
                    ["access", "read"],
                    ["collection", "   "],
                    ["attributes", "service=gh:github.com"],
                    ["label", "<any>"],
                ]),
                &host_req,
                true,
            )
            .is_none()
        );

        // Reject empty-selector host ALLOW rule.
        assert!(
            parse_secret_target(
                &submitted(PromptAction::Allow, &[
                    ["mode", "custom"],
                    ["access", "read"],
                    ["collection", "default"],
                    ["attributes", "<any>"],
                    ["label", "<any>"],
                ]),
                &host_req,
                true,
            )
            .is_none()
        );

        // Allow empty-selector host DENY rule.
        assert!(
            parse_secret_target(
                &submitted(PromptAction::Deny, &[
                    ["mode", "custom"],
                    ["access", "read"],
                    ["collection", "default"],
                    ["attributes", "<any>"],
                    ["label", "<any>"],
                ]),
                &host_req,
                true,
            )
            .is_some()
        );

        // Reject partition tampering.
        assert!(
            parse_secret_target(
                &submitted(PromptAction::Allow, &[
                    ["partition", "own_package"],
                    ["mode", "preset"],
                    ["access", "read"],
                    ["collection", "default"],
                    ["attributes", "service=gh:github.com"],
                    ["label", "<any>"],
                ]),
                &host_req,
                true,
            )
            .is_none()
        );

        // Reject non-covering selector.
        assert!(
            parse_secret_target(
                &submitted(PromptAction::Allow, &[
                    ["mode", "custom"],
                    ["access", "read"],
                    ["collection", "other-collection"],
                    ["attributes", "service=gh:github.com"],
                    ["label", "<any>"],
                ]),
                &host_req,
                true,
            )
            .is_none()
        );

        // Reject non-covering access level.
        assert!(
            parse_secret_target(
                &submitted(PromptAction::Allow, &[
                    ["mode", "preset"],
                    ["access", "delete"],
                    ["collection", "default"],
                    ["attributes", "service=gh:github.com"],
                    ["label", "<any>"],
                ]),
                &host_req,
                true,
            )
            .is_none()
        );
    }

    #[test]
    fn fallback_targets_exact_requested_secret_identity() {
        let request = host_read_request();
        let prompt = prompt(Some("ui-1"), origin(Some("codex")), request.clone());

        assert_eq!(prompt.fallback.scope_phrase, "secret");
        assert_eq!(
            prompt.fallback.action_title,
            "agent-sandbox (codex): secret get_secret (host)"
        );

        let FallbackTarget::Fixed(target) = &prompt.fallback.target else {
            panic!("secret fallback must be fixed");
        };
        assert_eq!(target, &ApprovalTarget::Secret {
            target: SecretTarget::exact_for_request(&request),
        });
    }
}

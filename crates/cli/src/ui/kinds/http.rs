use std::sync::Arc;

use agent_sandbox_core::{ApprovalTarget, HttpMethodMatcher, HttpRequest, HttpRuleTarget, HttpUrl};

use crate::ui::{
    options::{ApprovalFormOption, ApprovalFormPresentation, ApprovalFormResult},
    prompt::{
        Fallback, FallbackTarget, Origin, Prompt, choice_field, comment_field, prompt_tag,
        review_form, text_field,
    },
};

pub fn prompt(session_id: Option<&str>, origin: Origin, request: HttpRequest) -> Prompt {
    let tag = prompt_tag(origin.package.as_deref());

    let method_options = vec![
        ApprovalFormOption {
            value: "exact".into(),
            label: format!("{} only", request.method.as_str()),
        },
        ApprovalFormOption {
            value: "all".into(),
            label: "All methods".into(),
        },
    ];

    let review = review_form(&origin, session_id, http_presentation(&request), vec![
        choice_field("method", "Methods", "exact", method_options),
        text_field("url", "URL", request.url.to_string()),
        comment_field(),
    ]);

    let fallback = Fallback {
        action_title: format!("{tag}: {} {}", request.method.as_str(), request.url),
        scope_phrase: "HTTP".into(),
        target: FallbackTarget::Http(request.clone()),
    };

    Prompt {
        origin,
        review,
        parse_target: Arc::new(move |result| parse_http_target(result, &request)),
        fallback,
    }
}

fn http_presentation(request: &HttpRequest) -> ApprovalFormPresentation {
    ApprovalFormPresentation {
        heading: format!("Allow this {} request?", request.method.as_str()),
        subject: request.url.to_string(),
    }
}

/// Parse and validate an editable HTTP method matcher and URL pattern against
/// the request.
fn parse_http_target(result: &ApprovalFormResult, request: &HttpRequest) -> Option<ApprovalTarget> {
    let matcher = match result.values.get("method")?.as_str() {
        "exact" => HttpMethodMatcher::Exact(request.method.clone()),
        "all" => HttpMethodMatcher::All,
        _ => return None,
    };

    let url = HttpUrl::parse_pattern(result.values.get("url")?).ok()?;
    let target = HttpRuleTarget::new(matcher, url).ok()?;

    target
        .url
        .covers(&request.url)
        .then_some(ApprovalTarget::Http { target })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use agent_sandbox_core::{ApprovalScope, ApprovalTarget, HttpMethodMatcher, HttpRequest};

    use super::{http_presentation, parse_http_target, prompt};
    use crate::ui::{
        kinds::test_support::origin,
        options::{ApprovalFormResult, PromptAction},
        prompt::FallbackTarget,
    };

    fn get_request() -> HttpRequest {
        HttpRequest::from_parts("GET", "https", "example.com", "/path").expect("valid HTTP request")
    }

    fn submitted(method: &str, url: &str) -> ApprovalFormResult {
        ApprovalFormResult {
            action: Some(PromptAction::Allow),
            scope: ApprovalScope::Project,
            values: HashMap::from([("method".into(), method.into()), ("url".into(), url.into())]),
        }
    }

    #[test]
    fn http_presentation_uses_method_and_destination() {
        let presentation = http_presentation(&get_request());
        assert_eq!(presentation.heading, "Allow this GET request?");
        assert_eq!(presentation.subject, "https://example.com/path");
    }

    #[test]
    fn http_target_accepts_exact_method_and_covering_url() {
        let request = get_request();

        let Some(ApprovalTarget::Http { target }) =
            parse_http_target(&submitted("exact", "https://example.com/path"), &request)
        else {
            panic!("exact target rejected");
        };

        assert_eq!(target.method, HttpMethodMatcher::Exact(request.method));
    }

    #[test]
    fn http_target_accepts_all_methods_with_a_wider_pattern() {
        let target = parse_http_target(&submitted("all", "https://example.com/*"), &get_request());

        let Some(ApprovalTarget::Http { target }) = target else {
            panic!("all-methods target rejected");
        };

        assert_eq!(target.method, HttpMethodMatcher::All);
    }

    #[test]
    fn http_target_rejects_unknown_method_and_non_covering_url() {
        let request = get_request();

        assert!(
            parse_http_target(&submitted("some", "https://example.com/path"), &request).is_none()
        );
        assert!(
            parse_http_target(&submitted("exact", "https://other.example/path"), &request)
                .is_none()
        );
    }

    #[test]
    fn prompt_hands_the_request_to_the_fallback() {
        let prompt = prompt(Some("session"), origin(Some("omp")), get_request());

        assert_eq!(
            prompt.fallback.action_title,
            "agent-sandbox (omp): GET https://example.com/path"
        );

        assert_eq!(prompt.fallback.scope_phrase, "HTTP");
        assert!(matches!(prompt.fallback.target, FallbackTarget::Http(_)));
        assert!((prompt.parse_target)(&submitted("all", "https://example.com/*")).is_some());
    }
}

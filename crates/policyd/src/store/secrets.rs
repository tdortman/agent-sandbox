//! Secret Service (`org.freedesktop.secrets`) policy evaluation and package
//! identity resolution.

use agent_sandbox_core::{
    ResolvedRequestContext, SandboxPackageReply, SecretCheckReply, SecretRequest, Verdict,
    VerdictSource,
};

use super::PolicyStore;

impl PolicyStore {
    /// Return the authoritative package registered for the resolved sandbox
    /// instance context.
    #[must_use]
    pub fn resolve_sandbox_package(&self, ctx: &ResolvedRequestContext) -> SandboxPackageReply {
        SandboxPackageReply::ok(ctx.package.clone())
    }

    /// Evaluate a runtime Secret Service request against merged policy layers.
    ///
    /// Deny rules always take precedence over allow rules. Undecided requests
    /// fail closed until interactive approval is wired in.
    #[must_use]
    pub fn check_secret(
        &self,
        request: SecretRequest,
        ctx: &ResolvedRequestContext,
    ) -> SecretCheckReply {
        let verdict = Self::blocking(|| self.secret_verdict(&request, ctx));

        match verdict {
            Some(verdict) => SecretCheckReply::from_verdict(verdict, request),
            None => SecretCheckReply::blocked(
                "agent-sandbox: secret access not allowed by policy",
                request,
            ),
        }
    }

    /// Verdict the merged file policy layers give a runtime secret request, or
    /// `None` when undecided. Denies win over allows.
    pub(crate) fn secret_verdict(
        &self,
        request: &SecretRequest,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        let merged = self.merged_for(ctx);
        let attributed_package = ctx.package.is_some();

        if merged
            .secrets
            .deny
            .iter()
            .any(|rule| rule.target.validate().is_ok() && rule.matches(request, attributed_package))
        {
            return Some(Verdict::denied(VerdictSource::policy()));
        }

        merged
            .secrets
            .allow
            .iter()
            .find(|rule| {
                rule.target.validate_for_allow().is_ok()
                    && rule.matches(request, attributed_package)
            })
            .map(|rule| match rule.comment.as_deref() {
                Some(comment) if !comment.is_empty() => {
                    Verdict::allowed(VerdictSource::policy_with_comment(comment))
                }
                _ => Verdict::allowed(VerdictSource::policy()),
            })
    }
}

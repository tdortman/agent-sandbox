//! Policy types, access lattice, matching, and validation for the `secrets`
//! capability (`org.freedesktop.secrets`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{hosts::glob_matches, policy::contains_glob_syntax};

/// Reserved attribute prefix owned exclusively by the `dbus-proxy` mediator.
///
/// Sandboxed clients and policy rules may never set or match keys starting with
/// this prefix.
pub const RESERVED_SECRET_ATTRIBUTE_PREFIX: &str = "agent-sandbox:";

/// Ownership boundary inside the host keyring daemon separating package
/// secrets from host secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretPartition {
    /// Secrets owned by the calling declared package's secret partition.
    OwnPackage,

    /// Secrets in the host keyring daemon not owned by any package partition.
    Host,
}

impl SecretPartition {
    /// Return the stable wire / policy-file name of this partition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnPackage => "own_package",
            Self::Host => "host",
        }
    }
}

impl std::fmt::Display for SecretPartition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Access level for a secret capability rule or runtime secret request.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SecretAccess {
    /// Read secret values (`GetSecret`, `GetSecrets`).
    #[default]
    Read,

    /// Create or modify secrets and metadata (`CreateItem`, `SetSecret`,
    /// `SetAttributes`, `SetLabel`).
    Write,

    /// Both read and write secret access.
    ReadWrite,

    /// Delete secret items (`Item.Delete`).
    Delete,

    /// Every secret access level (read, write, and delete).
    All,
}

impl SecretAccess {
    /// Return the stable wire / policy-file name of this access level.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
            Self::Delete => "delete",
            Self::All => "all",
        }
    }

    /// Whether this access level covers `requested`.
    #[must_use]
    pub const fn covers(self, requested: Self) -> bool {
        match self {
            Self::All => true,
            Self::ReadWrite => matches!(requested, Self::Read | Self::Write | Self::ReadWrite),
            Self::Read => matches!(requested, Self::Read),
            Self::Write => matches!(requested, Self::Write),
            Self::Delete => matches!(requested, Self::Delete),
        }
    }

    /// Whether `self` covers every access level that `other` covers.
    #[must_use]
    pub const fn access_superset(self, other: Self) -> bool {
        self.covers(other)
    }

    /// Smallest policy access level that covers both `self` and `other`.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        if self.covers(other) {
            self
        } else if other.covers(self) {
            other
        } else if matches!(
            (self, other),
            (Self::Read, Self::Write) | (Self::Write, Self::Read)
        ) {
            Self::ReadWrite
        } else {
            Self::All
        }
    }
}

impl std::fmt::Display for SecretAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Specific Secret Service operation intercepted by `dbus-proxy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretOperation {
    /// `org.freedesktop.Secret.Item.GetSecret`.
    GetSecret,

    /// `org.freedesktop.Secret.Service.GetSecrets`.
    GetSecrets,

    /// `org.freedesktop.Secret.Collection.CreateItem`.
    CreateItem,

    /// `org.freedesktop.Secret.Item.SetSecret`.
    SetSecret,

    /// `org.freedesktop.DBus.Properties.Set` on `Item.Attributes`.
    SetAttributes,

    /// `org.freedesktop.DBus.Properties.Set` on `Item.Label`.
    SetLabel,

    /// `org.freedesktop.Secret.Item.Delete`.
    Delete,
}

impl SecretOperation {
    /// Return the stable wire name of this operation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetSecret => "get_secret",
            Self::GetSecrets => "get_secrets",
            Self::CreateItem => "create_item",
            Self::SetSecret => "set_secret",
            Self::SetAttributes => "set_attributes",
            Self::SetLabel => "set_label",
            Self::Delete => "delete",
        }
    }
}

impl std::fmt::Display for SecretOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Position of one item within a multi-item `Service.GetSecrets` batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SecretBatchInfo {
    /// 1-based position of this item within a multi-item `Service.GetSecrets`
    /// call.
    pub index: u32,

    /// Total number of items in the batch.
    pub total: u32,
}

/// Runtime secret operation intercepted by `dbus-proxy` and evaluated by
/// `policyd`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SecretRequest {
    /// Partition the target secret belongs to.
    pub partition: SecretPartition,

    /// Resolved concrete collection segment (e.g. `kdewallet`, `login`).
    pub collection: String,

    /// Whether `collection` is currently the target of
    /// `/org/freedesktop/secrets/aliases/default`.
    pub is_default_collection: bool,

    /// Normalized client attributes (daemon-synthesized keys and
    /// `agent-sandbox:*` removed).
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,

    /// Human-readable item label.
    pub label: String,

    /// Required access level (`Read`, `Write`, or `Delete`).
    pub access: SecretAccess,

    /// Intercepted Secret Service operation.
    pub operation: SecretOperation,

    /// Set on `CreateItem` calls to surface replace context in prompts.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replace: bool,

    /// Present only for multi-item `Service.GetSecrets` batches (`total > 1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<SecretBatchInfo>,
}

fn default_secret_collection() -> String {
    "default".to_owned()
}

/// Durable rule pattern stored in policy files and runtime session buckets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SecretTarget {
    /// Secret partition matched by this rule.
    pub partition: SecretPartition,

    /// Collection selector (`default`, a concrete collection name, or a glob
    /// such as `*`).
    #[serde(default = "default_secret_collection")]
    pub collection: String,

    /// Subset client attribute patterns (`key -> literal or glob`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,

    /// Optional item label pattern (`literal or glob`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Secret access level granted or denied by this rule.
    pub access: SecretAccess,
}

impl SecretTarget {
    /// Validate invariants required for every secret rule (allow or deny).
    ///
    /// # Errors
    ///
    /// Returns a static error reason if `collection` is empty or any attribute
    /// key uses the reserved `agent-sandbox:` prefix.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.collection.is_empty() {
            return Err("secret rule collection must not be empty");
        }

        if self
            .attributes
            .keys()
            .any(|key| key.starts_with(RESERVED_SECRET_ATTRIBUTE_PREFIX))
        {
            return Err("secret rule attributes must not use reserved `agent-sandbox:` prefix");
        }

        Ok(())
    }

    /// Validate guardrails required for secret **allow** rules.
    ///
    /// # Errors
    ///
    /// Returns a static error reason if [`Self::validate`] fails or if a `host`
    /// allow rule has neither attributes nor a label.
    pub fn validate_for_allow(&self) -> Result<(), &'static str> {
        self.validate()?;

        if self.partition == SecretPartition::Host
            && self.attributes.is_empty()
            && self.label.is_none()
        {
            return Err("host secret allow rule must specify at least one attribute or a label");
        }

        Ok(())
    }

    /// Whether this durable target matches runtime secret request `req`.
    ///
    /// `attributed_package` indicates whether the caller is attributed to a
    /// declared package; `own_package` rules never match unattributed callers.
    #[must_use]
    pub fn matches(&self, req: &SecretRequest, attributed_package: bool) -> bool {
        if self.validate().is_err() {
            return false;
        }

        if self.partition == SecretPartition::OwnPackage && !attributed_package {
            return false;
        }

        if self.partition != req.partition || !self.access.covers(req.access) {
            return false;
        }

        let collection_matches = self.collection == "*"
            || (self.collection == "default" && req.is_default_collection)
            || self.collection == req.collection
            || glob_matches(&self.collection, &req.collection);
        if !collection_matches {
            return false;
        }

        let attributes_match = self.attributes.iter().all(|(key, pattern)| {
            req.attributes
                .get(key)
                .is_some_and(|value| value == pattern || glob_matches(pattern, value))
        });
        if !attributes_match {
            return false;
        }

        if let Some(pattern) = &self.label
            && req.label != *pattern
            && !glob_matches(pattern, &req.label)
        {
            return false;
        }

        true
    }

    /// Whether `self` provably covers every runtime secret request that `other`
    /// can match.
    ///
    /// Used during deny-wins policy merging: collection matching stays
    /// conservative (`default` vs. concrete collection names return `false` so
    /// both rules stay in the merged policy and `policyd` evaluates deny before
    /// allow).
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        if self.validate().is_err() {
            return false;
        }

        if self.partition != other.partition || !self.access.access_superset(other.access) {
            return false;
        }

        let collection_covered = self.collection == "*" || self.collection == other.collection;
        if !collection_covered {
            return false;
        }

        let attributes_covered = self.attributes.iter().all(|(key, self_pat)| {
            other
                .attributes
                .get(key)
                .is_some_and(|other_pat| pattern_covers(self_pat, other_pat))
        });
        if !attributes_covered {
            return false;
        }

        match (&self.label, &other.label) {
            (None, _) => true,
            (Some(self_label), Some(other_label)) => pattern_covers(self_label, other_label),
            (Some(_), None) => false,
        }
    }
}

fn pattern_covers(broader: &str, narrower: &str) -> bool {
    broader == narrower || (!contains_glob_syntax(narrower) && glob_matches(broader, narrower))
}

/// One allow or deny rule in the `secrets` policy section.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SecretRule {
    /// Durable secret target matched by this rule.
    #[serde(flatten)]
    pub target: SecretTarget,

    /// Optional human-readable annotation attached to the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl SecretRule {
    /// Construct a new rule from a target and comment.
    #[must_use]
    pub fn new(target: SecretTarget, comment: impl Into<String>) -> Self {
        Self {
            target,
            comment: Some(comment.into()),
        }
    }

    /// Return the durable identity key of this rule (without access level).
    #[must_use]
    pub fn key(&self) -> SecretRuleKey {
        SecretRuleKey {
            partition: self.target.partition,
            collection: self.target.collection.clone(),
            attributes: self.target.attributes.clone(),
            label: self.target.label.clone(),
        }
    }

    /// Whether this rule matches runtime secret request `req`.
    #[must_use]
    pub fn matches(&self, req: &SecretRequest, attributed_package: bool) -> bool {
        self.target.matches(req, attributed_package)
    }
}

/// Identity key of a [`SecretRule`] without access level, used for policy-file
/// upserts and rule deduplication.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretRuleKey {
    /// Secret partition matched by the rule.
    pub partition: SecretPartition,

    /// Collection selector matched by the rule.
    pub collection: String,

    /// Subset attribute patterns matched by the rule.
    pub attributes: BTreeMap<String, String>,

    /// Optional item label pattern matched by the rule.
    pub label: Option<String>,
}

/// The `secrets` policy section: ordered lists of allow and deny
/// [`SecretRule`]s governing freedesktop Secret Service access.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSection {
    /// Allow rules.
    #[serde(default)]
    pub allow: Vec<SecretRule>,

    /// Deny rules.
    #[serde(default)]
    pub deny: Vec<SecretRule>,
}

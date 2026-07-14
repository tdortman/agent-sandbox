//! Typed HTTP request and rule normalization shared by policy, RPC, and proxies.

use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;

use globset::GlobBuilder;
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use url::Url;

use crate::hosts::normalize_dns_name;

const MAX_METHOD_BYTES: usize = 64;

/// A validated HTTP method token.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpMethod(Box<str>);

impl HttpMethod {
    /// Parse an HTTP method without trimming or case folding it.
    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError::InvalidMethod`] when `value` is empty, too
    /// long, or contains a byte outside the HTTP method token grammar.
    pub fn parse(value: &str) -> Result<Self, HttpParseError> {
        if value.is_empty() || value.len() > MAX_METHOD_BYTES {
            return Err(HttpParseError::InvalidMethod);
        }
        if !value.bytes().all(is_method_byte) {
            return Err(HttpParseError::InvalidMethod);
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for HttpMethod {
    type Error = HttpParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl Serialize for HttpMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HttpMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

/// Exact, any-of, or all-method matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpMethodMatcher {
    Exact(HttpMethod),
    AnyOf(Vec<HttpMethod>),
    All,
}

impl HttpMethodMatcher {
    #[must_use]
    pub const fn all() -> Self {
        Self::All
    }

    /// Construct the matcher represented by a canonical `methods` array.
    ///
    /// An empty array means all methods. One method is represented as
    /// [`Self::Exact`]; multiple methods are represented as [`Self::AnyOf`].
    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError::InvalidMethod`] when any element is invalid.
    pub fn from_methods(methods: &[String]) -> Result<Self, HttpParseError> {
        let methods = methods
            .iter()
            .map(|method| HttpMethod::parse(method))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::from_http_methods(methods))
    }

    fn from_http_methods(mut methods: Vec<HttpMethod>) -> Self {
        methods.sort();
        methods.dedup();
        match methods.as_slice() {
            [] => Self::All,
            [method] => Self::Exact(method.clone()),
            _ => Self::AnyOf(methods),
        }
    }

    #[must_use]
    pub fn matches(&self, request: &HttpMethod) -> bool {
        match self {
            Self::Exact(method) => method == request,
            Self::AnyOf(methods) => methods.iter().any(|method| method == request),
            Self::All => true,
        }
    }

    /// Return whether this matcher covers every method covered by `other`.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::All, _) => true,
            (_, Self::All) => false,
            (Self::Exact(left), Self::Exact(right)) => left == right,
            (Self::Exact(left), Self::AnyOf(right)) => {
                !right.is_empty() && right.iter().all(|method| method == left)
            }
            (Self::AnyOf(left), Self::Exact(right)) => left.iter().any(|method| method == right),
            (Self::AnyOf(left), Self::AnyOf(right)) => {
                !right.is_empty() && right.iter().all(|method| left.contains(method))
            }
        }
    }

    /// Return the union of the methods covered by two matchers.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        if matches!(self, Self::All) || matches!(other, Self::All) {
            return Self::All;
        }
        let mut methods = self.to_methods();
        methods.extend(other.to_methods());
        Self::from_http_methods(methods)
    }

    /// Return the canonical method list. An empty list represents all methods.
    #[must_use]
    pub fn to_methods(&self) -> Vec<HttpMethod> {
        match self {
            Self::Exact(method) => vec![method.clone()],
            Self::AnyOf(methods) => methods.clone(),
            Self::All => Vec::new(),
        }
    }

    /// Return the legacy singular method when this is an exact matcher.
    #[must_use]
    pub const fn as_option(&self) -> Option<&HttpMethod> {
        match self {
            Self::Exact(method) => Some(method),
            Self::AnyOf(_) | Self::All => None,
        }
    }
}

impl Serialize for HttpMethodMatcher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Exact(method) => serializer.serialize_str(method.as_str()),
            Self::AnyOf(methods) => methods.serialize(serializer),
            Self::All => serializer.serialize_none(),
        }
    }
}

struct HttpMethodMatcherVisitor;

impl<'de> Visitor<'de> for HttpMethodMatcherVisitor {
    type Value = HttpMethodMatcher;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("null, an HTTP method string, or an array of HTTP methods")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(HttpMethodMatcher::All)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(HttpMethodMatcher::All)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        HttpMethod::parse(value)
            .map(HttpMethodMatcher::Exact)
            .map_err(E::custom)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_str(&value)
    }

    fn visit_seq<A>(self, sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let methods =
            Vec::<String>::deserialize(serde::de::value::SeqAccessDeserializer::new(sequence))?;
        HttpMethodMatcher::from_methods(&methods).map_err(A::Error::custom)
    }
}

impl<'de> Deserialize<'de> for HttpMethodMatcher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(HttpMethodMatcherVisitor)
    }
}

/// HTTP scheme accepted by the transparent proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpScheme {
    Http,
    Https,
}

impl HttpScheme {
    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError::UnsupportedScheme`] when `value` is not
    /// `http` or `https`, ignoring ASCII case.
    pub fn parse(value: &str) -> Result<Self, HttpParseError> {
        match value.to_ascii_lowercase().as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            _ => Err(HttpParseError::UnsupportedScheme),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

impl Serialize for HttpScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HttpScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

/// Canonical HTTP host, preserving whether the authority is an IP literal or DNS name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpHost {
    Ip(IpAddr),
    Dns(Box<str>),
}

impl HttpHost {
    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError::InvalidAuthority`] when `host` is empty or
    /// cannot be normalized as an IP address or DNS name.
    pub fn parse(host: &str) -> Result<Self, HttpParseError> {
        let host = host.trim();
        if host.is_empty() {
            return Err(HttpParseError::InvalidAuthority);
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        let normalized = normalize_dns_name(host).map_err(|_| HttpParseError::InvalidAuthority)?;
        Ok(Self::Dns(normalized.into_boxed_str()))
    }

    #[must_use]
    pub const fn is_ipv6(&self) -> bool {
        matches!(self, Self::Ip(IpAddr::V6(_)))
    }
}

impl fmt::Display for HttpHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Dns(name) => f.write_str(name),
        }
    }
}

/// Canonical authority host and nonzero effective port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpAuthority {
    host: HttpHost,
    port: NonZeroU16,
}

impl HttpAuthority {
    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError::InvalidAuthority`] for malformed authorities,
    /// [`HttpParseError::CredentialsNotAllowed`] for embedded credentials, or
    /// [`HttpParseError::InvalidPort`] for a zero or unavailable port.
    pub fn parse(scheme: HttpScheme, authority: &str) -> Result<Self, HttpParseError> {
        if authority.is_empty()
            || authority.contains(['/', '?', '#', '@'])
            || authority.chars().any(char::is_whitespace)
        {
            return Err(HttpParseError::InvalidAuthority);
        }
        let candidate = format!("{}://{authority}/", scheme.as_str());
        let parsed = Url::parse(&candidate).map_err(|_| HttpParseError::InvalidAuthority)?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(HttpParseError::CredentialsNotAllowed);
        }
        let host = parsed.host_str().ok_or(HttpParseError::InvalidAuthority)?;
        let host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        let port = parsed
            .port_or_known_default()
            .ok_or(HttpParseError::InvalidAuthority)?;
        if port == 0 || parsed.port() == Some(0) {
            return Err(HttpParseError::InvalidPort);
        }
        Ok(Self {
            host: HttpHost::parse(host)?,
            port: NonZeroU16::new(port).ok_or(HttpParseError::InvalidPort)?,
        })
    }

    #[must_use]
    pub const fn host(&self) -> &HttpHost {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> NonZeroU16 {
        self.port
    }

    #[must_use]
    pub const fn port_number(&self) -> u16 {
        self.port.get()
    }

    #[must_use]
    pub const fn is_default_port(&self, scheme: HttpScheme) -> bool {
        self.port.get() == scheme.default_port()
    }

    fn display(&self, scheme: HttpScheme) -> String {
        let host = if self.host.is_ipv6() {
            format!("[{}]", self.host)
        } else {
            self.host.to_string()
        };
        if self.is_default_port(scheme) {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Canonical HTTP path used for policy matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalizedHttpPath(Box<str>);

impl NormalizedHttpPath {
    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError::InvalidPath`] when `raw` is not an absolute
    /// path, or [`HttpParseError::QueryOrFragmentNotAllowed`] when it contains
    /// a query or fragment.
    pub fn parse(raw: &str) -> Result<Self, HttpParseError> {
        if raw.is_empty() {
            return Ok(Self("/".into()));
        }
        if !raw.starts_with('/') {
            return Err(HttpParseError::InvalidPath);
        }
        if raw.contains(['?', '#']) {
            return Err(HttpParseError::QueryOrFragmentNotAllowed);
        }
        let decoded = decode_path(raw)?;
        let mut segments = Vec::new();
        for (index, segment) in decoded.split('/').enumerate() {
            if index == 0 {
                continue;
            }
            match segment {
                "" => segments.push(String::new()),
                "." => {}
                ".." => {
                    let _ = segments.pop();
                }
                value => segments.push(value.to_string()),
            }
        }
        let mut normalized = String::from('/');
        normalized.push_str(&segments.join("/"));
        if normalized.is_empty() {
            normalized.push('/');
        }
        while normalized.len() > 1 && normalized.ends_with('/') {
            normalized.pop();
        }
        Ok(Self(normalized.into_boxed_str()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn matches_prefix(&self, request: &Self) -> bool {
        if self.as_str() == "/" || self == request {
            return true;
        }
        request
            .as_str()
            .strip_prefix(self.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    }
    /// Return whether this path is a prefix that covers `request`.
    #[must_use]
    pub fn covers(&self, request: &Self) -> bool {
        self.matches_prefix(request)
    }
}

impl fmt::Display for NormalizedHttpPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// URL target, including the reserved `OPTIONS *` form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpTarget {
    Path(NormalizedHttpPath),
    Asterisk,
}
/// Canonical scheme, authority, and path used by HTTP policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpUrl {
    pub scheme: HttpScheme,
    pub authority: HttpAuthority,
    pub target: HttpTarget,
    pattern: Option<Box<str>>,
}
impl HttpUrl {
    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError::InvalidUrl`] when `raw` is malformed, or
    /// [`HttpParseError::QueryOrFragmentNotAllowed`] when it has a query or
    /// fragment.
    pub fn parse(raw: &str) -> Result<Self, HttpParseError> {
        if raw.contains(['?', '#']) {
            return Err(HttpParseError::QueryOrFragmentNotAllowed);
        }
        Self::parse_absolute_parts(raw, false)
    }

    /// Parse a persisted HTTP rule URL, allowing glob metacharacters.
    ///
    /// Glob characters are replaced by valid literal characters while the
    /// strict URL parser validates the scheme, authority, and path. The
    /// resulting URL retains its canonical glob pattern for display and
    /// matching.
    ///
    /// # Errors
    ///
    /// Returns an [`HttpParseError`] when the URL or glob pattern is invalid.
    pub fn parse_pattern(raw: &str) -> Result<Self, HttpParseError> {
        if raw.ends_with(" *") {
            return Self::parse(raw);
        }
        let (sanitized, tokens) = replace_pattern_metacharacters(raw);
        let mut url = Self::parse(&sanitized)?;
        if tokens.is_empty() {
            return Ok(url);
        }
        let mut pattern = url.to_string();
        for (token, metacharacter) in tokens {
            if pattern.matches(&token).count() != 1 {
                return Err(HttpParseError::InvalidUrl);
            }
            pattern = pattern.replacen(&token, &metacharacter.to_string(), 1);
        }
        GlobBuilder::new(&pattern)
            .literal_separator(true)
            .build()
            .map_err(|_| HttpParseError::InvalidUrl)?;
        url.pattern = Some(pattern.into_boxed_str());
        Ok(url)
    }

    fn parse_request_absolute(raw: &str) -> Result<Self, HttpParseError> {
        Self::parse_absolute_parts(raw, true)
    }

    ///
    /// # Errors
    ///
    /// Returns an [`HttpParseError`] when the scheme, authority, or path target
    /// is malformed.
    pub fn from_parts(
        scheme: &str,
        authority: &str,
        path_or_target: &str,
    ) -> Result<Self, HttpParseError> {
        let scheme = HttpScheme::parse(scheme)?;
        let authority = HttpAuthority::parse(scheme, authority)?;
        let target = if path_or_target == "*" {
            HttpTarget::Asterisk
        } else {
            HttpTarget::Path(NormalizedHttpPath::parse(path_or_target)?)
        };
        Ok(Self {
            scheme,
            authority,
            target,
            pattern: None,
        })
    }

    fn parse_absolute_parts(raw: &str, allow_query: bool) -> Result<Self, HttpParseError> {
        let (scheme_raw, rest) = raw.split_once("://").ok_or(HttpParseError::InvalidUrl)?;
        let scheme = HttpScheme::parse(scheme_raw)?;
        if let Some(scheme_authority) = rest.strip_suffix(" *") {
            return Self::from_parts(scheme.as_str(), scheme_authority, "*");
        }
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority_raw = &rest[..authority_end];
        let suffix = &rest[authority_end..];
        if suffix.contains('#') {
            return Err(HttpParseError::QueryOrFragmentNotAllowed);
        }
        let path_raw = if let Some((path, _query)) = suffix.split_once('?') {
            if !allow_query {
                return Err(HttpParseError::QueryOrFragmentNotAllowed);
            }
            path
        } else {
            suffix
        };
        let authority = HttpAuthority::parse(scheme, authority_raw)?;
        Ok(Self {
            scheme,
            authority,
            target: HttpTarget::Path(NormalizedHttpPath::parse(path_raw)?),
            pattern: None,
        })
    }

    #[must_use]
    pub const fn path(&self) -> Option<&NormalizedHttpPath> {
        match &self.target {
            HttpTarget::Path(path) => Some(path),
            HttpTarget::Asterisk => None,
        }
    }
    #[must_use]
    pub fn covers(&self, request: &Self) -> bool {
        match (&self.pattern, &request.pattern) {
            (Some(rule), Some(other)) => rule == other,
            (Some(_), None) => self.matches(request),
            (None, Some(_)) => false,
            (None, None) => {
                self.scheme == request.scheme
                    && self.authority == request.authority
                    && match (&self.target, &request.target) {
                        (HttpTarget::Asterisk, HttpTarget::Asterisk) => true,
                        (HttpTarget::Path(rule), HttpTarget::Path(request)) => rule.covers(request),
                        _ => false,
                    }
            }
        }
    }

    #[must_use]
    pub fn matches(&self, request: &Self) -> bool {
        if let Some(pattern) = &self.pattern {
            return GlobBuilder::new(pattern)
                .literal_separator(true)
                .build()
                .is_ok_and(|glob| glob.compile_matcher().is_match(request.to_string()));
        }
        self.covers(request)
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(pattern) = &self.pattern {
            return f.write_str(pattern);
        }
        write!(
            f,
            "{}://{}",
            self.scheme.as_str(),
            self.authority.display(self.scheme)
        )?;
        match &self.target {
            HttpTarget::Path(path) => f.write_str(path.as_str()),
            HttpTarget::Asterisk => f.write_str(" *"),
        }
    }
}

impl Serialize for HttpUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HttpUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

/// One observed HTTP request. Query strings are intentionally outside policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: HttpUrl,
}

impl Serialize for HttpRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            method: &'a HttpMethod,
            url: &'a HttpUrl,
        }
        Wire {
            method: &self.method,
            url: &self.url,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HttpRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            method: HttpMethod,
            url: HttpUrl,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::validate(wire.method, wire.url).map_err(D::Error::custom)
    }
}

impl HttpRequest {
    ///
    /// # Errors
    ///
    /// Returns an [`HttpParseError`] when `method` or any URL component is
    /// malformed.
    pub fn from_parts(
        method: &str,
        scheme: &str,
        authority: &str,
        path_or_target: &str,
    ) -> Result<Self, HttpParseError> {
        let method = HttpMethod::parse(method)?;
        let url = HttpUrl::from_parts(scheme, authority, path_or_target)?;
        Self::validate(method, url)
    }

    ///
    /// # Errors
    ///
    /// Returns an [`HttpParseError`] when `method` or `raw_url` is malformed,
    /// or when the URL uses `*` with a method other than `OPTIONS`.
    pub fn parse_absolute(method: &str, raw_url: &str) -> Result<Self, HttpParseError> {
        let method = HttpMethod::parse(method)?;
        let url = HttpUrl::parse_request_absolute(raw_url)?;
        Self::validate(method, url)
    }

    fn validate(method: HttpMethod, url: HttpUrl) -> Result<Self, HttpParseError> {
        if matches!(url.target, HttpTarget::Asterisk) && method.as_str() != "OPTIONS" {
            return Err(HttpParseError::AsteriskRequiresOptions);
        }
        Ok(Self { method, url })
    }
}
/// Typed policy target used by approvals and persisted HTTP rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpRuleTarget {
    pub method: HttpMethodMatcher,
    pub url: HttpUrl,
}

impl HttpRuleTarget {
    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError::AsteriskRequiresOptions`] when `url` is an
    /// asterisk target and `method` is not the exact `OPTIONS` method.
    pub fn new(method: HttpMethodMatcher, url: HttpUrl) -> Result<Self, HttpParseError> {
        if matches!(url.target, HttpTarget::Asterisk)
            && !matches!(&method, HttpMethodMatcher::Exact(value) if value.as_str() == "OPTIONS")
        {
            return Err(HttpParseError::AsteriskRequiresOptions);
        }
        Ok(Self { method, url })
    }

    ///
    /// # Errors
    ///
    /// Returns an [`HttpParseError`] when the raw rule target is malformed or
    /// violates the `OPTIONS *` restriction.
    pub fn from_rule(rule: &HttpRule) -> Result<Self, HttpParseError> {
        let method = HttpMethodMatcher::from_methods(&rule.methods)?;
        let url = HttpUrl::parse_pattern(&rule.url)?;
        Self::new(method, url)
    }

    #[must_use]
    pub fn matches(&self, request: &HttpRequest) -> bool {
        self.method.matches(&request.method) && self.url.matches(&request.url)
    }

    /// Return whether this target covers every request covered by `other`.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        self.method.covers(&other.method) && self.url.covers(&other.url)
    }
}

impl Serialize for HttpRuleTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            method: &'a HttpMethodMatcher,
            url: &'a HttpUrl,
        }
        Wire {
            method: &self.method,
            url: &self.url,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HttpRuleTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            method: HttpMethodMatcher,
            url: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let url = HttpUrl::parse_pattern(&wire.url).map_err(D::Error::custom)?;
        Self::new(wire.method, url).map_err(D::Error::custom)
    }
}

/// Raw JSON/Nix policy rule. Validate before matching or persistence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpRule {
    pub methods: Vec<String>,
    pub url: String,
    pub comment: Option<String>,
}

impl Serialize for HttpRule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            methods: &'a [String],
            url: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            comment: &'a Option<String>,
        }
        Wire {
            methods: &self.methods,
            url: &self.url,
            comment: &self.comment,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HttpRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            methods: Option<Vec<String>>,
            #[serde(default)]
            method: Option<String>,
            url: String,
            #[serde(default)]
            comment: Option<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            methods: wire
                .methods
                .unwrap_or_else(|| wire.method.into_iter().collect()),
            url: wire.url,
            comment: wire.comment,
        })
    }
}

impl HttpRule {
    pub fn new(methods: Vec<String>, url: impl Into<String>, comment: impl Into<String>) -> Self {
        Self {
            methods,
            url: url.into(),
            comment: Some(comment.into()),
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an [`HttpParseError`] when this rule's method or URL is invalid.
    pub fn target(&self) -> Result<HttpRuleTarget, HttpParseError> {
        HttpRuleTarget::from_rule(self)
    }
}

/// Context dimensions that HTTP verdicts must never cross.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HttpContextKey {
    pub cwd: Option<std::path::PathBuf>,

    pub home: Option<std::path::PathBuf>,
    pub project_root: Option<std::path::PathBuf>,
    pub sandbox_session_id: Option<String>,
}

/// Opaque pending HTTP request identifier encoded as `http:<simple-v7>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingHttpId(uuid::Uuid);

impl PendingHttpId {
    #[must_use]
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7())
    }

    ///
    /// # Errors
    ///
    /// Returns [`HttpParseError::InvalidPendingId`] when `value` does not use
    /// the canonical `http:` `UUIDv7` representation.
    pub fn parse(value: &str) -> Result<Self, HttpParseError> {
        let raw = value
            .strip_prefix("http:")
            .ok_or(HttpParseError::InvalidPendingId)?;
        if raw.len() != 32 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HttpParseError::InvalidPendingId);
        }
        let uuid = uuid::Uuid::parse_str(raw).map_err(|_| HttpParseError::InvalidPendingId)?;
        if uuid.get_version() != Some(uuid::Version::SortRand) {
            return Err(HttpParseError::InvalidPendingId);
        }
        Ok(Self(uuid))
    }

    #[must_use]
    pub const fn uuid(self) -> uuid::Uuid {
        self.0
    }
}

impl Default for PendingHttpId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PendingHttpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "http:{}", self.0.as_simple())
    }
}

impl Serialize for PendingHttpId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PendingHttpId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("invalid HTTP method")]
    InvalidMethod,
    #[error("unsupported HTTP URL scheme")]
    UnsupportedScheme,
    #[error("invalid HTTP authority")]
    InvalidAuthority,
    #[error("HTTP credentials are not allowed")]
    CredentialsNotAllowed,
    #[error("invalid HTTP port")]
    InvalidPort,
    #[error("invalid HTTP URL")]
    InvalidUrl,
    #[error("invalid HTTP path")]
    InvalidPath,
    #[error("query or fragment is not allowed in an HTTP policy target")]
    QueryOrFragmentNotAllowed,
    #[error("malformed percent escape in HTTP path")]
    MalformedEscape,
    #[error("encoded path separator, percent, control, or NUL is not allowed")]
    EncodedForbiddenByte,
    #[error("literal non-ASCII or control byte is not allowed in HTTP path")]
    InvalidPathByte,
    #[error("invalid pending HTTP identifier")]
    InvalidPendingId,
    #[error("OPTIONS is required for the HTTP asterisk target")]
    AsteriskRequiresOptions,
}
fn replace_pattern_metacharacters(raw: &str) -> (String, Vec<(String, char)>) {
    let mut sanitized = String::with_capacity(raw.len());
    let mut replacements = Vec::new();
    let mut index = 0usize;
    for character in raw.chars() {
        if character != '*' {
            sanitized.push(character);
            continue;
        }
        let token = loop {
            let candidate = format!("glob{index}x");
            index += 1;
            if !raw.contains(&candidate) {
                break candidate;
            }
        };
        sanitized.push_str(&token);
        replacements.push((token, character));
    }
    (sanitized, replacements)
}

const fn is_method_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn decode_path(raw: &str) -> Result<String, HttpParseError> {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte >= 0x80 || byte.is_ascii_control() || byte == b'\\' {
            return Err(HttpParseError::InvalidPathByte);
        }
        if byte != b'%' {
            out.push(char::from(byte));
            index += 1;
            continue;
        }

        if index + 2 >= bytes.len() {
            return Err(HttpParseError::MalformedEscape);
        }
        let high = hex_value(bytes[index + 1]).ok_or(HttpParseError::MalformedEscape)?;
        let low = hex_value(bytes[index + 2]).ok_or(HttpParseError::MalformedEscape)?;
        let decoded = (high << 4) | low;
        if matches!(decoded, b'/' | b'\\' | b'%' | 0..=0x1f | 0x7f) {
            return Err(HttpParseError::EncodedForbiddenByte);
        }
        if is_unreserved(decoded) {
            out.push(char::from(decoded));
        } else {
            out.push('%');
            out.push(hex_digit(high));
            out.push(hex_digit(low));
        }
        index += 3;
    }

    Ok(out)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_digit(value: u8) -> char {
    char::from(b"0123456789ABCDEF"[usize::from(value)])
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_url_and_path() {
        let url = HttpUrl::parse("https://Example.com:443/public/%7e/../api//").expect("valid URL");
        assert_eq!(url.to_string(), "https://example.com/public/api");
    }

    #[test]
    fn preserves_internal_repeated_slashes() {
        let path = NormalizedHttpPath::parse("/a//b///c").expect("valid path");
        assert_eq!(path.as_str(), "/a//b///c");
    }

    #[test]
    fn normalizes_ipv6_authority_and_default_port() {
        let url = HttpUrl::parse("https://[2001:0DB8::1]:443/").expect("valid IPv6 URL");
        assert_eq!(url.to_string(), "https://[2001:db8::1]/");
        assert_eq!(url.authority.port_number(), 443);
    }

    #[test]
    fn path_prefix_requires_segment_boundary() {
        let rule = HttpRuleTarget::new(
            HttpMethodMatcher::All,
            HttpUrl::parse("https://example.com/v1/api").expect("valid rule URL"),
        )
        .expect("valid rule target");
        let request = HttpRequest::from_parts("GET", "https", "example.com", "/v1/api/test")
            .expect("valid request");
        let sibling = HttpRequest::from_parts("GET", "https", "example.com", "/v1/apix")
            .expect("valid request");
        assert!(rule.matches(&request));
        assert!(!rule.matches(&sibling));
    }

    #[test]
    fn github_url_rule_pattern_matches() {
        let rule = HttpRule::new(
            vec!["GET".into()],
            "https://github.com/**/releases/**",
            "GitHub releases",
        );
        let target = rule.target().expect("valid URL pattern");
        let request = HttpRequest::parse_absolute(
            "GET",
            "https://github.com/owner/repo/releases/download/v1.0.0",
        )
        .expect("valid request");
        assert!(target.matches(&request));
        assert_eq!(target.url.to_string(), "https://github.com/**/releases/**");
    }

    #[test]
    fn url_glob_matches_authority_and_path() {
        let target = HttpRule::new(
            vec![],
            "https://*.github.com/repos/*/*",
            "GitHub repositories",
        )
        .target()
        .expect("valid URL pattern");
        let matching =
            HttpRequest::parse_absolute("GET", "https://api.github.com/repos/owner/repo")
                .expect("valid request");
        let wrong_host =
            HttpRequest::parse_absolute("GET", "https://api.example.com/repos/owner/repo")
                .expect("valid request");
        assert!(target.matches(&matching));
        assert!(!target.matches(&wrong_host));
    }
    #[test]
    fn url_glob_star_stays_within_path_segment() {
        let single = HttpRule::new(vec![], "https://example.com/a/*/c", "");
        let double = HttpRule::new(vec![], "https://example.com/a/**/c", "");
        let one =
            HttpRequest::parse_absolute("GET", "https://example.com/a/b/c").expect("valid request");
        let nested = HttpRequest::parse_absolute("GET", "https://example.com/a/b/d/c")
            .expect("valid request");
        assert!(single.target().expect("valid rule").matches(&one));
        assert!(!single.target().expect("valid rule").matches(&nested));
        assert!(double.target().expect("valid rule").matches(&nested));
    }

    #[test]
    fn concrete_request_url_accepts_literal_wildcards() {
        let request = HttpRequest::parse_absolute("GET", "https://example.com/files/*.txt")
            .expect("valid request");
        let target = HttpRule::new(vec![], "https://example.com/files/*.txt", "")
            .target()
            .expect("valid URL glob");
        assert!(target.matches(&request));
    }

    #[test]
    fn rejects_forbidden_path_encodings() {
        for path in ["/a%2fb", "/a%5Cb", "/a%25b", "/a%00b", "/a%zz"] {
            assert!(NormalizedHttpPath::parse(path).is_err(), "{path}");
        }
        assert!(NormalizedHttpPath::parse("/a/%E2%98%83").is_ok());
    }

    #[test]
    fn method_matchers_support_exact_any_of_and_all() {
        let get = HttpMethod::parse("GET").expect("valid method");
        let post = HttpMethod::parse("POST").expect("valid method");
        let exact = HttpMethodMatcher::Exact(get.clone());
        let any = HttpMethodMatcher::AnyOf(vec![get.clone(), post.clone()]);
        assert!(exact.matches(&get));
        assert!(!exact.matches(&post));
        assert!(any.matches(&get));
        assert!(any.matches(&post));
        assert!(HttpMethodMatcher::All.matches(&post));
        assert!(any.covers(&exact));
        assert!(!exact.covers(&any));
        assert!(HttpMethodMatcher::All.covers(&any));
    }

    #[test]
    fn canonical_methods_and_legacy_method_deserialize() {
        let canonical: HttpRule =
            serde_json::from_str(r#"{"methods":["POST","GET"],"url":"https://example.com"}"#)
                .expect("canonical methods");
        assert_eq!(canonical.methods, vec!["POST", "GET"]);
        assert_eq!(
            serde_json::to_string(&canonical).expect("serialize canonical"),
            r#"{"methods":["POST","GET"],"url":"https://example.com"}"#
        );

        let legacy: HttpRule =
            serde_json::from_str(r#"{"method":"GET","url":"https://example.com"}"#)
                .expect("legacy method");
        assert_eq!(legacy.methods, vec!["GET"]);
        assert_eq!(
            serde_json::to_string(&legacy).expect("serialize legacy as canonical"),
            r#"{"methods":["GET"],"url":"https://example.com"}"#
        );

        let all: HttpRule =
            serde_json::from_str(r#"{"url":"https://example.com"}"#).expect("all methods");
        assert!(all.methods.is_empty());
        assert_eq!(
            serde_json::to_string(&all).expect("serialize all methods"),
            r#"{"methods":[],"url":"https://example.com"}"#
        );
    }

    #[test]
    fn asterisk_is_options_only_and_distinct() {
        let rule = HttpRule {
            methods: vec!["OPTIONS".into()],
            url: "https://example.com *".into(),
            comment: None,
        };
        let target = rule.target().expect("valid asterisk rule");
        assert!(matches!(target.url.target, HttpTarget::Asterisk));
        assert_eq!(target.url.to_string(), "https://example.com *");
        assert!(HttpRequest::from_parts("GET", "https", "example.com", "*").is_err());
        let invalid = HttpRule {
            methods: vec!["GET".into()],
            url: "https://example.com *".into(),
            comment: None,
        };
        assert_eq!(
            invalid.target(),
            Err(HttpParseError::AsteriskRequiresOptions)
        );
        let wildcard = HttpRule {
            methods: vec![],
            url: "https://example.com *".into(),
            comment: None,
        };
        assert_eq!(
            wildcard.target(),
            Err(HttpParseError::AsteriskRequiresOptions)
        );
    }

    #[test]
    fn rejects_non_options_asterisk_on_wire() {
        let value = r#"{"method":"GET","url":"https://example.com *"}"#;
        assert!(serde_json::from_str::<HttpRequest>(value).is_err());
    }

    #[test]
    fn serializes_and_deserializes_asterisk_target() {
        let target = HttpRuleTarget::new(
            HttpMethodMatcher::Exact(HttpMethod::parse("OPTIONS").expect("valid method")),
            HttpUrl::parse("https://example.com *").expect("valid asterisk URL"),
        )
        .expect("valid target");
        let json = serde_json::to_string(&target).expect("serialize target");
        let decoded: HttpRuleTarget = serde_json::from_str(&json).expect("deserialize target");
        assert_eq!(decoded, target);
        assert_eq!(
            json,
            r#"{"method":"OPTIONS","url":"https://example.com *"}"#
        );
    }

    #[test]
    fn serializes_all_methods_as_null() {
        let target = HttpRuleTarget::new(
            HttpMethodMatcher::All,
            HttpUrl::parse("https://example.com/").expect("valid URL"),
        )
        .expect("valid target");
        let json = serde_json::to_string(&target).expect("serialize target");
        assert_eq!(json, r#"{"method":null,"url":"https://example.com/"}"#);
        let decoded: HttpRuleTarget = serde_json::from_str(&json).expect("deserialize target");
        assert_eq!(decoded, target);
    }
    #[test]
    fn serializes_and_deserializes_url_glob_target() {
        let target = HttpRule::new(
            vec!["GET".into()],
            "https://api.github.com/repos/*/*",
            "GitHub repositories",
        )
        .target()
        .expect("valid URL glob");
        let json = serde_json::to_string(&target).expect("serialize target");
        let decoded: HttpRuleTarget = serde_json::from_str(&json).expect("deserialize target");
        assert_eq!(decoded, target);
        assert_eq!(
            json,
            r#"{"method":"GET","url":"https://api.github.com/repos/*/*"}"#
        );
    }

    #[test]
    fn rejects_ambiguous_glob_placeholder_restoration() {
        assert!(
            HttpUrl::parse_pattern("https://example.com/%67lob0x/*").is_err(),
            "encoded placeholder text must not be rewritten as a glob"
        );
    }

    #[test]
    fn url_glob_query_and_fragment_are_rejected() {
        assert!(HttpUrl::parse_pattern("https://example.com/path?query").is_err());
        assert!(HttpUrl::parse_pattern("https://example.com/path/*?query").is_err());
        assert!(HttpUrl::parse_pattern("https://example.com/path/*#fragment").is_err());
    }
}

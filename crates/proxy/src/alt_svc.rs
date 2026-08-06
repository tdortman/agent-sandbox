//! Validated `Alt-Svc` mapping store for HTTP/3 discovery.
//!
//! The proxy records one mapping per approved response: the response's origin
//! authority maps to each advertised alternative host and port, with an
//! expiry taken from the `ma` parameter. An alternative is preserved in the
//! client-visible response only when transparent UDP interception covers its
//! port and the mapping can be resolved to the origin before a later QUIC
//! association is claimed. All other alternatives are filtered.
//!
//! When a later association arrives at an alternative endpoint, the store
//! attributes it to the recorded origin. The alternative host and port stay
//! transport details: the original authority keeps its role for `:authority`,
//! SNI, certificate identity, policy identity, and connection pooling.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use tracing::debug;

/// Rewrite the `Alt-Svc` headers of one approved response.
///
/// Validated alternatives are preserved, filtered alternatives are removed,
/// and the special `clear` value passes through. The header is removed
/// entirely when no alternative survives validation.
pub async fn preserve_response_alt_svc<B>(
    response: &mut http::Response<B>,
    store: &AltSvcStore,
    origin: &str,
) {
    let values = response
        .headers()
        .get_all("alt-svc")
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();

    if values.is_empty() {
        return;
    }

    let borrowed = values.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let rewritten = store.record(origin, &borrowed).await;
    let headers = response.headers_mut();
    headers.remove("alt-svc");

    if let Some(value) = rewritten
        && let Ok(value) = http::HeaderValue::from_bytes(&value)
    {
        headers.append("alt-svc", value);
    }
}

/// Default lifetime of an alternative when no `ma` parameter is present
/// (RFC 7838 section 3).
const DEFAULT_MAX_AGE: Duration = Duration::from_hours(24);

/// Default port for an `h3` alternative.
const H3_DEFAULT_PORT: u16 = 443;

/// Split an unbracketed authority into its host and optional port.
///
/// A malformed explicit port filters the alternative instead of silently
/// becoming the default port.
fn split_host_port(authority: &str) -> Option<(&str, u16)> {
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, port.parse().ok()?)),
        None => Some((authority, H3_DEFAULT_PORT)),
    }
}

/// A `host:port` split where a malformed explicit port filters the
/// alternative instead of silently becoming the default port.
fn parse_bracketed<'a>(host: &'a str, suffix: &str) -> Option<(&'a str, u16)> {
    match suffix.strip_prefix(':') {
        Some(port) => Some((host, port.parse().ok()?)),
        None => Some((host, H3_DEFAULT_PORT)),
    }
}

/// Mapping store shared by the TCP and HTTP/3 proxy backends.
pub struct AltSvcStore {
    intercepted_udp_ports: Mutex<Vec<u16>>,
    entries: Mutex<HashMap<(IpAddr, u16), OriginEntry>>,
}

#[derive(Debug, Clone)]
struct OriginEntry {
    origin: String,
    expiry: Instant,
}

impl AltSvcStore {
    /// Build an empty store for the given intercepted UDP ports.
    #[must_use]
    pub fn new(intercepted_udp_ports: Vec<u16>) -> Self {
        Self {
            intercepted_udp_ports: Mutex::new(intercepted_udp_ports),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Record one more intercepted UDP port.
    ///
    /// Port-0 listeners learn their real port only after binding, so the
    /// intercepted set is filled in once the HTTP/3 backend is prepared.
    ///
    /// # Panics
    ///
    /// Panics when the ports lock is poisoned by a panicking task.
    pub fn intercept(&self, port: u16) {
        let mut ports = self
            .intercepted_udp_ports
            .lock()
            .expect("alt-svc ports lock");

        if !ports.contains(&port) {
            ports.push(port);
        }
    }

    /// Whether transparent UDP interception covers `port`.
    ///
    /// # Panics
    ///
    /// Panics when the ports lock is poisoned by a panicking task.
    #[must_use]
    pub fn is_intercepted(&self, port: u16) -> bool {
        self.intercepted_udp_ports
            .lock()
            .expect("alt-svc ports lock")
            .contains(&port)
    }

    /// Record the validated alternatives of one approved response.
    ///
    /// `values` are the raw `Alt-Svc` header values of the response. The
    /// special value `clear` removes the origin's recorded mappings and is
    /// passed through to the client. Every other alternative is validated
    /// against the intercepted UDP ports and the resolved alternative
    /// address, then stored with its expiry.
    ///
    /// Returns the header value to send to the client, or `None` when every
    /// alternative was filtered and the header must be removed.
    ///
    /// # Panics
    ///
    /// Panics when the entry lock is poisoned by a panicking task.
    pub async fn record(&self, origin: &str, values: &[&[u8]]) -> Option<Vec<u8>> {
        let mut preserved = Vec::new();
        let mut new_entries = Vec::new();
        let mut cleared = false;

        for value in values {
            for alternative in parse_alternatives(value) {
                match alternative {
                    Alternative::Clear => cleared = true,

                    Alternative::Service(service) => {
                        let Some(entry) = self.resolved_entry(origin, &service).await else {
                            continue;
                        };

                        new_entries.extend(entry);
                        preserved.push(service.raw.to_vec());
                    }
                }
            }
        }

        if cleared {
            self.clear_origin(origin);
            return Some(b"clear".to_vec());
        }

        if preserved.is_empty() {
            return None;
        }

        // The client replaces its cached alternatives on every response; drop
        // the origin's previous entries so stale alternatives die with the
        // response that stopped advertising them.
        {
            let mut entries = self.entries.lock().expect("alt-svc entries lock");
            entries.retain(|_, entry| entry.origin != origin);
            entries.extend(new_entries);
        }

        Some(preserved.join(&b", "[..]))
    }

    /// Resolve one validated alternative to its recorded transport entries.
    ///
    /// Returns `None` when the alternative is not intercepted or its host
    /// cannot be resolved, so the alternative is filtered.
    async fn resolved_entry(
        &self,
        origin: &str,
        service: &ServiceAlternative<'_>,
    ) -> Option<Vec<((IpAddr, u16), OriginEntry)>> {
        if !self.is_intercepted(service.port) {
            debug!(
                port = service.port,
                "filtering Alt-Svc alternative on an unintercepted port"
            );

            return None;
        }

        let host = service
            .host
            .map_or_else(|| origin_host(origin).unwrap_or_default(), str::to_owned);

        if host.is_empty() {
            debug!("filtering Alt-Svc alternative with an unresolvable host");
            return None;
        }

        let ips = resolve_host(&host).await;

        if ips.is_empty() {
            debug!(host, "filtering Alt-Svc alternative that does not resolve");
            return None;
        }

        let expiry = Instant::now() + service.max_age;
        let origin = origin.to_owned();

        Some(
            ips.into_iter()
                .map(|ip| {
                    ((ip, service.port), OriginEntry {
                        origin: origin.clone(),
                        expiry,
                    })
                })
                .collect(),
        )
    }

    /// Resolve the recorded origin for one transport endpoint.
    ///
    /// Expired entries are dropped on access.
    ///
    /// # Panics
    ///
    /// Panics when the entry lock is poisoned by a panicking task.
    #[must_use]
    pub fn origin_for(&self, ip: IpAddr, port: u16) -> Option<String> {
        let origin = {
            let mut entries = self.entries.lock().expect("alt-svc entries lock");
            let entry = entries.get(&(ip, port))?;

            if entry.expiry <= Instant::now() {
                entries.remove(&(ip, port));
                drop(entries);
                return None;
            }

            let origin = entry.origin.clone();
            drop(entries);
            origin
        };

        Some(origin)
    }

    /// Resolve the origin port for one transport endpoint.
    #[must_use]
    pub fn origin_port_for(&self, ip: IpAddr, port: u16) -> Option<u16> {
        self.origin_for(ip, port)
            .and_then(|origin| origin_port(&origin))
    }

    fn clear_origin(&self, origin: &str) {
        self.entries
            .lock()
            .expect("alt-svc entries lock")
            .retain(|_, entry| entry.origin != origin);
    }
}

/// One parsed element of an `Alt-Svc` header value.
enum Alternative<'a> {
    Clear,
    Service(ServiceAlternative<'a>),
}

struct ServiceAlternative<'a> {
    host: Option<&'a str>,
    port: u16,
    max_age: Duration,
    raw: &'a [u8],
}

/// Split one `Alt-Svc` header value into its alternatives and parameters.
fn parse_alternatives(value: &[u8]) -> Vec<Alternative<'_>> {
    value
        .split(|byte| *byte == b',')
        .filter_map(|part| {
            let part = trim_ascii(part);

            if part.is_empty() {
                return None;
            }

            std::str::from_utf8(part).ok().and_then(parse_element)
        })
        .collect()
}

/// Trim ASCII whitespace from both ends of a byte slice.
fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }

    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }

    value
}

fn parse_element(element: &str) -> Option<Alternative<'_>> {
    if element.eq_ignore_ascii_case("clear") {
        return Some(Alternative::Clear);
    }

    let mut segments = element.split(';');
    let service = segments.next()?;
    let (protocol, authority) = service.split_once('=')?;

    if !protocol.trim().eq_ignore_ascii_case("h3") {
        return None;
    }

    let authority = authority.trim().trim_matches('"');
    let mut max_age = DEFAULT_MAX_AGE;

    for parameter in segments {
        let parameter = parameter.trim();

        if let Some(value) = parameter.strip_prefix("ma=")
            && let Ok(seconds) = value.trim().parse::<u64>()
        {
            max_age = Duration::from_secs(seconds);
        }
    }

    let parsed = parse_authority(authority)?;

    Some(Alternative::Service(ServiceAlternative {
        host: parsed.host,
        port: parsed.port,
        max_age,
        raw: element.as_bytes(),
    }))
}

struct ParsedAuthority<'a> {
    host: Option<&'a str>,
    port: u16,
}

fn parse_authority(authority: &str) -> Option<ParsedAuthority<'_>> {
    if authority.is_empty() {
        return Some(ParsedAuthority {
            host: None,
            port: H3_DEFAULT_PORT,
        });
    }

    // The empty-host form `:port` means the origin host with an explicit
    // alternative port; a malformed port filters the alternative.
    if let Some(port) = authority.strip_prefix(':') {
        return Some(ParsedAuthority {
            host: None,
            port: port.parse().ok()?,
        });
    }

    // Bracketed IPv6 literals split at the closing bracket; everything else
    // splits at the last colon. A malformed port filters the alternative.
    let (host, port) = match authority
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
    {
        Some((host, suffix)) => parse_bracketed(host, suffix)?,
        None => split_host_port(authority)?,
    };

    Some(ParsedAuthority {
        host: Some(host),
        port,
    })
}

fn origin_host(origin: &str) -> Option<String> {
    url::Url::parse(&format!("https://{origin}/"))
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
}

fn origin_port(origin: &str) -> Option<u16> {
    url::Url::parse(&format!("https://{origin}/"))
        .ok()
        .and_then(|url| url.port_or_known_default())
}

async fn resolve_host(host: &str) -> Vec<IpAddr> {
    match tokio::net::lookup_host((host, H3_DEFAULT_PORT)).await {
        Ok(addresses) => addresses.map(|address| address.ip()).collect(),

        Err(error) => {
            debug!(host, error = %error, "cannot resolve Alt-Svc alternative host");
            Vec::new()
        }
    }
}

/// Convenience for tests: a store with a fixed intercepted port list.
#[cfg(test)]
mod tests {
    use super::{AltSvcStore, parse_authority};
    use std::{net::IpAddr, time::Duration};
    use tokio::time::sleep;

    fn store() -> AltSvcStore {
        AltSvcStore::new(vec![443, 8443])
    }

    /// Resolve `localhost` the same way `record` does, so assertions match
    /// the recorded transport endpoints without depending on external DNS.
    async fn localhost_ips() -> Vec<IpAddr> {
        tokio::net::lookup_host(("localhost", 443))
            .await
            .expect("resolve localhost")
            .map(|address| address.ip())
            .collect()
    }

    async fn recorded_origins(store: &AltSvcStore, port: u16) -> Vec<String> {
        let mut origins = localhost_ips()
            .await
            .into_iter()
            .filter_map(|ip| store.origin_for(ip, port))
            .collect::<Vec<_>>();

        origins.sort();
        origins.dedup();
        origins
    }

    #[tokio::test]
    async fn preserves_intercepted_alternative_with_default_expiry() {
        let store = store();

        let rewritten = store
            .record("localhost:443", &[b"h3=\":8443\""])
            .await
            .expect("preserved alternative");

        assert_eq!(rewritten, b"h3=\":8443\"");
        assert_eq!(recorded_origins(&store, 8443).await, vec!["localhost:443"]);
    }

    #[tokio::test]
    async fn filters_unintercepted_ports() {
        let store = store();
        let rewritten = store.record("localhost:443", &[b"h3=\":9999\""]).await;
        assert_eq!(rewritten, None);
        assert_eq!(recorded_origins(&store, 9999).await, Vec::<String>::new());
    }

    #[tokio::test]
    async fn filters_non_h3_protocols_and_malformed_values() {
        let store = store();

        assert_eq!(
            store.record("localhost:443", &[b"h2=\":8443\""]).await,
            None
        );

        assert_eq!(store.record("localhost:443", &[b"garbage"]).await, None);
    }

    #[tokio::test]
    async fn clear_removes_recorded_mappings_and_passes_through() {
        let store = store();

        store
            .record("localhost:443", &[b"h3=\":8443\""])
            .await
            .expect("preserved alternative");

        let rewritten = store
            .record("localhost:443", &[b"clear"])
            .await
            .expect("clear passes through");

        assert_eq!(rewritten, b"clear");
        assert_eq!(recorded_origins(&store, 8443).await, Vec::<String>::new());
    }

    #[tokio::test]
    async fn replacement_drops_alternatives_no_longer_advertised() {
        let store = store();

        store
            .record("localhost:443", &[b"h3=\":8443\""])
            .await
            .expect("first alternative");

        store
            .record("localhost:443", &[b"h3=\":443\""])
            .await
            .expect("second alternative");

        assert_eq!(recorded_origins(&store, 8443).await, Vec::<String>::new());
        assert_eq!(recorded_origins(&store, 443).await, vec!["localhost:443"]);
    }

    #[tokio::test]
    async fn expired_entries_are_not_resolved() {
        let store = store();

        store
            .record("localhost:443", &[b"h3=\":8443\"; ma=1"])
            .await
            .expect("short-lived alternative");

        sleep(Duration::from_millis(1_100)).await;
        assert_eq!(recorded_origins(&store, 8443).await, Vec::<String>::new());
    }

    #[tokio::test]
    async fn origin_port_comes_from_the_recorded_origin() {
        let store = store();

        store
            .record("localhost:443", &[b"h3=\":8443\""])
            .await
            .expect("alternative");

        let ips = super::resolve_host("localhost").await;
        assert!(!ips.is_empty(), "localhost must resolve");

        for ip in ips {
            assert_eq!(store.origin_port_for(ip, 8443), Some(443));
        }
    }

    #[tokio::test]
    async fn multiple_valid_alternatives_are_all_preserved() {
        let store = store();

        let rewritten = store
            .record("localhost:443", &[b"h3=\":8443\", h3=\":443\""])
            .await
            .expect("preserved alternatives");

        assert!(String::from_utf8_lossy(&rewritten).contains("h3=\":8443\""));
        assert!(String::from_utf8_lossy(&rewritten).contains("h3=\":443\""));
    }

    #[test]
    fn empty_host_authority_keeps_explicit_port() {
        let parsed = parse_authority(":8443").expect("valid authority");
        assert_eq!(parsed.host, None);
        assert_eq!(parsed.port, 8443);
        let parsed = parse_authority("alt.test:8443").expect("valid authority");
        assert_eq!(parsed.host, Some("alt.test"));
        assert_eq!(parsed.port, 8443);
        let parsed = parse_authority("").expect("valid authority");
        assert_eq!(parsed.host, None);
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn malformed_authorities_are_filtered() {
        assert!(parse_authority(":not-a-port").is_none());
        assert!(parse_authority("alt.test:not-a-port").is_none());
        assert!(parse_authority("[::1]:not-a-port").is_none());
    }
}

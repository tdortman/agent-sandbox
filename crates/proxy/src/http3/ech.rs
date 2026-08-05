//! Upstream ECH configuration discovery and verification for HTTP/3.
//!
//! The proxy queries the HTTPS (SVCB) record of each upstream origin through
//! the resolver named in `/etc/resolv.conf` (the sandbox DNS path) and
//! verifies the advertised ECH configuration with rustls. A verified
//! configuration enables ECH for that origin's upstream connections.
//!
//! Fail-closed rules:
//!
//! - No HTTPS record, or an HTTPS record without an `ech` parameter: the origin
//!   does not advertise ECH, so ordinary TLS is used and the SNI and
//!   certificate identity still have to match the policy target.
//! - An HTTPS record whose `ech` parameter cannot be parsed or matched against
//!   a supported HPKE suite: the connection fails, because the advertised
//!   metadata is unverifiable.
//! - An origin that rejects a verified ECH offer: the TLS handshake fails
//!   closed (rustls aborts with `ech_required`), so the encrypted identity is
//!   never silently downgraded.
//!
//! Note that the sandbox DNS path rewrites unsigned ECH configurations with
//! the proxy's own configuration, so in the sandbox an origin advertising
//! ECH fails closed rather than negotiating with its real configuration.

use super::{BoxError, hpke::ECH_SUPPORTED_SUITES};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType, rdata::svcb::SvcParamKey},
};

use rustls::{client::EchConfig, pki_types::EchConfigListBytes};

use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tracing::warn;

const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const MIN_TTL_SECONDS: u32 = 60;
const MAX_TTL_SECONDS: u32 = 3_600;
const DEFAULT_TTL_SECONDS: u32 = 3_600;

/// Verified upstream ECH configurations, cached per origin host.
pub struct UpstreamEch {
    /// Resolver override for tests; `None` reads `/etc/resolv.conf`.
    dns: Option<SocketAddr>,

    cache: Mutex<HashMap<String, CachedEch>>,
}

struct CachedEch {
    config: Option<Arc<EchConfig>>,
    expires_at: Instant,
}

/// The `ech` parameter of one HTTPS record.
struct EchAnswer {
    config: Vec<u8>,
    ttl: u32,
}

impl UpstreamEch {
    /// Build an ECH configuration cache.
    #[must_use]
    pub fn new(dns: Option<SocketAddr>) -> Self {
        Self {
            dns,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get the verified ECH configuration for one origin host.
    ///
    /// Returns `Ok(None)` when the origin does not advertise ECH or the DNS
    /// path cannot be read; both fall back to ordinary TLS. Returns an error
    /// only when the origin advertises an unverifiable configuration.
    ///
    /// # Panics
    ///
    /// Panics when the cache lock is poisoned by a panicking task.
    pub async fn config_for(&self, host: &str) -> Result<Option<Arc<EchConfig>>, BoxError> {
        {
            let mut cache = self.cache.lock().expect("ECH cache lock");

            if let Some(entry) = cache.get(host) {
                if entry.expires_at > Instant::now() {
                    return Ok(entry.config.clone());
                }

                cache.remove(host);
            }
        }

        match self.query_https(host).await {
            Ok(Some(answer)) => {
                let config = verify_config(&answer.config)?;
                let config = Arc::new(config);
                let ttl = answer.ttl.clamp(MIN_TTL_SECONDS, MAX_TTL_SECONDS);

                self.cache
                    .lock()
                    .expect("ECH cache lock")
                    .insert(host.to_owned(), CachedEch {
                        config: Some(config.clone()),
                        expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
                    });

                Ok(Some(config))
            }

            Ok(None) => {
                let ttl = DEFAULT_TTL_SECONDS.clamp(MIN_TTL_SECONDS, MAX_TTL_SECONDS);

                self.cache
                    .lock()
                    .expect("ECH cache lock")
                    .insert(host.to_owned(), CachedEch {
                        config: None,
                        expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
                    });

                Ok(None)
            }

            Err(error) => {
                // A discovery failure is not a verdict on the origin's ECH
                // support: do not cache it, so the next connection retries
                // instead of treating a transient failure as "no ECH".
                warn!(host, error = %error, "upstream ECH discovery failed; using ordinary TLS");
                Ok(None)
            }
        }
    }

    async fn query_https(&self, host: &str) -> Result<Option<EchAnswer>, BoxError> {
        let server = match self.resolver_address() {
            Ok(server) => server,
            Err(error) => {
                warn!(error = %error, "no usable DNS resolver for upstream ECH discovery");
                return Ok(None);
            }
        };

        let name = Name::from_ascii(host)
            .map_err(|error| BoxError::from(format!("invalid origin host: {error}")))?;

        let mut query = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(name.clone(), RecordType::HTTPS));

        let packet = query
            .to_vec()
            .map_err(|error| BoxError::from(format!("cannot encode HTTPS query: {error}")))?;

        let socket = tokio::net::UdpSocket::bind(match server {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })
        .await?;

        let reply = async {
            socket.send_to(&packet, server).await?;
            let mut buffer = [0_u8; 4_096];
            let (size, _) = socket.recv_from(&mut buffer).await?;
            Ok::<_, std::io::Error>(buffer[..size].to_vec())
        };

        let response = tokio::time::timeout(DNS_TIMEOUT, reply)
            .await
            .map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "HTTPS query timed out"))??;

        let message = Message::from_vec(&response)
            .map_err(|error| BoxError::from(format!("cannot decode HTTPS answer: {error}")))?;

        Ok(parse_https_answer(&message))
    }

    fn resolver_address(&self) -> Result<SocketAddr, BoxError> {
        if let Some(address) = self.dns {
            return Ok(address);
        }

        let nameserver = parse_resolv_conf(Path::new("/etc/resolv.conf"))
            .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no nameserver found"))?;

        Ok(SocketAddr::new(nameserver, 53))
    }
}

/// Extract the `ech` parameter of an HTTPS record in a DNS answer.
///
/// The answer name must match the question name, and every HTTPS record is
/// scanned so an earlier record without `ech` does not hide a later one.
fn parse_https_answer(message: &Message) -> Option<EchAnswer> {
    if message.metadata.response_code != ResponseCode::NoError {
        return None;
    }

    let queried = &message.queries.first()?.name;

    for answer in &message.answers {
        if &answer.name != queried {
            continue;
        }

        let RData::HTTPS(https) = &answer.data else {
            continue;
        };

        for (key, value) in &https.0.svc_params {
            if *key == SvcParamKey::EchConfigList
                && let hickory_proto::rr::rdata::svcb::SvcParamValue::EchConfigList(config) = value
            {
                return Some(EchAnswer {
                    config: config.0.clone(),
                    ttl: answer.ttl,
                });
            }
        }
    }

    None
}

/// Verify one advertised ECH configuration list against the supported HPKE
/// suites.
///
/// # Errors
///
/// Returns an error when the configuration is malformed or no supported
/// suite matches, so unverifiable advertised metadata fails closed.
fn verify_config(config_list: &[u8]) -> Result<EchConfig, BoxError> {
    EchConfig::new(EchConfigListBytes::from(config_list), ECH_SUPPORTED_SUITES).map_err(|error| {
        BoxError::from(format!("unverifiable upstream ECH configuration: {error}"))
    })
}

/// Read the first `nameserver` entry of a resolv.conf file.
fn parse_resolv_conf(path: &Path) -> Option<IpAddr> {
    let text = std::fs::read_to_string(path).ok()?;

    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or(line).trim();

        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };

        let Some(token) = rest.split_whitespace().next() else {
            continue;
        };

        if let Ok(ip) = token.parse::<IpAddr>() {
            return Some(ip);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{parse_https_answer, parse_resolv_conf, verify_config};

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{
                HTTPS,
                svcb::{EchConfigList, SVCB, SvcParamKey, SvcParamValue},
            },
        },
    };

    use std::{net::Ipv4Addr, path::Path};

    fn https_answer(ech: Option<&[u8]>) -> Message {
        let name = Name::from_ascii("example.test.").expect("valid name");
        let mut params = vec![(SvcParamKey::Port, SvcParamValue::Port(443))];

        if let Some(config) = ech {
            params.push((
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(config.to_vec())),
            ));
        }

        let https = RData::HTTPS(HTTPS(SVCB::new(1, name.clone(), params)));
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::HTTPS));
        message.add_answer(Record::from_rdata(name, 300, https));
        message
    }

    #[test]
    fn extracts_ech_config_from_https_answer() {
        let answer = https_answer(Some(&[1, 2, 3, 4]));
        let parsed = parse_https_answer(&answer).expect("parsed answer");
        assert_eq!(parsed.config, vec![1, 2, 3, 4]);
        assert_eq!(parsed.ttl, 300);
    }

    #[test]
    fn https_answer_without_ech_means_no_config() {
        let answer = https_answer(None);
        assert!(parse_https_answer(&answer).is_none());
    }

    #[test]
    fn non_https_answers_are_ignored() {
        let name = Name::from_ascii("example.test.").expect("valid name");
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::HTTPS));

        message.add_answer(Record::from_rdata(
            name,
            300,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::LOCALHOST)),
        ));

        assert!(parse_https_answer(&message).is_none());
    }

    #[test]
    fn servfail_answers_are_ignored() {
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.metadata.response_code = hickory_proto::op::ResponseCode::ServFail;
        assert!(parse_https_answer(&message).is_none());
    }

    #[test]
    fn scans_all_https_records_and_matches_the_query_name() {
        use hickory_proto::rr::rdata::svcb::{EchConfigList, SvcParamKey, SvcParamValue};

        let name = Name::from_ascii("example.test.").expect("valid name");
        let other = Name::from_ascii("other.test.").expect("valid name");
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::HTTPS));

        // A record for another name, then an ech-less record for the queried
        // name, then the ech-bearing record: the scan must find the last one.
        // The question itself stays the name of the first query.
        message.add_answer(Record::from_rdata(
            other,
            300,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::LOCALHOST)),
        ));

        message.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::HTTPS(hickory_proto::rr::rdata::HTTPS(SVCB::new(
                1,
                name.clone(),
                Vec::new(),
            ))),
        ));

        message.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::HTTPS(hickory_proto::rr::rdata::HTTPS(SVCB::new(2, name, vec![(
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(vec![9, 9])),
            )]))),
        ));

        let parsed = parse_https_answer(&message).expect("ech record found");
        assert_eq!(parsed.config, vec![9, 9]);
    }

    #[test]
    fn rejects_unverifiable_ech_configs() {
        assert!(verify_config(&[0xFF, 0x00, 0x01]).is_err());
    }

    #[test]
    fn reads_first_nameserver_from_resolv_conf() {
        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("resolv.conf");

        std::fs::write(
            &path,
            "# comment\nnameserver 10.0.0.53\nnameserver 10.0.0.54\n",
        )
        .expect("write resolv.conf");

        assert_eq!(
            parse_resolv_conf(&path),
            Some(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)))
        );
    }

    #[test]
    fn missing_resolv_conf_yields_no_nameserver() {
        assert_eq!(
            parse_resolv_conf(Path::new("/nonexistent/resolv.conf")),
            None
        );
    }

    #[test]
    fn ignores_malformed_nameserver_lines() {
        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("resolv.conf");

        std::fs::write(&path, "nameserver not-an-ip\nnameserver 192.0.2.1\n")
            .expect("write resolv.conf");

        assert_eq!(
            parse_resolv_conf(&path),
            Some(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
    }
}

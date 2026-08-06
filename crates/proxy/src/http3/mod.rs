//! Project-owned HTTP/3 backend boundary.
//!
//! This module terminates downstream QUIC/HTTP/3 associations and relays
//! approved requests through separately controlled upstream HTTP/3
//! connections. Quinn and h3 types stay inside this module and its
//! submodules; the rest of the proxy sees only the configuration and the
//! running backend.
//!
//! The backend is disabled by default. The proxy operator enables it with an
//! explicit flag, and the sandbox firewall must route the intercepted UDP
//! port to the proxy before any HTTP/3 traffic can arrive.

mod association;

mod ech;
mod hpke;
mod session;
mod socket;
pub mod upstream;
use crate::{alt_svc::AltSvcStore, cert::CertificateIssuer, policy::PolicySession};
use agent_sandbox_core::ProxyConnectionId;
use socket::TransparentUdpSocket;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::sync::{Notify, Semaphore};

/// Owner of one locally-issued QUIC connection-ID route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionIdOwner {
    pub(crate) stable_id: usize,
    pub(crate) proxy_connection_id: ProxyConnectionId,
}

/// Registry of authenticated locally-issued QUIC connection IDs.
#[derive(Debug, Default)]
pub(crate) struct ConnectionIdRegistry {
    owners: Mutex<HashMap<quinn::ConnectionId, ConnectionIdOwner>>,
}

impl ConnectionIdRegistry {
    pub(crate) fn bind(
        &self,
        id: quinn::ConnectionId,
        owner: ConnectionIdOwner,
    ) -> Result<(), String> {
        if id.is_empty() {
            return Ok(());
        }

        let mut owners = self
            .owners
            .lock()
            .map_err(|_| "QUIC connection-ID registry lock poisoned".to_owned())?;

        match owners.get(&id) {
            Some(existing) if *existing == owner => Ok(()),
            Some(existing) => Err(format!(
                "QUIC connection ID {id} already belongs to stable connection {}",
                existing.stable_id
            )),
            None => {
                owners.insert(id, owner);
                drop(owners);
                Ok(())
            }
        }
    }

    pub(crate) fn unbind(
        &self,
        id: quinn::ConnectionId,
        owner: ConnectionIdOwner,
    ) -> Result<(), String> {
        if id.is_empty() {
            return Ok(());
        }

        let mut owners = self
            .owners
            .lock()
            .map_err(|_| "QUIC connection-ID registry lock poisoned".to_owned())?;

        match owners.get(&id) {
            Some(existing) if *existing == owner => {
                owners.remove(&id);
                drop(owners);
                Ok(())
            }
            Some(existing) => Err(format!(
                "QUIC connection ID {id} belongs to stable connection {}, not {}",
                existing.stable_id, owner.stable_id
            )),
            None => Err(format!("unknown QUIC connection ID {id}")),
        }
    }

    pub(crate) fn remove_owner(&self, owner: ConnectionIdOwner) {
        let Ok(mut owners) = self.owners.lock() else {
            return;
        };
        owners.retain(|_, existing| *existing != owner);
    }
}

/// Shared state for every downstream QUIC association.
pub struct Http3State {
    pub policy: Arc<PolicySession>,
    pub issuer: CertificateIssuer,
    pub shutdown: Arc<Notify>,
    pub active_checks: Arc<Semaphore>,
    pub upstream: Arc<upstream::UpstreamPool>,
    pub destination_port: u16,
    pub alt_svc: Arc<AltSvcStore>,
    pub(crate) connection_ids: Arc<ConnectionIdRegistry>,
}

/// Configuration for the HTTP/3 backend.
pub struct Http3Config {
    pub policy: Arc<PolicySession>,
    pub issuer: CertificateIssuer,
    pub shutdown: Arc<Notify>,
    pub active_checks: Arc<Semaphore>,
    pub listen_port: u16,
    pub alt_ports: Vec<u16>,
    pub alt_svc: Arc<AltSvcStore>,
    pub test_destination: Option<SocketAddr>,
    pub test_ech_dns: Option<SocketAddr>,
}

/// Prepare the HTTP/3 backend so every fallible setup step runs before
/// the proxy declares itself ready.
///
/// # Errors
///
/// Returns an error when the upstream trust store is missing or the UDP
/// listeners cannot be bound.
pub fn prepare(config: Http3Config) -> Result<Http3Backend, BoxError> {
    let ca_file = std::env::var_os("SSL_CERT_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| boxed("SSL_CERT_FILE is required to verify upstream HTTP/3 certificates"))?;

    let upstream = Arc::new(upstream::UpstreamPool::new(&ca_file, config.test_ech_dns)?);
    let transparent = config.test_destination.is_none();

    let destination_port = config
        .test_destination
        .map_or(config.listen_port, |destination| destination.port());

    let state = Arc::new(Http3State {
        policy: config.policy,
        issuer: config.issuer,
        shutdown: config.shutdown,
        active_checks: config.active_checks,
        upstream,
        destination_port,
        alt_svc: config.alt_svc.clone(),
        connection_ids: Arc::new(ConnectionIdRegistry::default()),
    });

    let v4 = bind_endpoint(
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        config.listen_port,
        transparent,
        &state,
    )?;

    let v6 = bind_endpoint(
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        config.listen_port,
        transparent,
        &state,
    )?;

    let main_destination =
        association::DestinationResolver::new(config.listen_port, config.test_destination, false);

    let mut alternatives = Vec::with_capacity(config.alt_ports.len());

    for port in config.alt_ports {
        let v4 = bind_endpoint(
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port,
            transparent,
            &state,
        )?;

        let v6 = bind_endpoint(
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            port,
            transparent,
            &state,
        )?;

        let destination =
            association::DestinationResolver::new(port, config.test_destination, true);

        alternatives.push(AltEndpoint {
            v4,
            v6,
            destination,
        });
    }

    Ok(Http3Backend {
        v4,
        v6,
        state,
        destination: main_destination,
        alternatives,
    })
}

/// A prepared HTTP/3 backend; run it with [`run`].
pub struct Http3Backend {
    v4: quinn::Endpoint,
    v6: quinn::Endpoint,
    state: Arc<Http3State>,
    destination: association::DestinationResolver,
    alternatives: Vec<AltEndpoint>,
}

/// One alternative UDP listener for validated `Alt-Svc` endpoints.
struct AltEndpoint {
    v4: quinn::Endpoint,
    v6: quinn::Endpoint,
    destination: association::DestinationResolver,
}

/// Run a prepared HTTP/3 backend until shutdown is signalled.
pub async fn run(backend: Http3Backend) {
    let Http3Backend {
        v4,
        v6,
        state,
        destination,
        alternatives,
    } = backend;

    let v4_loop = tokio::spawn(association::accept_loop(
        v4,
        state.clone(),
        destination.clone(),
    ));

    let v6_loop = tokio::spawn(association::accept_loop(v6, state.clone(), destination));

    for alternative in alternatives {
        tokio::spawn(association::accept_loop(
            alternative.v4,
            state.clone(),
            alternative.destination.clone(),
        ));

        tokio::spawn(association::accept_loop(
            alternative.v6,
            state.clone(),
            alternative.destination,
        ));
    }

    tracing::info!("HTTP/3 backend listening");
    let _ = tokio::join!(v4_loop, v6_loop);
}

fn bind_endpoint(
    ip: IpAddr,
    port: u16,
    transparent: bool,
    state: &Http3State,
) -> Result<quinn::Endpoint, BoxError> {
    let socket = TransparentUdpSocket::bind(SocketAddr::new(ip, port), transparent)?;
    let tls = downstream_tls_config(state)?;

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(tls),
        Arc::new(socket),
        quinn::default_runtime()
            .ok_or_else(|| std::io::Error::other("no async runtime available"))?,
    )?;

    Ok(endpoint)
}

fn downstream_tls_config(state: &Http3State) -> Result<quinn::ServerConfig, BoxError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SandboxCertResolver {
            issuer: state.issuer.clone(),
            fallback_name: std::net::Ipv4Addr::LOCALHOST.to_string(),
        }));

    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
    let tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls));
    server_config.transport_config(Arc::new(transport));

    // Path migration stays subject to the policy-owned tuple rebind check.
    server_config.migration(true);

    Ok(server_config)
}

/// Issues a leaf certificate from the sandbox CA for each client's SNI.
struct SandboxCertResolver {
    issuer: CertificateIssuer,
    fallback_name: String,
}

impl std::fmt::Debug for SandboxCertResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxCertResolver")
            .field("issuer", &self.issuer)
            .field("fallback_name", &self.fallback_name)
            .finish()
    }
}

impl rustls::server::ResolvesServerCert for SandboxCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let server_name = client_hello.server_name().unwrap_or(&self.fallback_name);

        let issued = match self.issuer.issue(server_name) {
            Ok(issued) => issued,
            Err(error) => {
                tracing::warn!(server_name, %error, "HTTP/3 downstream certificate issue failed");
                return None;
            }
        };

        let signing_key = match rustls::crypto::ring::sign::any_supported_type(&issued.private_key)
        {
            Ok(signing_key) => signing_key,
            Err(error) => {
                tracing::warn!(server_name, ?error, "HTTP/3 downstream signing key failed");
                return None;
            }
        };

        let key = rustls::sign::CertifiedKey::new(issued.certificate_chain.clone(), signing_key);
        Some(Arc::new(key))
    }
}

/// Shared error type for the HTTP/3 backend.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn boxed(message: &'static str) -> BoxError {
    message.into()
}

#[cfg(test)]
mod tests {
    use super::{ConnectionIdOwner, ConnectionIdRegistry};
    use agent_sandbox_core::ProxyConnectionId;

    fn owner(stable_id: usize) -> ConnectionIdOwner {
        ConnectionIdOwner {
            stable_id,
            proxy_connection_id: ProxyConnectionId::new(),
        }
    }

    #[test]
    fn connection_id_registry_rejects_collisions_and_wrong_owners() {
        let registry = ConnectionIdRegistry::default();
        let id = quinn::ConnectionId::new(&[0x42; 8]);
        let first = owner(1);
        let second = owner(2);

        registry.bind(id, first).expect("first owner binds");
        registry.bind(id, first).expect("same owner is idempotent");
        assert!(registry.bind(id, second).is_err());
        assert!(registry.unbind(id, second).is_err());
        registry.unbind(id, first).expect("owner unbinds");
        assert!(registry.unbind(id, first).is_err());
    }

    #[test]
    fn connection_id_registry_removes_all_ids_for_a_torn_down_owner() {
        let registry = ConnectionIdRegistry::default();
        let first = owner(1);
        let second = owner(2);
        let first_id = quinn::ConnectionId::new(&[0x41; 8]);
        let second_id = quinn::ConnectionId::new(&[0x42; 8]);

        registry.bind(first_id, first).expect("first owner binds");
        registry
            .bind(second_id, first)
            .expect("first owner binds again");
        registry
            .bind(second_id, second)
            .expect_err("IDs cannot be stolen");
        registry.remove_owner(first);
        registry
            .bind(first_id, second)
            .expect("teardown releases first ID");
        registry
            .bind(second_id, second)
            .expect("teardown releases second ID");
    }

    #[test]
    fn connection_id_registry_allows_zero_length_ids_without_global_routing() {
        let registry = ConnectionIdRegistry::default();
        let id = quinn::ConnectionId::new(&[]);
        let first = owner(1);
        let second = owner(2);

        registry
            .bind(id, first)
            .expect("zero-length CID binds locally");
        registry
            .bind(id, second)
            .expect("zero-length CIDs use tuple routing");
    }
}

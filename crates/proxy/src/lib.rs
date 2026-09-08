//! The transparent agent-sandbox HTTP proxy.
//!
//! The proxy terminates downstream HTTP/1.x and HTTP/2 (TCP) and HTTP/3
//! (QUIC) connections, claims each intercepted flow with policyd, and
//! relays approved requests through separately controlled upstream
//! connections. Policy decisions are made by the policyd service over the
//! [`policy`] RPC client; certificate and ECH issuance are handled by the
//! [`cert`] and [`ech_state`] modules; [`alt_svc`] tracks validated
//! `Alt-Svc` mappings; [`semantic`] owns protocol-independent request and
//! response values shared by both backends.

/// Install `ring` as the process-level rustls crypto provider.
///
/// Compiling both the `ring` and `aws_lc_rs` rustls features stops rustls
/// from inferring a provider from crate features, while rama's TLS builders
/// still ask for the process-level default. Every rustls config in this crate
/// selects `ring` explicitly, so the default keeps rama aligned with them.
pub fn install_process_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub mod alt_svc;

pub mod cert;
pub mod ech_state;
pub mod http3;
pub mod policy;
pub mod semantic;
pub mod tcp_backend;
pub mod upstream_tls;

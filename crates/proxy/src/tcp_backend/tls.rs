use crate::{cert::CertificateIssuer, ech_state::DownstreamEch, http3};
use rama_core::{Service, error::BoxError, extensions::ExtensionsRef, io::Io};
use rama_tls_rustls::server::TlsStream as RustlsTlsStream;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct TlsServerName(pub(crate) String);

impl rama_core::extensions::Extension for TlsServerName {}

#[derive(Clone)]
pub struct RustlsTlsService<S> {
    pub(crate) config: Arc<rustls::ServerConfig>,
    pub(crate) inner: S,
}

impl<S, IO> Service<IO> for RustlsTlsService<S>
where
    IO: Io + Unpin + ExtensionsRef + std::fmt::Debug + Sync + 'static,
    S: Service<RustlsTlsStream<IO>, Error: Into<BoxError>>,
{
    type Error = BoxError;
    type Output = S::Output;

    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        // `TlsAcceptor` drives the full handshake state machine on a
        // `ServerConnection`, including ECH decryption. The
        // `LazyConfigAcceptor` path cannot be used: its config-independent
        // ClientHello pre-processing skips ECH entirely.
        let acceptor = rama_tls_rustls::dep::tokio_rustls::TlsAcceptor::from(self.config.clone());

        let stream = acceptor.accept(stream).await?;

        // Record the negotiated SNI on the connection extensions. The HTTP
        // server clones those extensions into each request's `Ingress`,
        // giving policy the verified TLS identity for authority resolution.
        // With an accepted ECH offer this is the decrypted inner name.
        let server_name = stream.get_ref().1.server_name().map(ToString::to_string);

        let stream = RustlsTlsStream::new(stream);

        if let Some(server_name) = server_name {
            stream.extensions().insert(TlsServerName(server_name));
        }

        self.inner.serve(stream).await.map_err(Into::into)
    }
}

/// Build the shared TLS configuration for one TCP listener.
///
/// The configuration is built once per listener and cloned per
/// connection with a destination-aware certificate resolver. The clone
/// shares the ticketer and session storage through their `Arc` fields,
/// so resumption state survives between handshakes.
pub fn build_tcp_tls_config(
    issuer: CertificateIssuer,
    ech: Option<&DownstreamEch>,
    fallback_name: String,
) -> Result<rustls::ServerConfig, BoxError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // The per-connection clone replaces this resolver with one that
    // issues certificates for the destination address, so the placeholder
    // is never used for a real handshake.
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(http3::SandboxCertResolver {
            issuer,
            fallback_name,
        }));

    // Terminate downstream ECH with the same key material the HTTP/3 leg
    // uses, so clients that fetch their configuration through the sandbox
    // DNS rewrite get a decryptable offer on both legs.
    if let Some(ech) = ech {
        tls = tls.with_ech_keys(ech.ech_keys()?).map_err(BoxError::from)?;
    }

    // h2 preferred, http/1.1 fallback: server preference order matching
    // the previous accept implementation's ALPN callback.
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // Real stateless tickets for TLS 1.2 and 1.3 resumption; the rustls
    // default ticketer never produces tickets.
    tls.ticketer = rustls::crypto::ring::Ticketer::new()?;

    Ok(tls)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    /// Drive a rustls client and server handshake through an in-memory pipe.
    fn drive_handshake(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) {
        let mut to_server = Vec::new();
        let mut to_client = Vec::new();

        for _ in 0..64 {
            while client.wants_write() {
                client.write_tls(&mut to_server).expect("client writes");
            }

            while server.wants_write() {
                server.write_tls(&mut to_client).expect("server writes");
            }

            if client.wants_read() && !to_client.is_empty() {
                let read = client
                    .read_tls(&mut to_client.as_slice())
                    .expect("client reads");

                to_client.drain(..read);
                client.process_new_packets().expect("client processes");
            }

            if server.wants_read() && !to_server.is_empty() {
                let read = server
                    .read_tls(&mut to_server.as_slice())
                    .expect("server reads");

                to_server.drain(..read);
                server.process_new_packets().expect("server processes");
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                return;
            }
        }

        panic!("TLS handshake did not finish");
    }

    #[test]
    fn downstream_ech_handshake_decrypts_inner_hello() {
        // Generate the same key material the proxy persists in its ECH state.
        let dir = tempfile::tempdir().expect("temp ECH state");

        let state = crate::ech_state::load_or_generate(dir.path()).expect("ECH state");

        // A server that terminates ECH with that state, issuing certificates
        // for the inner (real) server name.
        let inner_name = "ech-test.example";

        let certified = rcgen::generate_simple_self_signed(vec![inner_name.to_owned()])
            .expect("test certificate");

        let certificate = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());

        let private_key =
            rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                .expect("test key");

        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let keys = crate::http3::hpke::ECH_SUPPORTED_SUITES
            .iter()
            .map(|hpke| {
                rustls::server::ech::EchKeys::new(
                    rustls::pki_types::EchConfigListBytes::from(state.config_list.as_slice()),
                    &state.private_key,
                    *hpke,
                )
                .expect("ECH keys")
            })
            .collect();

        let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .expect("server certificate")
            .with_ech_keys(keys)
            .expect("server ECH keys");

        let mut server =
            rustls::ServerConnection::new(Arc::new(server_config)).expect("server connection");

        // A client that fetched the proxy's ECH configuration (the same bytes
        // the sandbox DNS rewrite distributes) and connects to the inner name.
        let config = rustls::client::EchConfig::new(
            rustls::pki_types::EchConfigListBytes::from(state.config_list.as_slice()),
            crate::http3::hpke::ECH_SUPPORTED_SUITES,
        )
        .expect("client ECH configuration");

        let client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_ech(rustls::client::EchMode::Enable(config))
            .expect("client ECH mode")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();

        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            rustls::pki_types::ServerName::try_from(inner_name).expect("server name"),
        )
        .expect("client connection");

        drive_handshake(&mut client, &mut server);
        assert_eq!(client.ech_status(), rustls::client::EchStatus::Accepted);
        assert!(!server.is_handshaking());

        assert_eq!(
            server.server_name().map(ToString::to_string),
            Some(inner_name.to_owned())
        );
    }

    /// Accepts any server certificate; the test asserts ECH behaviour, not
    /// certificate verification.
    #[derive(Debug)]
    struct AcceptAllVerifier;

    impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            certificate: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                certificate,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            certificate: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                certificate,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

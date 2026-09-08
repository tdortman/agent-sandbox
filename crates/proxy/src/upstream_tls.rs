//! Client identities scoped to exact upstream HTTPS origins.
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use rama_core::error::{BoxError, BoxErrorExt};
use rustls::{
    client::ResolvesClientCert,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    sign::{CertifiedKey, SingleCertAndKey},
};
use serde::Deserialize;

/// Client credentials loaded once at startup and shared by both upstream
/// backends.
#[derive(Default)]
pub struct UpstreamClientIdentities {
    identities: HashMap<String, Arc<dyn ResolvesClientCert>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientIdentityFiles {
    origin: String,
    certificate: PathBuf,
    private_key: PathBuf,
}

impl UpstreamClientIdentities {
    /// Load a JSON array of origins and PEM certificate/private-key paths.
    /// Relative paths are resolved against the JSON file's directory.
    ///
    /// # Errors
    ///
    /// Rejects invalid or duplicate origins, unreadable files, and certificates
    /// whose keys are invalid or do not match. Origins must use HTTPS and must
    /// not contain credentials, wildcards, paths, queries, or fragments.
    pub fn load(path: &Path) -> Result<Self, BoxError> {
        let entries: Vec<ClientIdentityFiles> = serde_json::from_slice(&std::fs::read(path)?)?;
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        let provider = rustls::crypto::ring::default_provider();
        let mut identities = HashMap::new();
        for entry in entries {
            let parsed = url::Url::parse(&entry.origin)?;
            if parsed.scheme() != "https"
                || entry.origin.contains('*')
                || parsed.port_or_known_default() == Some(0)
            {
                return Err(BoxError::from_static_str(
                    "mTLS identities require an exact HTTPS origin with a nonzero port",
                ));
            }
            let origin = crate::tcp_backend::canonical_http10_origin(&entry.origin)?;
            if identities.contains_key(&origin) {
                return Err(BoxError::from(format!("duplicate mTLS origin: {origin}")));
            }
            let certificate = directory.join(&entry.certificate);
            let private_key = directory.join(&entry.private_key);
            let chain =
                CertificateDer::pem_file_iter(&certificate)?.collect::<Result<Vec<_>, _>>()?;
            let key = PrivateKeyDer::from_pem_file(&private_key)?;
            let certified = CertifiedKey::from_der(chain, key, &provider)?;
            let resolver: Arc<dyn ResolvesClientCert> = Arc::new(SingleCertAndKey::from(certified));
            identities.insert(origin, resolver);
        }
        Ok(Self { identities })
    }

    pub(crate) fn resolver(
        &self,
        origin: &str,
    ) -> Result<Option<Arc<dyn ResolvesClientCert>>, BoxError> {
        let origin = crate::tcp_backend::canonical_http10_origin(origin)?;
        Ok(self.identities.get(&origin).cloned())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub struct TestIdentity {
        pub directory: tempfile::TempDir,
        pub roots: rustls::RootCertStore,
        pub chain: Vec<CertificateDer<'static>>,
        pub key: PrivateKeyDer<'static>,
    }

    impl TestIdentity {
        pub fn new() -> Self {
            let directory = tempfile::tempdir().expect("TLS files");
            let ca_key = rcgen::KeyPair::generate().expect("CA key");
            let mut params = rcgen::CertificateParams::default();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = params.self_signed(&ca_key).expect("CA");
            let issuer = rcgen::Issuer::from_params(&params, ca_key);
            let key = rcgen::KeyPair::generate().expect("leaf key");
            let mut params =
                rcgen::CertificateParams::new(vec!["localhost".into()]).expect("leaf parameters");
            params.extended_key_usages = vec![
                rcgen::ExtendedKeyUsagePurpose::ServerAuth,
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let leaf = params.signed_by(&key, &issuer).expect("leaf");
            std::fs::write(directory.path().join("ca.pem"), ca.pem()).expect("write CA");
            std::fs::write(directory.path().join("cert.pem"), leaf.pem()).expect("write leaf");
            std::fs::write(directory.path().join("key.pem"), key.serialize_pem())
                .expect("write key");
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.der().clone()).expect("trust CA");
            Self {
                directory,
                roots,
                chain: vec![leaf.der().clone(), ca.der().clone()],
                key: PrivateKeyDer::try_from(key.serialize_der()).expect("private key"),
            }
        }

        pub fn identities(&self, origin: &str) -> Arc<UpstreamClientIdentities> {
            let path = self.directory.path().join("identities.json");
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!([{
                    "origin": origin, "certificate": "cert.pem", "private_key": "key.pem"
                }]))
                .expect("JSON"),
            )
            .expect("write identities");
            Arc::new(UpstreamClientIdentities::load(&path).expect("load identities"))
        }

        pub fn server_config(&self) -> rustls::ServerConfig {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(self.roots.clone()),
                provider.clone(),
            )
            .build()
            .expect("client verifier");
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("TLS versions")
                .with_client_cert_verifier(verifier)
                .with_single_cert(self.chain.clone(), self.key.clone_key())
                .expect("server certificate")
        }
    }

    #[test]
    fn client_identities_are_exact_and_validated() {
        let identity = TestIdentity::new();
        let identities = identity.identities("https://EXAMPLE.test");
        assert!(
            identities
                .resolver("https://example.test:443")
                .expect("origin")
                .is_some()
        );
        for origin in [
            "http://example.test",
            "https://example.test:8443",
            "https://sub.example.test",
            "https://other.test",
        ] {
            assert!(
                identities.resolver(origin).expect("origin").is_none(),
                "{origin}"
            );
        }
        let path = identity.directory.path().join("identities.json");
        for origin in [
            "http://example.test",
            "https://*.example.test",
            "https://example.test/path",
            "https://example.test?query",
            "https://example.test#fragment",
            "https://user:pass@example.test",
            "https://example.test:0",
        ] {
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!([{
                    "origin": origin, "certificate": "cert.pem", "private_key": "key.pem"
                }]))
                .expect("JSON"),
            )
            .expect("write configuration");
            assert!(UpstreamClientIdentities::load(&path).is_err(), "{origin}");
        }
        std::fs::write(
            &path,
            r#"[
            {"origin":"https://example.test", "certificate":"cert.pem", "private_key":"key.pem"},
            {"origin":"https://example.test:443", "certificate":"cert.pem", "private_key":"key.pem"}
        ]"#,
        )
        .expect("write duplicates");
        assert!(UpstreamClientIdentities::load(&path).is_err());
        let _ = identity.identities("https://example.test");
        std::fs::write(
            identity.directory.path().join("key.pem"),
            rcgen::KeyPair::generate()
                .expect("wrong key")
                .serialize_pem(),
        )
        .expect("write wrong key");
        assert!(UpstreamClientIdentities::load(&path).is_err());
    }
}

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use rama_tls_rustls::dep::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rcgen::{CertificateParams, Issuer, KeyPair};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("invalid CA certificate: {0}")]
    Certificate(#[from] rcgen::Error),

    #[error("invalid CA private key: {0}")]
    Key(rcgen::Error),

    #[error("CA certificate PEM does not contain a certificate")]
    MissingCertificate,

    #[error("issued private key is not a supported DER key")]
    IssuedKey,
}

#[derive(Clone)]
pub struct CertificateIssuer {
    ca_issuer: Arc<Issuer<'static, KeyPair>>,
    ca_certificate_der: CertificateDer<'static>,
    cache: Arc<Mutex<HashMap<String, Arc<IssuedCertificate>>>>,
}

#[derive(Clone)]
pub struct IssuedCertificate {
    pub certificate_chain: Vec<CertificateDer<'static>>,
    pub private_key: Arc<PrivateKeyDer<'static>>,
}

impl CertificateIssuer {
    /// Load an interception CA certificate and private key from PEM.
    ///
    /// # Errors
    ///
    /// Returns an error when either PEM input is malformed or the CA
    /// certificate cannot be used for signing.
    pub fn from_pem(
        certificate_pem: &str,
        private_key_pem: &str,
    ) -> Result<Self, CertificateError> {
        let mut certificates = CertificateDer::pem_slice_iter(certificate_pem.as_bytes());

        let ca_certificate_der = certificates
            .next()
            .ok_or(CertificateError::MissingCertificate)?
            .map_err(|_| CertificateError::MissingCertificate)?
            .into_owned();

        let ca_key = KeyPair::from_pem(private_key_pem).map_err(CertificateError::Key)?;
        let ca_issuer = Issuer::from_ca_cert_pem(certificate_pem, ca_key)?;

        Ok(Self {
            ca_issuer: Arc::new(ca_issuer),
            ca_certificate_der,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Issue or retrieve a cached leaf certificate for an SNI name.
    ///
    /// # Errors
    ///
    /// Returns an error when the SNI name cannot be signed with the
    /// configured CA.
    pub fn issue(&self, server_name: &str) -> Result<Arc<IssuedCertificate>, CertificateError> {
        let server_name = normalize_server_name(server_name);

        let cached = self
            .cache
            .lock()
            .map_err(|_| CertificateError::MissingCertificate)?
            .get(&server_name)
            .cloned();

        if let Some(certificate) = cached {
            return Ok(certificate);
        }

        let params = CertificateParams::new(vec![server_name.clone()])?;
        let key_pair = KeyPair::generate()?;
        let certificate = params.signed_by(&key_pair, &self.ca_issuer)?;

        let private_key = PrivateKeyDer::try_from(key_pair.serialize_der())
            .map_err(|_| CertificateError::IssuedKey)?;

        let issued = Arc::new(IssuedCertificate {
            certificate_chain: vec![
                CertificateDer::from(certificate.der().to_vec()),
                self.ca_certificate_der.clone(),
            ],
            private_key: Arc::new(private_key),
        });

        self.cache
            .lock()
            .map_err(|_| CertificateError::MissingCertificate)?
            .insert(server_name, issued.clone());

        Ok(issued)
    }
}

fn normalize_server_name(server_name: &str) -> String {
    server_name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::normalize_server_name;

    #[test]
    fn normalizes_sni_names_for_cache_keys() {
        assert_eq!(normalize_server_name("Example.COM."), "example.com");
    }
}

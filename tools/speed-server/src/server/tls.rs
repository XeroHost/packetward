// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! rustls acceptor from PEM files (HTTP/1.1 only, ring crypto provider).

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use super::ServerError;

/// Load `cert` (PEM chain) and `key` (PEM, PKCS#8/PKCS#1/SEC1) into a TLS acceptor.
pub fn acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor, ServerError> {
    let certs = CertificateDer::pem_file_iter(cert)
        .map_err(|e| ServerError::Tls(format!("{}: {e}", cert.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Tls(format!("{}: {e}", cert.display())))?;
    if certs.is_empty() {
        return Err(ServerError::Tls(format!(
            "{}: no certificate found",
            cert.display()
        )));
    }
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| ServerError::Tls(format!("{}: {e}", key.display())))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ServerError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

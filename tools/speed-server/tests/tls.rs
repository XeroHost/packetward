// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Native TLS termination (`--features tls`). Uses the throwaway self-signed certificate in
//! `tests/fixtures` (EC P-256, CN=localhost, SAN localhost/127.0.0.1, valid 100 years); the key protects
//! nothing and must never be used anywhere else.
#![cfg(feature = "tls")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use pw_speed_server::{start, Config};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(fixture("test-cert.pem")).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn tls_server() -> pw_speed_server::RunningServer {
    let mut c = Config::default();
    c.server.listen = "127.0.0.1:0".parse().unwrap();
    c.tls.cert_file = Some(fixture("test-cert.pem"));
    c.tls.key_file = Some(fixture("test-key.pem"));
    start(c).await.unwrap()
}

async fn https_get(addr: std::net::SocketAddr, path: &str) -> (String, Vec<u8>) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = connector()
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut raw = Vec::new();
    // The server closes without close_notify when it is done; treat that like EOF.
    let _ = tls.read_to_end(&mut raw).await;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header end")
        + 4;
    (
        String::from_utf8_lossy(&raw[..split]).into_owned(),
        raw[split..].to_vec(),
    )
}

#[tokio::test]
async fn serves_info_and_downloads_over_tls() {
    let server = tls_server().await;
    let (head, body) = https_get(server.local_addr(), "/info").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["client_ip"], "127.0.0.1");

    let (head, body) = https_get(server.local_addr(), "/download?bytes=2000000").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body.len(), 2_000_000);
}

#[tokio::test]
async fn plain_http_to_a_tls_port_is_refused() {
    let server = tls_server().await;
    let mut s = TcpStream::connect(server.local_addr()).await.unwrap();
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    assert!(!String::from_utf8_lossy(&buf).contains("200 OK"));
}

#[tokio::test]
async fn bad_certificate_paths_fail_at_start() {
    let mut c = Config::default();
    c.server.listen = "127.0.0.1:0".parse().unwrap();
    c.tls.cert_file = Some(fixture("missing.pem"));
    c.tls.key_file = Some(fixture("test-key.pem"));
    let err = start(c).await.err().expect("must fail");
    assert!(err.to_string().contains("TLS"), "{err}");
}

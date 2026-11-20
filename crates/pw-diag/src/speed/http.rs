// SPDX-License-Identifier: GPL-3.0-or-later
//! The real transport: reqwest over rustls (ring provider, OS certificate verifier), same setup as `pw-intel`'s
//! `http` feature. No OpenSSL.
//!
//! * HTTP/1.1 only: every parallel stream must be its own TCP connection (HTTP/2 would multiplex them all onto one).
//! * The system proxy is honoured, an explicit `proxy` setting overrides it. Loopback servers are never sent through
//!   a proxy.
//! * No overall request timeout (a bin test runs for hours); ping and info have one. A stalled transfer is caught by
//!   the engine's stall watchdog, and dropping a request future closes its connection.
//! * Redirects are not followed.
//! * Errors are reduced to a short text without URLs (`without_url`), so no query string or proxy address leaks.

use std::io;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream;

use super::error::{sanitize_message, TransportError};
use super::providers::{self, CLOUDFLARE_MAX_DOWNLOAD, CLOUDFLARE_MAX_UPLOAD};
use super::server::{ServerEndpoint, ServerInfo, ServerKind};
use super::transport::{ByteMeter, DownloadRequest, SpeedTransport, UploadRequest};

/// Size of the reusable upload buffer; the body is sent as slices of it (no per-chunk allocation).
const UPLOAD_BUFFER: usize = 256 * 1024;
/// `/info` and error bodies are small; refuse anything larger.
const SMALL_BODY_LIMIT: usize = 64 * 1024;

/// Settings of the real transport.
#[derive(Debug, Clone)]
pub struct HttpTransportConfig {
    /// Explicit proxy URL from the app settings (`http://`, `https://`, `socks5://`); `None` = system proxy.
    pub proxy: Option<String>,
    /// Basic-auth credentials for the explicit proxy (never part of the URL). Ignored without `proxy`.
    pub proxy_auth: Option<pw_core::ProxyAuth>,
    /// Ignore every proxy (system and explicit). Used by the loopback integration test.
    pub no_proxy: bool,
    /// Sent as `User-Agent`: product and version only.
    pub user_agent: String,
    /// TCP + TLS connect timeout.
    pub connect_timeout: Duration,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            proxy: None,
            proxy_auth: None,
            no_proxy: false,
            user_agent: concat!("PacketWard/", env!("CARGO_PKG_VERSION")).to_owned(),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// The reqwest-based [`SpeedTransport`].
#[derive(Debug, Clone)]
pub struct HttpTransport {
    /// Honours the proxy settings.
    client: reqwest::Client,
    /// Never uses a proxy; for loopback servers.
    direct: reqwest::Client,
    upload_buffer: Bytes,
}

/// reqwest is built with `rustls-no-provider`; install the `ring` provider once. If something else already
/// installed a default provider, that one is used.
fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            tracing::debug!("a rustls crypto provider was already installed; using it");
        }
    });
}

impl HttpTransport {
    /// Build the clients. Fails only on an invalid proxy URL or a TLS setup problem.
    pub fn new(config: &HttpTransportConfig) -> Result<Self, TransportError> {
        ensure_crypto_provider();
        let base = || {
            reqwest::Client::builder()
                .user_agent(config.user_agent.clone())
                .connect_timeout(config.connect_timeout)
                .http1_only()
                .tcp_nodelay(true)
                .redirect(reqwest::redirect::Policy::none())
        };
        let build = |builder: reqwest::ClientBuilder| {
            builder
                .build()
                .map_err(|e| TransportError::Connect(e.without_url().to_string()))
        };
        let mut proxied = base();
        if config.no_proxy {
            proxied = proxied.no_proxy();
        } else if let Some(proxy) = &config.proxy {
            let mut proxy = reqwest::Proxy::all(proxy)
                .map_err(|_| TransportError::Protocol("invalid proxy URL".to_owned()))?;
            if let Some(auth) = &config.proxy_auth {
                proxy = proxy.basic_auth(auth.username(), auth.password());
            }
            proxied = proxied.proxy(proxy);
        }
        let client = build(proxied)?;
        let direct = build(base().no_proxy())?;
        Ok(Self {
            client,
            direct,
            upload_buffer: make_buffer(),
        })
    }

    fn client_for(&self, server: &ServerEndpoint) -> &reqwest::Client {
        if server.is_loopback() {
            &self.direct
        } else {
            &self.client
        }
    }
}

/// Pseudo-random bytes (xorshift64*), generated once; the content is irrelevant to the server.
fn make_buffer() -> Bytes {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut buffer = Vec::with_capacity(UPLOAD_BUFFER);
    while buffer.len() < UPLOAD_BUFFER {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let word = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        buffer.extend_from_slice(&word.to_le_bytes());
    }
    buffer.truncate(UPLOAD_BUFFER);
    Bytes::from(buffer)
}

fn map_error(error: reqwest::Error) -> TransportError {
    let (timeout, connect) = (error.is_timeout(), error.is_connect());
    // `without_url` keeps query strings (the test id) and proxy addresses out of the text.
    let text = error.without_url().to_string();
    if timeout {
        TransportError::Timeout
    } else if connect {
        TransportError::Connect(text)
    } else {
        TransportError::Io(text)
    }
}

/// Turn a non-2xx response into [`TransportError::Status`], reading a small JSON error body if there is one.
async fn status_error(mut response: reqwest::Response) -> TransportError {
    let status = response.status().as_u16();
    let retry_after_secs = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    let mut body = Vec::new();
    while body.len() < 4096 {
        match response.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            _ => break,
        }
    }
    let message = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .and_then(|m| m.as_str())
                .map(sanitize_message)
        })
        .filter(|m| !m.is_empty());
    TransportError::Status {
        status,
        retry_after_secs,
        message,
    }
}

async fn read_small(mut response: reqwest::Response) -> Result<Vec<u8>, TransportError> {
    if response
        .content_length()
        .is_some_and(|l| l > SMALL_BODY_LIMIT as u64)
    {
        return Err(TransportError::Protocol("response too large".to_owned()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_error)? {
        if body.len() + chunk.len() > SMALL_BODY_LIMIT {
            return Err(TransportError::Protocol("response too large".to_owned()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// What a static mirror tells without any request: its name, place and the size of its largest file.
fn mirror_info(server: &ServerEndpoint) -> ServerInfo {
    let builtin = providers::builtin_of(server);
    ServerInfo {
        node_id: server.id.clone(),
        node_name: server.name.clone(),
        location: builtin.map(|b| b.location.to_owned()).unwrap_or_default(),
        max_download_bytes: server.max_request_bytes().unwrap_or(0),
        ..ServerInfo::default()
    }
}

/// Cloudflare's `/cdn-cgi/trace` is plain `key=value` lines: the client address (`ip`), the data center (`colo`)
/// and the country (`loc`).
fn cloudflare_info(trace: &str) -> ServerInfo {
    let field = |key: &str| {
        trace
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .map(|v| sanitize_message(v.trim()))
            .unwrap_or_default()
    };
    let colo = field("colo");
    let country = field("loc");
    let place = match (colo.is_empty(), country.is_empty()) {
        (false, false) => format!("{colo}, {country}"),
        (false, true) => colo.clone(),
        (true, false) => country,
        (true, true) => String::new(),
    };
    ServerInfo {
        node_id: colo,
        node_name: "Cloudflare".to_owned(),
        location: place,
        client_ip: field("ip"),
        max_download_bytes: CLOUDFLARE_MAX_DOWNLOAD,
        max_upload_bytes: CLOUDFLARE_MAX_UPLOAD,
        ..ServerInfo::default()
    }
}

impl SpeedTransport for HttpTransport {
    async fn ping(
        &self,
        server: &ServerEndpoint,
        timeout: Duration,
    ) -> Result<Duration, TransportError> {
        let started = Instant::now();
        let request = match server.kind {
            ServerKind::Native => self.client_for(server).get(server.url("/ping")),
            // A zero-byte download: the cheapest round trip the endpoint offers.
            ServerKind::Cloudflare => self.client_for(server).get(server.url("/__down?bytes=0")),
            // The first byte of the smallest file.
            ServerKind::Mirror => {
                let file = providers::pick_mirror_file(providers::mirror_files(server), 1)
                    .ok_or_else(|| TransportError::Protocol("mirror without files".to_owned()))?;
                self.client_for(server)
                    .get(server.url(file.path))
                    .header(reqwest::header::RANGE, "bytes=0-0")
            }
        };
        let response = request.timeout(timeout).send().await.map_err(map_error)?;
        if !response.status().is_success() {
            return Err(status_error(response).await);
        }
        read_small(response).await?;
        Ok(started.elapsed())
    }

    async fn info(
        &self,
        server: &ServerEndpoint,
        timeout: Duration,
    ) -> Result<ServerInfo, TransportError> {
        match server.kind {
            ServerKind::Native => {}
            ServerKind::Mirror => return Ok(mirror_info(server)),
            ServerKind::Cloudflare => {
                // The trace only adds the client address and the place. The size limits matter more
                // (without them a request could exceed what Cloudflare answers), so they are given even
                // when the trace cannot be read.
                let trace = async {
                    let response = self
                        .client_for(server)
                        .get(server.url("/cdn-cgi/trace"))
                        .timeout(timeout)
                        .send()
                        .await
                        .map_err(map_error)?;
                    if !response.status().is_success() {
                        return Err(status_error(response).await);
                    }
                    read_small(response).await
                };
                let body = trace.await.unwrap_or_default();
                return Ok(cloudflare_info(&String::from_utf8_lossy(&body)));
            }
        }
        let response = self
            .client_for(server)
            .get(server.url("/info"))
            .timeout(timeout)
            .send()
            .await
            .map_err(map_error)?;
        if !response.status().is_success() {
            return Err(status_error(response).await);
        }
        let body = read_small(response).await?;
        serde_json::from_slice(&body).map_err(|_| {
            TransportError::Protocol("/info is not a speed-server document".to_owned())
        })
    }

    async fn download(
        &self,
        server: &ServerEndpoint,
        request: &DownloadRequest<'_>,
        meter: &ByteMeter,
    ) -> Result<u64, TransportError> {
        let builder = match server.kind {
            ServerKind::Native => self.client_for(server).get(server.url(&format!(
                "/download?bytes={}&test={}",
                request.bytes, request.test_id
            ))),
            ServerKind::Cloudflare => {
                if request.bytes > CLOUDFLARE_MAX_DOWNLOAD {
                    return Err(TransportError::Protocol(
                        "request larger than this provider answers".to_owned(),
                    ));
                }
                self.client_for(server)
                    .get(server.url(&format!("/__down?bytes={}", request.bytes)))
            }
            ServerKind::Mirror => {
                let file =
                    providers::pick_mirror_file(providers::mirror_files(server), request.bytes)
                        .ok_or_else(|| {
                            TransportError::Protocol("mirror without files".to_owned())
                        })?;
                let wanted = request.bytes.min(file.bytes).max(1);
                self.client_for(server)
                    .get(server.url(file.path))
                    .header(reqwest::header::RANGE, format!("bytes=0-{}", wanted - 1))
            }
        };
        // A mirror that ignores `Range` answers 200 with the whole file: stop after the bytes asked for.
        let limit = (server.kind == ServerKind::Mirror).then_some(request.bytes);
        let mut response = builder.send().await.map_err(map_error)?;
        if !response.status().is_success() {
            return Err(status_error(response).await);
        }
        let mut received = 0u64;
        // The data goes nowhere: counted, then dropped.
        while let Some(chunk) = response.chunk().await.map_err(map_error)? {
            let mut n = chunk.len() as u64;
            if let Some(limit) = limit {
                n = n.min(limit - received);
            }
            received += n;
            meter.add(n);
            if limit.is_some_and(|l| received >= l) {
                break;
            }
        }
        Ok(received)
    }

    async fn upload(
        &self,
        server: &ServerEndpoint,
        request: &UploadRequest<'_>,
        meter: &ByteMeter,
    ) -> Result<u64, TransportError> {
        let url = match server.kind {
            ServerKind::Native => server.url(&format!("/upload?test={}", request.test_id)),
            ServerKind::Cloudflare => {
                if request.bytes > CLOUDFLARE_MAX_UPLOAD {
                    return Err(TransportError::Protocol(
                        "upload larger than this provider takes".to_owned(),
                    ));
                }
                server.url("/__up")
            }
            ServerKind::Mirror => {
                return Err(TransportError::Protocol(
                    "this provider does not take uploads".to_owned(),
                ))
            }
        };
        let buffer = self.upload_buffer.clone();
        let meter = meter.clone();
        let body = stream::unfold(request.bytes, move |left| {
            let buffer = buffer.clone();
            let meter = meter.clone();
            async move {
                if left == 0 {
                    return None;
                }
                let n = left.min(buffer.len() as u64);
                meter.add(n);
                // `n` <= buffer length, so this never truncates.
                let chunk = buffer.slice(..n as usize);
                Some((Ok::<Bytes, io::Error>(chunk), left - n))
            }
        });
        let response = self
            .client_for(server)
            .post(url)
            .header(reqwest::header::CONTENT_LENGTH, request.bytes)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(reqwest::Body::wrap_stream(body))
            .send()
            .await
            .map_err(map_error)?;
        if !response.status().is_success() {
            return Err(status_error(response).await);
        }
        let body = read_small(response).await?;
        if server.kind == ServerKind::Cloudflare {
            // Its answer carries no byte count: a 2xx means the whole body was taken.
            return Ok(request.bytes);
        }
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| TransportError::Protocol("/upload answer is not JSON".to_owned()))?;
        value
            .get("bytes")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| TransportError::Protocol("/upload answer has no byte count".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_without_a_network() {
        assert!(HttpTransport::new(&HttpTransportConfig::default()).is_ok());
    }

    #[test]
    fn a_bad_explicit_proxy_is_rejected_and_a_good_one_accepted() {
        let good = HttpTransportConfig {
            proxy: Some("http://proxy.invalid:3128".to_owned()),
            ..HttpTransportConfig::default()
        };
        assert!(HttpTransport::new(&good).is_ok());
        let bad = HttpTransportConfig {
            proxy: Some("not a url".to_owned()),
            ..HttpTransportConfig::default()
        };
        let error = HttpTransport::new(&bad).unwrap_err();
        assert!(!error.to_string().contains("not a url"));
    }

    #[test]
    fn a_proxy_with_credentials_builds_without_a_network_and_never_shows_them() {
        let config = HttpTransportConfig {
            proxy: Some("http://proxy.invalid:3128".to_owned()),
            proxy_auth: Some(pw_core::ProxyAuth::new("alice", "hunter2")),
            ..HttpTransportConfig::default()
        };
        assert!(HttpTransport::new(&config).is_ok());
        let debug = format!("{config:?}");
        assert!(!debug.contains("alice") && !debug.contains("hunter2"));
        // The credentials are ignored (not an error) when there is no explicit proxy.
        let no_proxy = HttpTransportConfig {
            proxy_auth: config.proxy_auth.clone(),
            ..HttpTransportConfig::default()
        };
        assert!(HttpTransport::new(&no_proxy).is_ok());
    }

    #[test]
    fn the_cloudflare_trace_gives_the_address_and_the_place() {
        let info =
            cloudflare_info("fl=1\nh=speed.cloudflare.com\nip=203.0.113.7\ncolo=MIA\nloc=US\n");
        assert_eq!(info.client_ip, "203.0.113.7");
        assert_eq!(info.location, "MIA, US");
        assert_eq!(info.max_download_bytes, CLOUDFLARE_MAX_DOWNLOAD);
        assert_eq!(cloudflare_info("").location, "");
    }

    #[test]
    fn a_mirror_describes_itself_without_a_request() {
        let server = &providers::builtin_servers(Some("ovh"))[0];
        let info = mirror_info(server);
        assert_eq!(info.location, "Gravelines, FR");
        assert_eq!(info.max_download_bytes, 1 << 30);
    }

    /// Talks to the real public providers with a few megabytes each. Run on purpose:
    /// `cargo test -p pw-diag --features speed --lib live_public_providers -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "uses the public internet"]
    async fn live_public_providers() {
        let transport = HttpTransport::new(&HttpTransportConfig::default()).unwrap();
        for group in providers::GROUPS {
            let server = providers::builtin_servers(Some(group)).remove(0);
            let rtt = transport.ping(&server, Duration::from_secs(8)).await;
            let info = transport
                .info(&server, Duration::from_secs(8))
                .await
                .unwrap();
            let meter = ByteMeter::new();
            let wanted = 4 << 20;
            let got = transport
                .download(
                    &server,
                    &DownloadRequest {
                        bytes: wanted,
                        test_id: "t",
                    },
                    &meter,
                )
                .await;
            println!(
                "{group}: ping {rtt:?}, place {:?}, ip {:?}, download {got:?}",
                info.location, info.client_ip
            );
            assert_eq!(
                got.unwrap(),
                wanted,
                "{group} must return exactly the bytes asked"
            );
            assert_eq!(meter.total(), wanted);
            if server.supports_upload() {
                let sent = transport
                    .upload(
                        &server,
                        &UploadRequest {
                            bytes: 2 << 20,
                            test_id: "t",
                        },
                        &meter,
                    )
                    .await;
                println!("{group}: upload {sent:?}");
                assert_eq!(sent.unwrap(), 2 << 20);
            } else {
                let refused = transport
                    .upload(
                        &server,
                        &UploadRequest {
                            bytes: 1,
                            test_id: "t",
                        },
                        &meter,
                    )
                    .await;
                assert!(refused.is_err(), "a mirror takes no uploads");
            }
        }
    }

    #[test]
    fn the_upload_buffer_is_not_a_constant_and_has_the_expected_size() {
        let buffer = make_buffer();
        assert_eq!(buffer.len(), UPLOAD_BUFFER);
        assert!(buffer.windows(8).any(|w| w != &buffer[..8]));
    }
}

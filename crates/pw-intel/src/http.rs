// SPDX-License-Identifier: GPL-3.0-or-later
//! The real HTTPS fetcher: reqwest over rustls (ring provider, OS certificate verifier). No OpenSSL.
//!
//! Proxy: the system proxy settings are honoured by default; `HttpFetcherConfig::proxy` overrides them with an
//! explicit URL (`http://`, `https://` or `socks5://`) taken from the app settings, so the proxy setting applies to
//! every request made through this crate.

use std::time::Duration;

use crate::fetch::{FetchError, FetchRequest, FetchResponse, Fetcher, HttpMethod};

#[derive(Debug, Clone)]
pub struct HttpFetcherConfig {
    /// Explicit proxy URL from the settings; `None` uses the system proxy configuration.
    pub proxy: Option<String>,
    /// Basic-auth credentials for the explicit proxy (never part of the URL). Ignored without `proxy`.
    pub proxy_auth: Option<pw_core::ProxyAuth>,
    /// Sent as `User-Agent`. Generic on purpose: product and version only.
    pub user_agent: String,
    pub connect_timeout: Duration,
}

impl Default for HttpFetcherConfig {
    fn default() -> Self {
        Self {
            proxy: None,
            proxy_auth: None,
            user_agent: concat!("PacketWard/", env!("CARGO_PKG_VERSION")).to_owned(),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpFetcher {
    client: reqwest::Client,
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

impl HttpFetcher {
    pub fn new(config: &HttpFetcherConfig) -> Result<Self, FetchError> {
        ensure_crypto_provider();
        let mut builder = reqwest::Client::builder()
            .user_agent(config.user_agent.clone())
            .connect_timeout(config.connect_timeout)
            .https_only(true);
        if let Some(proxy) = &config.proxy {
            let mut proxy = reqwest::Proxy::all(proxy)
                .map_err(|_| FetchError::InvalidUrl("invalid proxy URL".to_owned()))?;
            if let Some(auth) = &config.proxy_auth {
                proxy = proxy.basic_auth(auth.username(), auth.password());
            }
            builder = builder.proxy(proxy);
        }
        let client = builder
            .build()
            .map_err(|e| FetchError::Network(e.without_url().to_string()))?;
        Ok(Self { client })
    }
}

fn map_error(error: reqwest::Error) -> FetchError {
    if error.is_timeout() {
        FetchError::Timeout
    } else {
        // `without_url` keeps query strings (an IP being looked up) out of error text.
        FetchError::Network(error.without_url().to_string())
    }
}

impl Fetcher for HttpFetcher {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        if !request.url.to_ascii_lowercase().starts_with("https://") {
            return Err(FetchError::InsecureUrl);
        }
        let mut builder = match request.method {
            HttpMethod::Get => self.client.get(&request.url),
            HttpMethod::Post => self.client.post(&request.url),
        };
        builder = builder.timeout(request.timeout);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let mut response = builder.send().await.map_err(map_error)?;
        let limit = request.max_bytes;
        if let Some(length) = response.content_length() {
            if usize::try_from(length).map_or(true, |l| l > limit) {
                return Err(FetchError::TooLarge { limit });
            }
        }
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_ascii_lowercase(), v.to_owned()))
            })
            .collect();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_error)? {
            if body.len().saturating_add(chunk.len()) > limit {
                // Dropping `response` aborts the transfer.
                return Err(FetchError::TooLarge { limit });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(FetchResponse {
            status,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_without_a_network_and_refuses_plain_http() {
        let fetcher = HttpFetcher::new(&HttpFetcherConfig::default()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result =
            runtime.block_on(fetcher.fetch(FetchRequest::get("http://example.invalid/x", 10)));
        assert_eq!(result, Err(FetchError::InsecureUrl));
    }

    #[test]
    fn an_explicit_proxy_is_accepted_and_a_bad_one_rejected() {
        let ok = HttpFetcherConfig {
            proxy: Some("http://proxy.invalid:3128".to_owned()),
            ..HttpFetcherConfig::default()
        };
        assert!(HttpFetcher::new(&ok).is_ok());
        let with_credentials = HttpFetcherConfig {
            proxy: Some("http://proxy.invalid:3128".to_owned()),
            proxy_auth: Some(pw_core::ProxyAuth::new("alice", "hunter2")),
            ..HttpFetcherConfig::default()
        };
        assert!(HttpFetcher::new(&with_credentials).is_ok());
        let debug = format!("{with_credentials:?}");
        assert!(!debug.contains("alice") && !debug.contains("hunter2"));
        let socks = HttpFetcherConfig {
            proxy: Some("socks5://proxy.invalid:1080".to_owned()),
            ..HttpFetcherConfig::default()
        };
        assert!(HttpFetcher::new(&socks).is_ok());
        let bad = HttpFetcherConfig {
            proxy: Some("not a url".to_owned()),
            ..HttpFetcherConfig::default()
        };
        assert!(HttpFetcher::new(&bad).is_err());
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! HTTP behind a trait, so no test (and no pure logic) ever touches the network.

use std::future::Future;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// One outbound request. `max_bytes` is enforced *while reading* the body (the transfer is aborted), not after.
#[derive(Clone)]
pub struct FetchRequest {
    pub method: HttpMethod,
    pub url: String,
    /// Header names and values. Values may carry credentials, so `Debug` never prints them.
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub max_bytes: usize,
    pub timeout: Duration,
}

impl FetchRequest {
    /// Default timeout for every request.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn get(url: impl Into<String>, max_bytes: usize) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            max_bytes,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    pub fn post(url: impl Into<String>, body: Vec<u8>, max_bytes: usize) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: Vec::new(),
            body: Some(body),
            max_bytes,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// First header value with that name (case-insensitive).
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl std::fmt::Debug for FetchRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Header values and the body are deliberately omitted: they can hold an API key.
        f.debug_struct("FetchRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field(
                "header_names",
                &self
                    .headers
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.as_ref().map(Vec::len))
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResponse {
    pub status: u16,
    /// Header names are lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FetchResponse {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), value.to_owned()));
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// Only `https://` is ever requested.
    #[error("refusing a non-HTTPS URL")]
    InsecureUrl,
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("the response exceeds the {limit}-byte limit")]
    TooLarge { limit: usize },
    #[error("request timed out")]
    Timeout,
    /// Connection, TLS or protocol failure. The message never contains request headers.
    #[error("network error: {0}")]
    Network(String),
}

/// Performs one HTTP request. Implemented by `HttpFetcher` (reqwest) and by the fakes in tests.
///
/// Not object-safe on purpose (`impl Future`); consumers are generic over `F: Fetcher`.
pub trait Fetcher: Send + Sync {
    fn fetch(
        &self,
        request: FetchRequest,
    ) -> impl Future<Output = Result<FetchResponse, FetchError>> + Send;
}

impl<T: Fetcher + ?Sized> Fetcher for std::sync::Arc<T> {
    fn fetch(
        &self,
        request: FetchRequest,
    ) -> impl Future<Output = Result<FetchResponse, FetchError>> + Send {
        (**self).fetch(request)
    }
}

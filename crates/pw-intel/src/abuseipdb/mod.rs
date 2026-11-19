// SPDX-License-Identifier: GPL-3.0-or-later
//! AbuseIPDB client: the `check` endpoint (only when the user stored a key) and an explicit manual `report`.
//!
//! * The key comes from a [`SecretStore`] on every call, is placed only in the `Key` header and is never logged.
//! * Private, loopback and other reserved addresses are never sent anywhere ([`AbuseError::NotPublic`]).
//! * Results are cached (default 24 h) through the [`AbuseCache`] trait.
//! * Rate limits: `X-RateLimit-Remaining`/`Retry-After`/`X-RateLimit-Reset` are honoured; an exhausted quota or a
//!   `429` pauses the client without any network request until the deadline, with exponential backoff on repeats.
//! * [`AbuseIpdbClient::report`] is **only ever called by an explicit user action**. Nothing in this crate calls it.

mod cache;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

pub use cache::{AbuseCache, CachedAbuse, MemoryAbuseCache};

use crate::net::is_public_ip;
use crate::secret::ABUSEIPDB_KEY_NAME;
use crate::{
    Clock, FetchError, FetchRequest, FetchResponse, Fetcher, SecretError, SecretStore, UnixSecs,
};

pub const CHECK_URL: &str = "https://api.abuseipdb.com/api/v2/check";
pub const REPORT_URL: &str = "https://api.abuseipdb.com/api/v2/report";
/// Default cache lifetime: 24 hours.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 24 * 3600;
pub const DEFAULT_MAX_AGE_DAYS: u16 = 90;
/// Responses are a few hundred bytes.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_COMMENT_CHARS: usize = 1024;
const MAX_CATEGORIES: usize = 10;
const BACKOFF_BASE_SECS: u64 = 60;
const BACKOFF_CAP_SECS: u64 = 3600;
/// Never wait longer than a day because of a header value.
const MAX_WAIT_SECS: u64 = 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbuseConfig {
    pub cache_ttl_secs: u64,
    pub max_age_days: u16,
}

impl Default for AbuseConfig {
    fn default() -> Self {
        Self {
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            max_age_days: DEFAULT_MAX_AGE_DAYS,
        }
    }
}

/// The fields of AbuseIPDB's `check` response that PacketWard shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseReport {
    pub ip: Option<IpAddr>,
    /// 0 – 100.
    pub abuse_confidence_score: u8,
    pub country_code: Option<String>,
    pub usage_type: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    pub total_reports: u32,
    pub num_distinct_users: u32,
    /// RFC 3339 text as sent by the service.
    pub last_reported_at: Option<String>,
    pub is_whitelisted: Option<bool>,
    pub is_tor: Option<bool>,
}

/// One answer to [`AbuseIpdbClient::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseCheck {
    pub report: AbuseReport,
    pub fetched_at: UnixSecs,
    /// `true` when served from the cache without a request.
    pub from_cache: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseState {
    /// No key stored: the UI shows "not configured".
    NotConfigured,
    Ready,
    /// Paused until `until` (quota exhausted or HTTP 429).
    RateLimited {
        until: UnixSecs,
    },
}

/// Quota information from the last response headers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateLimitInfo {
    pub limit: Option<u32>,
    pub remaining: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum AbuseError {
    #[error("AbuseIPDB is not configured (no API key stored)")]
    NotConfigured,
    /// The address is private, loopback or otherwise reserved and is never sent to an external service.
    #[error("not a public IP address; it is never sent to an external service")]
    NotPublic,
    #[error("AbuseIPDB rate limit reached; paused until {until}")]
    RateLimited { until: UnixSecs },
    #[error("AbuseIPDB rejected the API key")]
    InvalidKey,
    #[error("AbuseIPDB rejected the request (HTTP {0})")]
    Rejected(u16),
    #[error("AbuseIPDB answered HTTP {0}")]
    Server(u16),
    #[error("request failed: {0}")]
    Fetch(#[from] FetchError),
    #[error("unexpected response from AbuseIPDB: {0}")]
    BadResponse(String),
    #[error(transparent)]
    Secret(#[from] SecretError),
    #[error("invalid report: {0}")]
    InvalidReport(&'static str),
}

/// A report the user composed and confirmed in the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualReport {
    pub ip: IpAddr,
    /// AbuseIPDB category ids (1–23), at most 10.
    pub categories: Vec<u8>,
    /// Up to 1024 characters. Must not contain personal data; the UI says so.
    pub comment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportAck {
    pub abuse_confidence_score: u8,
}

#[derive(Default)]
struct Limiter {
    blocked_until: UnixSecs,
    consecutive_429: u32,
    info: RateLimitInfo,
}

pub struct AbuseIpdbClient<F: Fetcher> {
    fetcher: F,
    secrets: Arc<dyn SecretStore>,
    cache: Arc<dyn AbuseCache>,
    clock: Arc<dyn Clock>,
    config: AbuseConfig,
    limiter: Mutex<Limiter>,
}

// A manual Debug so that no field (least of all anything key-related) can be printed by accident.
impl<F: Fetcher> std::fmt::Debug for AbuseIpdbClient<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AbuseIpdbClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn backoff_secs(consecutive: u32) -> u64 {
    let exponent = consecutive.saturating_sub(1).min(16);
    BACKOFF_BASE_SECS
        .saturating_mul(1u64 << exponent)
        .min(BACKOFF_CAP_SECS)
}

/// Seconds until the next UTC midnight, when AbuseIPDB's daily quota resets.
fn secs_until_utc_midnight(now: UnixSecs) -> u64 {
    86_400 - now % 86_400
}

fn header_u64(response: &FetchResponse, name: &str) -> Option<u64> {
    response.header(name)?.trim().parse().ok()
}

/// Percent-encode for an `application/x-www-form-urlencoded` body.
fn form_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCheck {
    #[serde(default)]
    ip_address: Option<IpAddr>,
    #[serde(default)]
    abuse_confidence_score: u64,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    usage_type: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    total_reports: u64,
    #[serde(default)]
    num_distinct_users: u64,
    #[serde(default)]
    last_reported_at: Option<String>,
    #[serde(default)]
    is_whitelisted: Option<bool>,
    #[serde(default)]
    is_tor: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawReportAck {
    #[serde(default)]
    abuse_confidence_score: u64,
}

fn saturating_u8(value: u64) -> u8 {
    u8::try_from(value.min(100)).unwrap_or(100)
}

fn saturating_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

impl From<RawCheck> for AbuseReport {
    fn from(raw: RawCheck) -> Self {
        Self {
            ip: raw.ip_address,
            abuse_confidence_score: saturating_u8(raw.abuse_confidence_score),
            country_code: raw.country_code,
            usage_type: raw.usage_type,
            isp: raw.isp,
            domain: raw.domain,
            total_reports: saturating_u32(raw.total_reports),
            num_distinct_users: saturating_u32(raw.num_distinct_users),
            last_reported_at: raw.last_reported_at,
            is_whitelisted: raw.is_whitelisted,
            is_tor: raw.is_tor,
        }
    }
}

impl<F: Fetcher> AbuseIpdbClient<F> {
    pub fn new(
        fetcher: F,
        secrets: Arc<dyn SecretStore>,
        cache: Arc<dyn AbuseCache>,
        clock: Arc<dyn Clock>,
        config: AbuseConfig,
    ) -> Self {
        Self {
            fetcher,
            secrets,
            cache,
            clock,
            config,
            limiter: Mutex::new(Limiter::default()),
        }
    }

    fn limiter(&self) -> std::sync::MutexGuard<'_, Limiter> {
        self.limiter.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn key(&self) -> Result<crate::Secret, AbuseError> {
        match self.secrets.get(ABUSEIPDB_KEY_NAME)? {
            Some(secret) if !secret.is_empty() => Ok(secret),
            _ => Err(AbuseError::NotConfigured),
        }
    }

    /// Whether lookups are possible right now. Makes no request.
    pub fn state(&self) -> Result<AbuseState, AbuseError> {
        match self.key() {
            Err(AbuseError::NotConfigured) => return Ok(AbuseState::NotConfigured),
            Err(other) => return Err(other),
            Ok(_) => {}
        }
        let now = self.clock.now();
        let blocked_until = self.limiter().blocked_until;
        if now < blocked_until {
            return Ok(AbuseState::RateLimited {
                until: blocked_until,
            });
        }
        Ok(AbuseState::Ready)
    }

    /// Quota seen in the most recent response, for display.
    pub fn rate_limit(&self) -> RateLimitInfo {
        self.limiter().info
    }

    fn ensure_not_blocked(&self, now: UnixSecs) -> Result<(), AbuseError> {
        let blocked_until = self.limiter().blocked_until;
        if now < blocked_until {
            return Err(AbuseError::RateLimited {
                until: blocked_until,
            });
        }
        Ok(())
    }

    /// Record rate-limit headers; pause when the quota is exhausted.
    fn observe(&self, response: &FetchResponse, now: UnixSecs) {
        let mut limiter = self.limiter();
        limiter.info = RateLimitInfo {
            limit: header_u64(response, "x-ratelimit-limit").and_then(|v| u32::try_from(v).ok()),
            remaining: header_u64(response, "x-ratelimit-remaining")
                .and_then(|v| u32::try_from(v).ok()),
        };
        if response.is_success() {
            limiter.consecutive_429 = 0;
            if limiter.info.remaining == Some(0) {
                // `X-RateLimit-Reset` is an epoch timestamp or a delay in seconds; without it the daily quota
                // resets at the next UTC midnight.
                let wait = match header_u64(response, "x-ratelimit-reset") {
                    Some(reset) if reset > 1_000_000_000 => reset.saturating_sub(now),
                    Some(delay) => delay,
                    None => secs_until_utc_midnight(now),
                }
                .clamp(1, MAX_WAIT_SECS);
                limiter.blocked_until = now.saturating_add(wait);
                tracing::info!(
                    wait_secs = wait,
                    "AbuseIPDB quota exhausted; pausing lookups"
                );
            }
        }
    }

    /// Turn a non-success response into an error, updating the limiter for `429`.
    fn failure(&self, response: &FetchResponse, now: UnixSecs) -> AbuseError {
        match response.status {
            429 => {
                let mut limiter = self.limiter();
                limiter.consecutive_429 = limiter.consecutive_429.saturating_add(1);
                let wait = header_u64(response, "retry-after")
                    .unwrap_or_else(|| backoff_secs(limiter.consecutive_429))
                    .clamp(1, MAX_WAIT_SECS);
                limiter.blocked_until = now.saturating_add(wait);
                tracing::warn!(wait_secs = wait, "AbuseIPDB answered 429; backing off");
                AbuseError::RateLimited {
                    until: limiter.blocked_until,
                }
            }
            401 | 403 => AbuseError::InvalidKey,
            400 | 402 | 404 | 422 => AbuseError::Rejected(response.status),
            other => AbuseError::Server(other),
        }
    }

    /// Reputation of `ip`: cached if fresh, otherwise one `check` request.
    pub async fn check(&self, ip: IpAddr) -> Result<AbuseCheck, AbuseError> {
        let ip = ip.to_canonical();
        if !is_public_ip(ip) {
            return Err(AbuseError::NotPublic);
        }
        let key = self.key()?;
        let now = self.clock.now();
        if let Some(cached) = self.cache.get(ip) {
            // A timestamp in the future (clock set back) is treated as stale.
            let age = now.checked_sub(cached.fetched_at);
            if age.is_some_and(|age| age < self.config.cache_ttl_secs) {
                return Ok(AbuseCheck {
                    report: cached.report,
                    fetched_at: cached.fetched_at,
                    from_cache: true,
                });
            }
        }
        self.ensure_not_blocked(now)?;

        let url = format!(
            "{CHECK_URL}?ipAddress={ip}&maxAgeInDays={}",
            self.config.max_age_days
        );
        let request = FetchRequest::get(url, MAX_RESPONSE_BYTES)
            .header("Key", key.expose())
            .header("Accept", "application/json");
        let response = self.fetcher.fetch(request).await?;
        self.observe(&response, now);
        if !response.is_success() {
            return Err(self.failure(&response, now));
        }
        let envelope: Envelope<RawCheck> = serde_json::from_slice(&response.body)
            .map_err(|e| AbuseError::BadResponse(e.to_string()))?;
        let mut report = AbuseReport::from(envelope.data);
        report.ip.get_or_insert(ip);
        self.cache.put(
            ip,
            CachedAbuse {
                report: report.clone(),
                fetched_at: now,
            },
        );
        Ok(AbuseCheck {
            report,
            fetched_at: now,
            from_cache: false,
        })
    }

    /// Submit a report to AbuseIPDB. **Manual only**: call this from an explicit, confirmed user action, never from
    /// detection or the Guardian. Reserved addresses are refused, and the cached result for the address is dropped.
    pub async fn report(&self, report: &ManualReport) -> Result<ReportAck, AbuseError> {
        let ip = report.ip.to_canonical();
        if !is_public_ip(ip) {
            return Err(AbuseError::NotPublic);
        }
        if report.categories.is_empty() {
            return Err(AbuseError::InvalidReport(
                "at least one category is required",
            ));
        }
        if report.categories.len() > MAX_CATEGORIES {
            return Err(AbuseError::InvalidReport("too many categories"));
        }
        if report.categories.iter().any(|c| !(1..=23).contains(c)) {
            return Err(AbuseError::InvalidReport(
                "category must be between 1 and 23",
            ));
        }
        if report.comment.chars().count() > MAX_COMMENT_CHARS {
            return Err(AbuseError::InvalidReport(
                "comment is longer than 1024 characters",
            ));
        }
        let key = self.key()?;
        let now = self.clock.now();
        self.ensure_not_blocked(now)?;

        let categories = report
            .categories
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let body = format!(
            "ip={}&categories={}&comment={}",
            form_encode(&ip.to_string()),
            form_encode(&categories),
            form_encode(&report.comment)
        );
        let request = FetchRequest::post(REPORT_URL, body.into_bytes(), MAX_RESPONSE_BYTES)
            .header("Key", key.expose())
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded");
        let response = self.fetcher.fetch(request).await?;
        self.observe(&response, now);
        if !response.is_success() {
            return Err(self.failure(&response, now));
        }
        let envelope: Envelope<RawReportAck> = serde_json::from_slice(&response.body)
            .map_err(|e| AbuseError::BadResponse(e.to_string()))?;
        self.cache.remove(ip);
        Ok(ReportAck {
            abuse_confidence_score: saturating_u8(envelope.data.abuse_confidence_score),
        })
    }
}

#[cfg(test)]
mod tests;

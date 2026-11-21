// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The HTTP application: router, guard middleware and the five endpoints.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use futures_util::StreamExt;
use serde::Serialize;

use crate::config::{Config, ConfigError};
use crate::error::ApiError;
use crate::ip::{normalize, ProxyPolicy};
use crate::limits::{Limiter, Stats};
use crate::payload::{client_label, DownloadContext, Payload};

/// Protocol revision reported by `/info`; bump when a response shape changes incompatibly.
pub const PROTOCOL_VERSION: u32 = 1;

/// TCP peer of the connection, inserted by the connection service.
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub SocketAddr);

/// Client IP after applying the trusted-proxy policy, inserted by the guard middleware.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: Config,
    limiter: Arc<Limiter>,
    payload: Arc<Payload>,
    stats: Arc<Stats>,
    proxy: ProxyPolicy,
    next_start_frame: AtomicUsize,
}

impl AppState {
    /// Build the state from a validated configuration.
    pub fn new(cfg: Config) -> Result<Self, ConfigError> {
        Self::with_payload(cfg, Payload::random())
    }

    /// Like [`AppState::new`] with an explicit payload pool (deterministic tests).
    pub fn with_payload(cfg: Config, payload: Payload) -> Result<Self, ConfigError> {
        cfg.validate()?;
        let proxy = cfg.proxy_policy()?;
        let stats = Arc::new(Stats::default());
        let limiter = Limiter::new(&cfg.limits, &cfg.server, Arc::clone(&stats), Instant::now());
        Ok(Self {
            inner: Arc::new(Inner {
                cfg,
                limiter,
                payload: Arc::new(payload),
                stats,
                proxy,
                next_start_frame: AtomicUsize::new(0),
            }),
        })
    }

    /// Shared counters.
    pub fn stats(&self) -> &Arc<Stats> {
        &self.inner.stats
    }

    /// The limiter (used by the connection layer for per-IP connection caps).
    pub fn limiter(&self) -> &Arc<Limiter> {
        &self.inner.limiter
    }

    /// The proxy policy.
    pub fn proxy(&self) -> &ProxyPolicy {
        &self.inner.proxy
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.inner.cfg
    }

    fn label(&self, ip: IpAddr) -> String {
        client_label(ip, self.inner.cfg.logging.log_full_ips)
    }
}

/// Build the router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ping", get(ping))
        .route("/download", get(download))
        .route("/upload", post(upload))
        .route("/info", get(info))
        .route("/healthz", get(healthz))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Resolve the client IP and apply the per-IP request rate limit (everything except `/healthz`).
async fn guard(State(app): State<AppState>, mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<PeerAddr>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |p| p.0.ip());
    let client = app.inner.proxy.resolve(peer, req.headers());
    req.extensions_mut().insert(ClientIp(client));
    if req.uri().path() != "/healthz" {
        if let Err(denied) = app.inner.limiter.check_request(client, Instant::now()) {
            tracing::debug!(client = %app.label(client), "request rate limited");
            return ApiError::from(denied).into_response();
        }
    }
    next.run(req).await
}

fn no_cache(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[derive(Serialize)]
struct PingResponse {
    /// Server wall-clock time, milliseconds since the Unix epoch.
    ts_ms: u64,
}

async fn ping() -> Response {
    let mut resp = Json(PingResponse {
        ts_ms: unix_millis(),
    })
    .into_response();
    no_cache(resp.headers_mut());
    resp
}

async fn healthz() -> Response {
    let mut resp = (StatusCode::OK, "ok\n").into_response();
    no_cache(resp.headers_mut());
    resp
}

#[derive(Serialize)]
struct LimitsInfo {
    max_concurrent_tests_per_ip: usize,
    max_streams_per_test: usize,
    max_concurrent_tests_global: usize,
    requests_per_minute_per_ip: u64,
    hourly_bytes_per_ip: u64,
    daily_bytes_per_ip: u64,
    max_transfer_secs: u64,
}

#[derive(Serialize)]
struct InfoResponse {
    protocol: u32,
    server_version: &'static str,
    node_id: String,
    node_name: String,
    location: String,
    /// The requesting client's public IP as seen by this server.
    client_ip: String,
    max_download_bytes: u64,
    max_upload_bytes: u64,
    limits: LimitsInfo,
}

async fn info(State(app): State<AppState>, Extension(client): Extension<ClientIp>) -> Response {
    let c = &app.inner.cfg;
    let body = InfoResponse {
        protocol: PROTOCOL_VERSION,
        server_version: env!("CARGO_PKG_VERSION"),
        node_id: c.node.id.clone(),
        node_name: c.node.name.clone(),
        location: c.node.location.clone(),
        client_ip: normalize(client.0).to_string(),
        max_download_bytes: c.limits.max_download_bytes,
        max_upload_bytes: c.limits.max_upload_bytes,
        limits: LimitsInfo {
            max_concurrent_tests_per_ip: c.limits.max_concurrent_tests_per_ip,
            max_streams_per_test: c.limits.max_streams_per_test,
            max_concurrent_tests_global: c.limits.max_concurrent_tests_global,
            requests_per_minute_per_ip: c.limits.requests_per_minute_per_ip,
            hourly_bytes_per_ip: c.limits.hourly_bytes_per_ip,
            daily_bytes_per_ip: c.limits.daily_bytes_per_ip,
            max_transfer_secs: c.server.max_transfer_secs,
        },
    };
    let mut resp = Json(body).into_response();
    no_cache(resp.headers_mut());
    resp
}

/// Minimal strict query-string reader: `a=b&c=d`, no percent-decoding (the accepted values are plain
/// ASCII tokens), duplicates are rejected, unknown keys are ignored (cache busters are common).
struct Query<'a>(Vec<(&'a str, &'a str)>);

impl<'a> Query<'a> {
    fn parse(raw: Option<&'a str>) -> Self {
        let pairs = raw
            .unwrap_or("")
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| p.split_once('=').unwrap_or((p, "")))
            .collect();
        Self(pairs)
    }

    fn unique(&self, key: &str) -> Result<Option<&'a str>, ApiError> {
        let mut found = None;
        for (k, v) in &self.0 {
            if *k == key {
                if found.is_some() {
                    return Err(ApiError::BadRequest(format!(
                        "parameter {key:?} given more than once"
                    )));
                }
                found = Some(*v);
            }
        }
        Ok(found)
    }
}

/// Parse and bound-check the `bytes` parameter of `/download`.
fn parse_bytes(raw: Option<&str>, max: u64) -> Result<u64, ApiError> {
    let raw = raw.ok_or_else(|| ApiError::BadRequest("missing parameter \"bytes\"".into()))?;
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::BadRequest(
            "\"bytes\" must be a positive integer (digits only)".into(),
        ));
    }
    let n: u64 = raw
        .parse()
        .map_err(|_| ApiError::BadRequest("\"bytes\" is too large".into()))?;
    if n == 0 {
        return Err(ApiError::BadRequest(
            "\"bytes\" must be greater than 0".into(),
        ));
    }
    if n > max {
        return Err(ApiError::BadRequest(format!(
            "\"bytes\" exceeds the maximum of {max}"
        )));
    }
    Ok(n)
}

/// Validate the optional `test` id that groups parallel streams (1-64 chars of `[A-Za-z0-9_-]`).
fn parse_test_id(raw: Option<&str>) -> Result<Option<&str>, ApiError> {
    match raw {
        None => Ok(None),
        Some(id)
            if (1..=64).contains(&id.len())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
        {
            Ok(Some(id))
        }
        Some(_) => Err(ApiError::BadRequest(
            "\"test\" must be 1-64 characters of A-Z, a-z, 0-9, '-' or '_'".into(),
        )),
    }
}

async fn download(
    State(app): State<AppState>,
    Extension(client): Extension<ClientIp>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let query = Query::parse(uri.query());
    let bytes = parse_bytes(
        query.unique("bytes")?,
        app.inner.cfg.limits.max_download_bytes,
    )?;
    let test = parse_test_id(query.unique("test")?)?;
    let permit = app
        .inner
        .limiter
        .begin_transfer(client.0, test, bytes, Instant::now())
        .map_err(|d| {
            tracing::debug!(client = %app.label(client.0), reason = %d, "download refused");
            ApiError::from(d)
        })?;
    let start_frame = app.inner.next_start_frame.fetch_add(3, Ordering::Relaxed);
    let ctx = DownloadContext {
        permit,
        stats: Arc::clone(&app.inner.stats),
        deadline: Instant::now() + app.inner.cfg.max_transfer(),
        start_frame,
        client_label: app.label(client.0),
    };
    let body = app.inner.payload.body(bytes, ctx);
    let mut resp = Response::new(Body::new(body));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes));
    no_cache(h);
    Ok(resp)
}

#[derive(Serialize)]
struct UploadResponse {
    bytes: u64,
    millis: u64,
}

/// Bytes accumulated before charging the byte budget (bounds lock traffic on fast uploads).
const CHARGE_BATCH: u64 = 256 * 1024;

async fn upload(
    State(app): State<AppState>,
    Extension(client): Extension<ClientIp>,
    req: Request,
) -> Result<Json<UploadResponse>, ApiError> {
    let max = app.inner.cfg.limits.max_upload_bytes;
    let (parts, body) = req.into_parts();
    let query = Query::parse(parts.uri.query());
    let test = parse_test_id(query.unique("test")?)?;

    // Refuse early when the declared length is already too large; nothing is read.
    if let Some(len) = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if len > max {
            return Err(ApiError::PayloadTooLarge { max });
        }
    }

    let mut permit = app
        .inner
        .limiter
        .begin_transfer(client.0, test, 0, Instant::now())
        .map_err(|d| {
            tracing::debug!(client = %app.label(client.0), reason = %d, "upload refused");
            ApiError::from(d)
        })?;

    let started = Instant::now();
    let deadline = started + app.inner.cfg.max_transfer();
    let mut stream = body.into_data_stream();
    let mut total: u64 = 0;
    let mut uncharged: u64 = 0;
    let outcome: Result<(), ApiError> = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let next = match tokio::time::timeout(remaining, stream.next()).await {
            Ok(next) => next,
            Err(_) => break Err(ApiError::Timeout),
        };
        match next {
            None => break Ok(()),
            Some(Err(e)) => {
                tracing::debug!(client = %app.label(client.0), error = %e, "upload body error");
                break Err(ApiError::BadRequest("upload interrupted".into()));
            }
            Some(Ok(chunk)) => {
                let n = chunk.len() as u64;
                total = total.saturating_add(n);
                app.inner
                    .stats
                    .received_bytes
                    .fetch_add(n, Ordering::Relaxed);
                if total > max {
                    break Err(ApiError::PayloadTooLarge { max });
                }
                uncharged += n;
                if uncharged >= CHARGE_BATCH {
                    if let Err(d) = permit.charge(uncharged) {
                        break Err(d.into());
                    }
                    uncharged = 0;
                }
            }
        }
    };
    let outcome = outcome.and_then(|()| {
        if uncharged > 0 {
            permit.charge(uncharged).map_err(ApiError::from)
        } else {
            Ok(())
        }
    });
    let millis = started.elapsed().as_millis() as u64;
    tracing::info!(
        client = %app.label(client.0),
        bytes = total,
        millis,
        ok = outcome.is_ok(),
        "upload finished"
    );
    outcome?;
    Ok(Json(UploadResponse {
        bytes: total,
        millis,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_parameter_validation() {
        let max = 1000;
        assert_eq!(parse_bytes(Some("1"), max).unwrap(), 1);
        assert_eq!(parse_bytes(Some("1000"), max).unwrap(), 1000);
        for bad in [
            "0",
            "00",
            "-1",
            "+5",
            "1.5",
            "1e3",
            " 5",
            "",
            "abc",
            "1001",
            "99999999999999999999999",
            "0x10",
        ] {
            assert!(
                parse_bytes(Some(bad), max).is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert!(parse_bytes(None, max).is_err());
    }

    #[test]
    fn test_id_validation() {
        assert_eq!(parse_test_id(None).unwrap(), None);
        assert_eq!(
            parse_test_id(Some("abc-DEF_123")).unwrap(),
            Some("abc-DEF_123")
        );
        assert!(parse_test_id(Some("")).is_err());
        assert!(parse_test_id(Some("a b")).is_err());
        assert!(parse_test_id(Some("é")).is_err());
        assert!(parse_test_id(Some(&"x".repeat(65))).is_err());
    }

    #[test]
    fn query_rejects_duplicates_and_ignores_unknown() {
        let q = Query::parse(Some("bytes=5&r=0.123&flag"));
        assert_eq!(q.unique("bytes").unwrap(), Some("5"));
        assert_eq!(q.unique("flag").unwrap(), Some(""));
        assert_eq!(q.unique("nope").unwrap(), None);
        assert!(Query::parse(Some("bytes=1&bytes=2"))
            .unique("bytes")
            .is_err());
        assert_eq!(Query::parse(None).unique("bytes").unwrap(), None);
    }
}

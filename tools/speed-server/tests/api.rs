// SPDX-License-Identifier: GPL-3.0-or-later
//! End-to-end tests against a real server bound to 127.0.0.1:0. No test moves more than ~64 MB; "huge"
//! downloads are requested but only a few MB are read before the client disconnects.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use pw_speed_server::{start, Config, RunningServer};
use reqwest::{Client, Response, StatusCode};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const GIB: u64 = 1 << 30;

struct Node {
    server: RunningServer,
    base: String,
    client: Client,
}

impl Node {
    fn addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn get(&self, path: &str) -> Response {
        self.client.get(self.url(path)).send().await.unwrap()
    }

    async fn json(&self, path: &str) -> Value {
        self.get(path).await.json().await.unwrap()
    }

    fn active(&self) -> usize {
        self.server.stats().active_streams.load(Ordering::SeqCst)
    }
}

fn base_config() -> Config {
    let mut c = Config::default();
    c.server.listen = "127.0.0.1:0".parse().unwrap();
    c.server.shutdown_grace_secs = 1;
    c
}

async fn spawn(tweak: impl FnOnce(&mut Config)) -> Node {
    let mut c = base_config();
    tweak(&mut c);
    let server = start(c).await.unwrap();
    let base = format!("http://{}", server.local_addr());
    let client = Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    Node {
        server,
        base,
        client,
    }
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

type BodyStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Send>>;

/// Read until at least `n` bytes arrived (or the stream ends); returns the stream so the caller can keep
/// the transfer open or drop it to disconnect.
async fn read_at_least(resp: Response, n: usize) -> (usize, BodyStream) {
    let mut stream: BodyStream = Box::pin(resp.bytes_stream());
    let mut got = 0;
    while got < n {
        match stream.next().await {
            Some(chunk) => got += chunk.unwrap().len(),
            None => break,
        }
    }
    (got, stream)
}

async fn drain(resp: Response) -> u64 {
    let mut total = 0u64;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        total += chunk.unwrap().len() as u64;
    }
    total
}

#[tokio::test]
async fn ping_returns_server_timestamp() {
    let node = spawn(|_| {}).await;
    let resp = node.get("/ping").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers()["cache-control"]
        .to_str()
        .unwrap()
        .contains("no-store"));
    let v: Value = resp.json().await.unwrap();
    let ts = v["ts_ms"].as_u64().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(now.abs_diff(ts) < 5_000);
}

#[tokio::test]
async fn healthz_is_ok_and_unknown_paths_404() {
    let node = spawn(|_| {}).await;
    let resp = node.get("/healthz").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap().trim(), "ok");
    assert_eq!(node.get("/nope").await.status(), StatusCode::NOT_FOUND);
    // Wrong method.
    let r = node
        .client
        .post(node.url("/download?bytes=10"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn download_returns_exact_byte_counts_with_content_length() {
    let node = spawn(|_| {}).await;
    for n in [
        1u64, 2, 1000, 131_071, 131_072, 131_073, 1_048_576, 5_000_001,
    ] {
        let resp = node.get(&format!("/download?bytes={n}")).await;
        assert_eq!(resp.status(), StatusCode::OK, "bytes={n}");
        assert_eq!(resp.content_length(), Some(n), "Content-Length for {n}");
        let h = resp.headers().clone();
        assert!(h["cache-control"].to_str().unwrap().contains("no-store"));
        assert!(h.get("etag").is_none() && h.get("last-modified").is_none());
        assert!(h.get("content-encoding").is_none());
        assert_eq!(drain(resp).await, n, "body length for {n}");
    }
    assert_eq!(node.active(), 0);
}

#[tokio::test]
async fn download_data_looks_random_and_streams_differ() {
    let node = spawn(|_| {}).await;
    let a = node
        .get("/download?bytes=300000")
        .await
        .bytes()
        .await
        .unwrap();
    let b = node
        .get("/download?bytes=300000")
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(a.len(), 300_000);
    let mut histogram = [0u32; 256];
    for &x in a.iter() {
        histogram[x as usize] += 1;
    }
    // Roughly uniform: every byte value shows up and none dominates.
    assert!(histogram.iter().all(|&c| c > 0));
    assert!(histogram.iter().all(|&c| c < 300_000 / 256 * 3));
    // Sequential streams start at different pool frames.
    assert_ne!(a, b);
}

#[tokio::test]
async fn download_rejects_invalid_parameters() {
    let node = spawn(|c| c.limits.max_download_bytes = 1_000_000).await;
    for q in [
        "",
        "bytes=",
        "bytes=0",
        "bytes=-1",
        "bytes=+5",
        "bytes=abc",
        "bytes=1.5",
        "bytes=1e3",
        "bytes=99999999999999999999999999",
        "bytes=18446744073709551616",
        "bytes=1000001",
        "bytes=10&bytes=20",
        "bytes=10&test=bad%20id",
        "bytes=10&test=",
    ] {
        let resp = node.get(&format!("/download?{q}")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "query {q:?}");
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error"], "bad_request");
    }
    assert_eq!(
        node.get("/download").await.status(),
        StatusCode::BAD_REQUEST
    );
    // The boundary is accepted, and unknown parameters (cache busters) are ignored.
    let resp = node.get("/download?bytes=1000000&r=0.123").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(drain(resp).await, 1_000_000);
    assert_eq!(node.active(), 0);
}

#[tokio::test]
async fn partial_download_then_disconnect_stops_generation_and_frees_the_slot() {
    // Default limits: max_download 50 GiB, hourly budget 100 GiB, 2 tests per IP.
    let node = spawn(|_| {}).await;
    let stats = node.server.stats();
    let before = stats.generated_bytes.load(Ordering::SeqCst);
    for round in 0..3 {
        // Three rounds of "50 GiB" requests only fit the 100 GiB hourly budget if aborted transfers refund
        // their unsent bytes.
        let resp = node.get(&format!("/download?bytes={}", 50 * GIB)).await;
        assert_eq!(resp.status(), StatusCode::OK, "round {round}");
        assert_eq!(resp.content_length(), Some(50 * GIB));
        let (got, stream) = read_at_least(resp, 4 * 1024 * 1024).await;
        assert!(got >= 4 * 1024 * 1024);
        assert_eq!(node.active(), 1);
        drop(stream);
        wait_for("download slot to be released", || node.active() == 0).await;
    }
    let after_disconnect = stats.generated_bytes.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let later = stats.generated_bytes.load(Ordering::SeqCst);
    assert_eq!(
        after_disconnect, later,
        "generation must stop when the client disconnects"
    );
    // Only what the client read plus what fits in socket and hyper buffers was ever produced.
    let produced = later - before;
    assert!(
        produced < 3 * 64 * 1024 * 1024,
        "produced {produced} bytes for three aborted downloads"
    );
    assert_eq!(node.active(), 0);
}

#[tokio::test]
async fn upload_counts_bytes() {
    let node = spawn(|_| {}).await;
    for n in [0usize, 1, 1000, 3_000_000] {
        let resp = node
            .client
            .post(node.url("/upload"))
            .body(vec![7u8; n])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "size {n}");
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["bytes"].as_u64().unwrap(), n as u64);
        assert!(v["millis"].as_u64().is_some());
    }
    assert_eq!(
        node.server.stats().received_bytes.load(Ordering::SeqCst),
        3_001_001
    );
    assert_eq!(node.active(), 0);
}

#[tokio::test]
async fn upload_counts_chunked_bodies_without_content_length() {
    let node = spawn(|_| {}).await;
    let chunks =
        (0..10).map(|_| Ok::<_, std::convert::Infallible>(bytes::Bytes::from(vec![1u8; 100_000])));
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter(chunks));
    let resp = node
        .client
        .post(node.url("/upload"))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["bytes"].as_u64().unwrap(), 1_000_000);
}

#[tokio::test]
async fn upload_over_the_limit_is_413_for_declared_and_chunked_bodies() {
    let node = spawn(|c| c.limits.max_upload_bytes = 100_000).await;
    // Exactly at the limit is fine.
    let ok = node
        .client
        .post(node.url("/upload"))
        .body(vec![0u8; 100_000])
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    // Declared length over the limit: rejected before reading.
    let resp = node
        .client
        .post(node.url("/upload"))
        .body(vec![0u8; 100_001])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"], "payload_too_large");
    // Chunked (no length): rejected as soon as the running total crosses the limit.
    let chunks =
        (0..4).map(|_| Ok::<_, std::convert::Infallible>(bytes::Bytes::from(vec![1u8; 50_000])));
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter(chunks));
    let result = node
        .client
        .post(node.url("/upload"))
        .body(body)
        .send()
        .await;
    // The server may close the connection while the client is still sending; that is acceptable.
    if let Ok(resp) = result {
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
    wait_for("upload slots to be released", || node.active() == 0).await;
}

#[tokio::test]
async fn concurrent_test_limit_returns_429_with_retry_after_and_recovers() {
    let node = spawn(|c| c.limits.max_concurrent_tests_per_ip = 2).await;
    let big = format!("/download?bytes={}", 10 * GIB);
    let (_, s1) = read_at_least(node.get(&big).await, 1024).await;
    let (_, s2) = read_at_least(node.get(&big).await, 1024).await;
    assert_eq!(node.active(), 2);
    let denied = node.get(&big).await;
    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        denied.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            >= 1
    );
    let v: Value = denied.json().await.unwrap();
    assert_eq!(v["error"], "too_many_requests");
    // Uploads share the same per-IP test budget.
    let up = node
        .client
        .post(node.url("/upload"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(up.status(), StatusCode::TOO_MANY_REQUESTS);
    // Cheap endpoints are not affected.
    assert_eq!(node.get("/ping").await.status(), StatusCode::OK);
    drop(s1);
    wait_for("slot release", || node.active() == 1).await;
    let again = node.get("/download?bytes=1000").await;
    assert_eq!(again.status(), StatusCode::OK);
    assert_eq!(drain(again).await, 1000);
    drop(s2);
}

#[tokio::test]
async fn streams_sharing_a_test_id_count_as_one_test_up_to_the_stream_cap() {
    let node = spawn(|c| {
        c.limits.max_concurrent_tests_per_ip = 1;
        c.limits.max_streams_per_test = 3;
    })
    .await;
    let big = format!("/download?bytes={}&test=run1", 10 * GIB);
    let mut held = Vec::new();
    for _ in 0..3 {
        let resp = node.get(&big).await;
        assert_eq!(resp.status(), StatusCode::OK);
        held.push(read_at_least(resp, 1024).await.1);
    }
    assert_eq!(
        node.get(&big).await.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "fourth stream"
    );
    // A different test id is a second test, which the per-IP limit of 1 refuses.
    let other = format!("/download?bytes={}&test=run2", 10 * GIB);
    assert_eq!(
        node.get(&other).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    held.clear();
    wait_for("streams to end", || node.active() == 0).await;
    assert_eq!(
        node.get("/download?bytes=10&test=run2").await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn global_test_limit_returns_429() {
    let node = spawn(|c| {
        c.limits.max_concurrent_tests_per_ip = 0;
        c.limits.max_concurrent_tests_global = 2;
    })
    .await;
    let big = format!("/download?bytes={}", 10 * GIB);
    let (_, _a) = read_at_least(node.get(&big).await, 1024).await;
    let (_, _b) = read_at_least(node.get(&big).await, 1024).await;
    assert_eq!(node.get(&big).await.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn request_rate_limit_applies_to_endpoints_but_not_healthz() {
    let node = spawn(|c| c.limits.requests_per_minute_per_ip = 5).await;
    for i in 0..5 {
        assert_eq!(
            node.get("/ping").await.status(),
            StatusCode::OK,
            "request {i}"
        );
    }
    let limited = node.get("/ping").await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = limited.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry), "retry-after {retry}");
    assert_eq!(
        node.get("/info").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    for _ in 0..20 {
        assert_eq!(node.get("/healthz").await.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn byte_budget_returns_429_once_exhausted() {
    let node = spawn(|c| {
        c.limits.max_download_bytes = 1_000_000;
        c.limits.hourly_bytes_per_ip = 2_000_000;
        c.limits.daily_bytes_per_ip = 10_000_000;
    })
    .await;
    for _ in 0..2 {
        let resp = node.get("/download?bytes=1000000").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(drain(resp).await, 1_000_000);
    }
    wait_for("slots", || node.active() == 0).await;
    let denied = node.get("/download?bytes=1000").await;
    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = denied.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((3500..=3601).contains(&retry), "retry-after {retry}");
    // Uploads are charged against the same budget.
    let up = node
        .client
        .post(node.url("/upload"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(up.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn upload_that_overruns_the_budget_is_cut_off_with_429() {
    let node = spawn(|c| {
        c.limits.max_download_bytes = 500_000;
        c.limits.hourly_bytes_per_ip = 500_000;
        c.limits.daily_bytes_per_ip = 0;
    })
    .await;
    let resp = node
        .client
        .post(node.url("/upload"))
        .body(vec![0u8; 1_000_000])
        .send()
        .await;
    match resp {
        Ok(r) => assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS),
        Err(e) => panic!("expected a 429 response, got {e}"),
    }
}

#[tokio::test]
async fn unlimited_settings_disable_limits() {
    let node = spawn(|c| {
        c.limits.requests_per_minute_per_ip = 0;
        c.limits.hourly_bytes_per_ip = 0;
        c.limits.daily_bytes_per_ip = 0;
        c.limits.max_concurrent_tests_per_ip = 0;
        c.limits.max_download_bytes = 1_000_000;
    })
    .await;
    for _ in 0..50 {
        assert_eq!(node.get("/ping").await.status(), StatusCode::OK);
    }
    for _ in 0..5 {
        assert_eq!(
            drain(node.get("/download?bytes=1000000").await).await,
            1_000_000
        );
    }
}

#[tokio::test]
async fn info_reports_node_limits_and_client_ip() {
    let node = spawn(|c| {
        c.node.id = "mia".into();
        c.node.name = "Miami".into();
        c.node.location = "Miami, US".into();
    })
    .await;
    let v = node.json("/info").await;
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["node_id"], "mia");
    assert_eq!(v["node_name"], "Miami");
    assert_eq!(v["location"], "Miami, US");
    assert_eq!(v["client_ip"], "127.0.0.1");
    assert_eq!(v["max_download_bytes"].as_u64().unwrap(), 50 * GIB);
    assert_eq!(v["max_upload_bytes"].as_u64().unwrap(), 10 * GIB);
    assert_eq!(v["limits"]["max_concurrent_tests_per_ip"], 2);
    assert_eq!(v["limits"]["max_concurrent_tests_global"], 64);
    assert!(v["server_version"].as_str().is_some());
}

async fn client_ip_with_header(node: &Node, value: &str) -> String {
    let v: Value = node
        .client
        .get(node.url("/info"))
        .header("X-Forwarded-For", value)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["client_ip"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn proxy_header_is_ignored_unless_enabled() {
    let node = spawn(|c| c.proxy.trust_header = false).await;
    assert_eq!(
        client_ip_with_header(&node, "203.0.113.9").await,
        "127.0.0.1"
    );
}

#[tokio::test]
async fn proxy_header_is_honored_when_enabled_and_peer_is_trusted() {
    let node = spawn(|c| c.proxy.trust_header = true).await;
    assert_eq!(
        client_ip_with_header(&node, "203.0.113.9").await,
        "203.0.113.9"
    );
    // A spoofed leftmost entry does not win over the entry our proxy appended.
    assert_eq!(
        client_ip_with_header(&node, "6.6.6.6, 203.0.113.9").await,
        "203.0.113.9"
    );
    // IPv6 and garbage.
    assert_eq!(
        client_ip_with_header(&node, "2001:db8::7").await,
        "2001:db8::7"
    );
    assert_eq!(client_ip_with_header(&node, "not an ip").await, "127.0.0.1");
}

#[tokio::test]
async fn proxy_header_is_ignored_when_peer_is_not_a_trusted_proxy() {
    let node = spawn(|c| {
        c.proxy.trust_header = true;
        c.proxy.trusted_peers = vec!["10.0.0.0/8".into()];
    })
    .await;
    assert_eq!(
        client_ip_with_header(&node, "203.0.113.9").await,
        "127.0.0.1"
    );
}

#[tokio::test]
async fn limits_are_applied_per_resolved_client_behind_a_proxy() {
    let node = spawn(|c| {
        c.proxy.trust_header = true;
        c.limits.requests_per_minute_per_ip = 2;
    })
    .await;
    let get = |ip: &'static str| {
        let node = &node;
        async move {
            node.client
                .get(node.url("/ping"))
                .header("X-Forwarded-For", ip)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(get("203.0.113.1").await, StatusCode::OK);
    assert_eq!(get("203.0.113.1").await, StatusCode::OK);
    assert_eq!(get("203.0.113.1").await, StatusCode::TOO_MANY_REQUESTS);
    // A different real client behind the same proxy has its own bucket.
    assert_eq!(get("203.0.113.2").await, StatusCode::OK);
}

/// Read from a raw socket until EOF/reset, returning how long that took (or None on timeout).
async fn time_to_close(stream: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let start = Instant::now();
    let mut buf = [0u8; 1024];
    loop {
        match tokio::time::timeout(limit.saturating_sub(start.elapsed()), stream.read(&mut buf))
            .await
        {
            Err(_) => return None,
            Ok(Ok(0)) | Ok(Err(_)) => return Some(start.elapsed()),
            Ok(Ok(_)) => continue,
        }
    }
}

#[tokio::test]
async fn idle_connections_are_closed() {
    let node = spawn(|c| c.server.idle_timeout_secs = 1).await;
    let mut s = TcpStream::connect(node.addr()).await.unwrap();
    let closed = time_to_close(&mut s, Duration::from_secs(6)).await;
    let t = closed.expect("idle connection should be closed by the server");
    assert!(t >= Duration::from_millis(800), "closed too early: {t:?}");
}

#[tokio::test]
async fn keep_alive_connection_is_closed_after_idle_period() {
    let node = spawn(|c| c.server.idle_timeout_secs = 1).await;
    let mut s = TcpStream::connect(node.addr()).await.unwrap();
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let n = s.read(&mut buf).await.unwrap();
    assert!(std::str::from_utf8(&buf[..n])
        .unwrap()
        .starts_with("HTTP/1.1 200"));
    assert!(time_to_close(&mut s, Duration::from_secs(6))
        .await
        .is_some());
}

#[tokio::test]
async fn slow_headers_are_cut_off() {
    let node = spawn(|c| {
        c.server.header_read_timeout_secs = 1;
        c.server.idle_timeout_secs = 30;
    })
    .await;
    let mut s = TcpStream::connect(node.addr()).await.unwrap();
    // A slow-loris client dribbles a header and never finishes it.
    s.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nX-A: ")
        .await
        .unwrap();
    let t = time_to_close(&mut s, Duration::from_secs(6))
        .await
        .expect("server must give up on the headers");
    assert!(t < Duration::from_secs(5), "{t:?}");
}

#[tokio::test]
async fn stalled_reader_is_dropped_and_frees_its_slot() {
    let node = spawn(|c| c.server.idle_timeout_secs = 1).await;
    let mut s = TcpStream::connect(node.addr()).await.unwrap();
    let req = format!(
        "GET /download?bytes={} HTTP/1.1\r\nHost: x\r\n\r\n",
        50 * GIB
    );
    s.write_all(req.as_bytes()).await.unwrap();
    // Never read: socket buffers fill, writes stall, the idle timeout fires.
    wait_for("download to start", || node.active() == 1).await;
    wait_for("stalled download to be dropped", || node.active() == 0).await;
    drop(s);
    // Whatever was buffered is bounded by socket buffers, not by the 50 GiB request.
    assert!(node.server.stats().generated_bytes.load(Ordering::SeqCst) < 256 * 1024 * 1024);
}

#[tokio::test]
async fn max_transfer_duration_cuts_a_slow_download() {
    let node = spawn(|c| c.server.max_transfer_secs = 1).await;
    let resp = node.get(&format!("/download?bytes={}", 50 * GIB)).await;
    let mut stream = Box::pin(resp.bytes_stream());
    let started = Instant::now();
    let mut total = 0usize;
    let mut cut = false;
    // Read slowly so only a few MB move, but keep the connection active past the 1 s deadline.
    while started.elapsed() < Duration::from_secs(8) {
        match stream.next().await {
            Some(Ok(chunk)) => total += chunk.len(),
            Some(Err(_)) | None => {
                cut = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    assert!(
        cut,
        "download should have been aborted by max_transfer_secs"
    );
    assert!(total < 64 * 1024 * 1024, "{total}");
    wait_for("slot release", || node.active() == 0).await;
}

#[tokio::test]
async fn per_ip_connection_cap_drops_extra_connections() {
    let node = spawn(|c| c.server.max_connections_per_ip = 2).await;
    let mut a = TcpStream::connect(node.addr()).await.unwrap();
    let mut b = TcpStream::connect(node.addr()).await.unwrap();
    // Let the server register both before opening the third.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut c = TcpStream::connect(node.addr()).await.unwrap();
    assert!(
        time_to_close(&mut c, Duration::from_secs(3))
            .await
            .is_some(),
        "third connection should be dropped"
    );
    // The first two still work.
    for s in [&mut a, &mut b] {
        s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("HTTP/1.1 200"));
    }
}

#[tokio::test]
async fn graceful_shutdown_closes_idle_connections_and_cuts_stragglers_after_the_grace_period() {
    let node = spawn(|c| {
        c.server.shutdown_grace_secs = 1;
        c.server.idle_timeout_secs = 30;
    })
    .await;
    let addr = node.addr();
    let mut idle = TcpStream::connect(addr).await.unwrap();
    // An unfinished 50 GiB download that the client is still reading slowly.
    let resp = node.get(&format!("/download?bytes={}", 50 * GIB)).await;
    let (_, mut stream) = read_at_least(resp, 1024).await;
    let reader = tokio::spawn(async move {
        let mut total = 0usize;
        while let Some(Ok(chunk)) = stream.next().await {
            total += chunk.len();
            tokio::time::sleep(Duration::from_millis(50)).await;
            if total > 32 * 1024 * 1024 {
                break;
            }
        }
        total
    });
    let started = Instant::now();
    node.server.shutdown();
    assert!(
        time_to_close(&mut idle, Duration::from_secs(5))
            .await
            .is_some(),
        "idle connection must close"
    );
    tokio::time::timeout(Duration::from_secs(10), node.server.wait())
        .await
        .expect("server must stop");
    assert!(started.elapsed() < Duration::from_secs(8));
    reader.await.unwrap();
    // The port no longer accepts.
    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn invalid_configuration_is_rejected_at_start() {
    let mut c = base_config();
    c.limits.max_download_bytes = 0;
    assert!(start(c).await.is_err());
    let mut c = base_config();
    c.tls.cert_file = Some("only-cert.pem".into());
    assert!(start(c).await.is_err());
}

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn tls_config_without_the_feature_fails_clearly() {
    let mut c = base_config();
    c.tls.cert_file = Some("c.pem".into());
    c.tls.key_file = Some("k.pem".into());
    let err = start(c).await.err().expect("must fail");
    assert!(err.to_string().contains("tls"), "{err}");
}

/// Loopback throughput; run explicitly: `cargo test --release -p pw-speed-server --test api -- --ignored --nocapture`.
/// Moves 64 MiB per measurement, well under the 64 MB-per-test cap of the dev box.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark; run explicitly in release mode"]
async fn throughput_loopback_64mib() {
    const TOTAL: u64 = 64 * 1024 * 1024;
    let node = spawn(|c| {
        c.limits.requests_per_minute_per_ip = 0;
        c.limits.max_concurrent_tests_per_ip = 0;
    })
    .await;
    // Warm up connection/JIT-ish effects.
    drain(node.get("/download?bytes=1048576").await).await;

    let mut single = Vec::new();
    for _ in 0..3 {
        let started = Instant::now();
        let n = drain(node.get(&format!("/download?bytes={TOTAL}")).await).await;
        assert_eq!(n, TOTAL);
        single.push(TOTAL as f64 * 8.0 / started.elapsed().as_secs_f64() / 1e9);
    }
    println!("single stream 64 MiB: {single:.2?} Gbit/s");

    // 8 parallel streams of 8 MiB each (64 MiB total).
    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let client = node.client.clone();
        let url = node.url(&format!("/download?bytes={}&test=bench", TOTAL / 8));
        tasks.push(tokio::spawn(async move {
            let resp = client.get(url).send().await.unwrap();
            drain(resp).await
        }));
    }
    let mut total = 0;
    for t in tasks {
        total += t.await.unwrap();
    }
    assert_eq!(total, TOTAL);
    println!(
        "8 parallel streams, 64 MiB total: {:.2} Gbit/s",
        TOTAL as f64 * 8.0 / started.elapsed().as_secs_f64() / 1e9
    );

    // Upload 64 MiB.
    let started = Instant::now();
    let resp = node
        .client
        .post(node.url("/upload"))
        .body(vec![0u8; TOTAL as usize])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    println!(
        "upload 64 MiB: {:.2} Gbit/s",
        TOTAL as f64 * 8.0 / started.elapsed().as_secs_f64() / 1e9
    );
}

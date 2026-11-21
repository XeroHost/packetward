// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The speed-test client against the real `pw-speed-server`, started in-process on 127.0.0.1:0 (no firewall port,
//! no outside traffic). Every test moves at most 64 MB. Run with `--features speed`.

#![cfg(feature = "speed")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::Ordering;
use std::time::Duration;

use pw_diag::speed::{
    BinOptions, BinSize, HttpTransport, HttpTransportConfig, LatencyOptions, PickOptions,
    RunOptions, ServerEndpoint, SpeedClient, SpeedError, SpeedProgress, ThroughputOptions,
};
use pw_diag::{CancelToken, FnSink, NullSink};
use pw_speed_server::{start, Config, RunningServer};

const MIB: u64 = 1 << 20;

async fn spawn(tweak: impl FnOnce(&mut Config)) -> (RunningServer, ServerEndpoint) {
    let mut config = Config::default();
    config.server.listen = "127.0.0.1:0".parse().unwrap();
    config.server.shutdown_grace_secs = 1;
    config.node.id = "loop".into();
    config.node.name = "Loopback".into();
    tweak(&mut config);
    let server = start(config).await.unwrap();
    let endpoint = ServerEndpoint::custom(&format!("http://{}", server.local_addr())).unwrap();
    (server, endpoint)
}

fn client() -> SpeedClient<HttpTransport> {
    let transport = HttpTransport::new(&HttpTransportConfig {
        no_proxy: true,
        ..HttpTransportConfig::default()
    })
    .unwrap();
    SpeedClient::new(transport)
}

fn bounded(streams: usize, total: u64) -> ThroughputOptions {
    ThroughputOptions {
        streams,
        duration: Duration::from_secs(60),
        warmup: Duration::ZERO,
        max_bytes: Some(total),
        bucket: Duration::from_millis(50),
        ..ThroughputOptions::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ping_info_and_a_16_mib_download_and_upload_over_four_streams() {
    // One test slot per client IP: the four parallel streams only get through because they all carry the same
    // `?test=` id (without it the server would count four tests and answer 429).
    let (server, endpoint) = spawn(|c| c.limits.max_concurrent_tests_per_ip = 1).await;
    let client = client();
    let cancel = CancelToken::new();

    let latency = client
        .latency(
            &endpoint,
            &LatencyOptions {
                interval: Duration::ZERO,
                ..LatencyOptions::default()
            },
            &cancel,
            &mut NullSink,
        )
        .await
        .unwrap();
    assert_eq!(
        (latency.sent, latency.received, latency.failed),
        (10, 10, 0)
    );
    assert!(latency.min_ms.unwrap() >= 0.0 && latency.max_ms.unwrap() < 2000.0);
    assert!(latency.jitter_ms.is_some());

    let info = client.server_info(&endpoint, &cancel).await.unwrap();
    assert_eq!(info.node_id, "loop");
    assert_eq!(info.client_ip_addr(), Some("127.0.0.1".parse().unwrap()));
    assert_eq!(info.limits.max_concurrent_tests_per_ip, 1);

    let mut events = Vec::new();
    let download = client
        .download(
            &endpoint,
            Some(&info),
            &bounded(4, 16 * MIB),
            &cancel,
            &mut FnSink(|e| events.push(e)),
        )
        .await
        .unwrap();
    assert_eq!(download.streams, 4);
    assert_eq!(download.total_bytes, 16 * MIB);
    assert!(download.avg_mbps > 0.0 && download.peak_mbps >= download.avg_mbps);
    assert_eq!(
        server.stats().generated_bytes.load(Ordering::SeqCst),
        16 * MIB
    );
    // Loopback may finish before the first 50 ms bucket, so only the phase event is guaranteed.
    assert!(events
        .iter()
        .any(|e| matches!(e, SpeedProgress::Phase { .. })));

    let upload = client
        .upload(
            &endpoint,
            Some(&info),
            &bounded(4, 16 * MIB),
            &cancel,
            &mut NullSink,
        )
        .await
        .unwrap();
    assert_eq!(upload.streams, 4);
    assert_eq!(upload.total_bytes, 16 * MIB);
    assert_eq!(
        server.stats().received_bytes.load(Ordering::SeqCst),
        16 * MIB
    );
    assert_ne!(download.test_id, upload.test_id);

    let bin_options = {
        let mut bin = BinOptions::new(BinSize::OneGib);
        bin.scale = (16 * MIB) as f64 / (1u64 << 30) as f64;
        bin.bucket = Duration::from_millis(50);
        bin
    };
    let bin = client
        .bin_test(&endpoint, Some(&info), &bin_options, &cancel, &mut NullSink)
        .await
        .unwrap();
    assert_eq!(
        (bin.bytes, bin.size_bytes, bin.streams),
        (16 * MIB, 1 << 30, 4)
    );
    assert_eq!(
        server.stats().generated_bytes.load(Ordering::SeqCst),
        32 * MIB
    );
    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_full_run_picks_the_live_server_skips_a_dead_one_and_reports_the_source_ip() {
    let (server, live) = spawn(|_| {}).await;
    // Nothing listens on port 1: connection refused, the candidate is dead.
    let dead = ServerEndpoint::custom("http://127.0.0.1:1").unwrap();
    let options = RunOptions {
        pick: PickOptions::default(),
        latency: Some(LatencyOptions {
            count: 3,
            interval: Duration::ZERO,
            ..LatencyOptions::default()
        }),
        download: Some(bounded(4, 8 * MIB)),
        upload: Some(bounded(4, 8 * MIB)),
    };
    let result = client()
        .run(&[dead, live], &options, &CancelToken::new(), &mut NullSink)
        .await
        .unwrap();
    assert_eq!(result.server.name, "Loopback");
    assert_eq!(result.source_ip, Some("127.0.0.1".parse().unwrap()));
    assert_eq!(result.servers_probed.len(), 2);
    assert!(result.servers_probed[0].latency_ms.is_none());
    assert!(result.servers_probed[1].latency_ms.is_some());
    assert_eq!(result.download.unwrap().total_bytes, 8 * MIB);
    assert_eq!(result.upload.unwrap().total_bytes, 8 * MIB);
    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_servers_429_with_retry_after_fails_fast_and_the_published_budget_is_respected() {
    // 8 MiB per download, 16 MiB per hour: the third download is refused by the server.
    let (server, endpoint) = spawn(|c| {
        c.limits.max_download_bytes = 8 * MIB;
        c.limits.hourly_bytes_per_ip = 16 * MIB;
        c.limits.daily_bytes_per_ip = 16 * MIB;
    })
    .await;
    let client = client();
    let cancel = CancelToken::new();
    for _ in 0..2 {
        client
            .download(
                &endpoint,
                None,
                &bounded(2, 8 * MIB),
                &cancel,
                &mut NullSink,
            )
            .await
            .unwrap();
    }
    let error = client
        .download(
            &endpoint,
            None,
            &bounded(2, 8 * MIB),
            &cancel,
            &mut NullSink,
        )
        .await
        .unwrap_err();
    match error {
        SpeedError::RateLimited {
            retry_after_secs: Some(secs),
        } => assert!(secs >= 1),
        other => panic!("expected RateLimited with Retry-After, got {other:?}"),
    }
    assert!(server.stats().rejected.load(Ordering::SeqCst) >= 1);

    // With the server's /info in hand, a 1 GiB bin test is refused before any request.
    let info = client.server_info(&endpoint, &cancel).await.unwrap();
    let before = server.stats().generated_bytes.load(Ordering::SeqCst);
    let error = client
        .bin_test(
            &endpoint,
            Some(&info),
            &BinOptions::new(BinSize::OneGib),
            &cancel,
            &mut NullSink,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, SpeedError::BudgetExceeded { .. }),
        "{error:?}"
    );
    assert_eq!(
        server.stats().generated_bytes.load(Ordering::SeqCst),
        before
    );
    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_a_real_download_closes_its_connections() {
    let (server, endpoint) = spawn(|_| {}).await;
    let client = client();
    let cancel = CancelToken::new();
    // Cancel as soon as the server reports the first generated bytes. 64 MiB is the most this test may move.
    let trigger = cancel.clone();
    let stats = std::sync::Arc::clone(server.stats());
    let watcher = tokio::spawn(async move {
        while stats.generated_bytes.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        trigger.cancel();
    });
    let options = ThroughputOptions {
        request_bytes: Some(16 * MIB),
        ..bounded(4, 64 * MIB)
    };
    let result = client
        .download(&endpoint, None, &options, &cancel, &mut NullSink)
        .await;
    watcher.abort();
    match result {
        Err(SpeedError::Cancelled) => {
            // The streams are gone: the server sees the disconnects and no byte flows any more.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while server.stats().active_streams.load(Ordering::SeqCst) != 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "server streams never ended"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let after = server.stats().generated_bytes.load(Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(250)).await;
            assert_eq!(server.stats().generated_bytes.load(Ordering::SeqCst), after);
            assert!(after < 64 * MIB);
        }
        // Loopback was faster than the first 50 ms bucket: nothing left to cancel, which is fine.
        Ok(done) => {
            eprintln!("loopback finished before the first bucket; nothing to cancel");
            assert_eq!(done.total_bytes, 64 * MIB);
        }
        Err(other) => panic!("unexpected error {other:?}"),
    }
    server.shutdown();
}

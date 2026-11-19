// SPDX-License-Identifier: GPL-3.0-or-later
//! Behaviour tests of the speed-test client against the scripted fake transport. No sockets; the duration logic
//! runs on tokio's paused clock, the cancellation test on the real one.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::error::BudgetWindow;
use super::fake::{CallKind, FakeTransport};
use super::*;
use crate::{CancelToken, FnSink, NullSink};

const MIB: u64 = 1 << 20;

fn server(authority: &str) -> ServerEndpoint {
    ServerEndpoint::custom(&format!("https://{authority}")).unwrap()
}

fn info(max_streams: u64, hourly: u64) -> ServerInfo {
    ServerInfo {
        protocol: 1,
        node_id: "mia".into(),
        node_name: "Miami".into(),
        location: "Miami, US".into(),
        client_ip: "203.0.113.9".into(),
        max_download_bytes: 50 << 30,
        max_upload_bytes: 10 << 30,
        limits: ServerLimits {
            max_streams_per_test: max_streams,
            hourly_bytes_per_ip: hourly,
            daily_bytes_per_ip: 3 * hourly,
            ..ServerLimits::default()
        },
        ..ServerInfo::default()
    }
}

fn client(fake: &FakeTransport) -> SpeedClient<FakeTransport> {
    SpeedClient::new(fake.clone())
}

fn quick(streams: usize, duration_secs: u64, warmup_secs: u64) -> ThroughputOptions {
    ThroughputOptions {
        streams,
        duration: Duration::from_secs(duration_secs),
        warmup: Duration::from_secs(warmup_secs),
        ..ThroughputOptions::default()
    }
}

fn near(actual: f64, expected: f64, tolerance: f64) {
    assert!(
        (actual - expected).abs() <= tolerance,
        "{actual} is not within {tolerance} of {expected}"
    );
}

// ---------------------------------------------------------------- throughput

#[tokio::test(start_paused = true)]
async fn warm_up_is_excluded_and_the_window_is_the_configured_duration() {
    let fake = FakeTransport::new(); // 1 MB/s per stream
    let s = server("a.example:443");
    let result = client(&fake)
        .download(
            &s,
            None,
            &quick(2, 4, 2),
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap();
    assert_eq!(result.streams, 2);
    assert_eq!(result.duration_ms, 4000);
    assert_eq!(result.warmup_ms, 2000);
    // 2 streams x 1 MB/s = 16 Mbit/s, over the 4 s after the warm-up: 8 MB. Everything moved: 12 MB.
    near(result.avg_mbps, 16.0, 0.4);
    near(result.bytes as f64, 8_000_000.0, 40_000.0);
    near(result.total_bytes as f64, 12_000_000.0, 40_000.0);
    assert_eq!(result.buckets_mbps.len(), 4);
    assert!(result.peak_mbps >= result.avg_mbps);
    near(result.peak_mbps, 16.0, 1.0);
}

#[tokio::test(start_paused = true)]
async fn all_streams_of_a_run_share_one_test_id_and_phases_get_their_own() {
    let fake = FakeTransport::new();
    fake.set_latency("a.example:443", Duration::from_millis(5));
    fake.set_info("a.example:443", Ok(info(8, 100 << 30)));
    let s = server("a.example:443");
    let options = RunOptions {
        latency: None,
        download: Some(ThroughputOptions {
            max_bytes: Some(4 * MIB),
            ..quick(4, 2, 0)
        }),
        upload: Some(ThroughputOptions {
            max_bytes: Some(4 * MIB),
            ..quick(4, 2, 0)
        }),
        ..RunOptions::default()
    };
    let result = client(&fake)
        .run(&[s], &options, &CancelToken::new(), &mut NullSink)
        .await
        .unwrap();
    let downloads = fake.calls_of(CallKind::Download);
    let uploads = fake.calls_of(CallKind::Upload);
    assert_eq!((downloads.len(), uploads.len()), (4, 4));
    let down_id = result.download.unwrap().test_id;
    let up_id = result.upload.unwrap().test_id;
    assert!(downloads.iter().all(|c| c.test_id == down_id));
    assert!(uploads.iter().all(|c| c.test_id == up_id));
    assert_ne!(down_id, up_id);
    assert!(valid_test_id(&down_id) && valid_test_id(&up_id));
}

#[tokio::test(start_paused = true)]
async fn a_byte_cap_is_shared_out_equally_and_ends_the_run_early() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let started = Instant::now();
    let result = client(&fake)
        .download(
            &s,
            None,
            &ThroughputOptions {
                max_bytes: Some(16 * MIB),
                ..quick(4, 60, 0)
            },
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap();
    assert_eq!(result.total_bytes, 16 * MIB);
    let calls = fake.calls_of(CallKind::Download);
    assert_eq!(calls.len(), 4);
    assert!(calls.iter().all(|c| c.bytes == 4 * MIB));
    // 4 MiB per stream at 1 MB/s: about 4 s, nowhere near the 60 s duration.
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test(start_paused = true)]
async fn streams_are_clamped_to_the_range_and_to_the_server_limit() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let capped = ThroughputOptions {
        max_bytes: Some(MIB),
        ..quick(16, 1, 0)
    };
    let c = client(&fake);
    let with_limit = c
        .download(
            &s,
            Some(&info(8, 0)),
            &capped,
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap();
    assert_eq!(with_limit.streams, 8);
    let without = c
        .download(
            &s,
            None,
            &ThroughputOptions {
                streams: 99,
                ..capped.clone()
            },
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap();
    assert_eq!(without.streams, 16);
    let one = c
        .download(
            &s,
            None,
            &ThroughputOptions {
                streams: 0,
                ..capped
            },
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap();
    assert_eq!(one.streams, 1);
}

#[tokio::test(start_paused = true)]
async fn requests_never_exceed_the_servers_published_maximum() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let mut limits = info(8, 0);
    limits.max_download_bytes = 512 * 1024;
    client(&fake)
        .download(
            &s,
            Some(&limits),
            &ThroughputOptions {
                max_bytes: Some(3 * MIB),
                ..quick(2, 30, 0)
            },
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap();
    let calls = fake.calls_of(CallKind::Download);
    assert!(calls.len() >= 6);
    assert!(calls.iter().all(|c| c.bytes <= 512 * 1024));
    assert_eq!(calls.iter().map(|c| c.bytes).sum::<u64>(), 3 * MIB);
}

#[tokio::test(start_paused = true)]
async fn progress_reports_each_bucket_and_marks_the_warm_up() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let mut events = Vec::new();
    client(&fake)
        .download(
            &s,
            None,
            &quick(2, 3, 2),
            &CancelToken::new(),
            &mut FnSink(|e| events.push(e)),
        )
        .await
        .unwrap();
    assert!(matches!(
        events[0],
        SpeedProgress::Phase {
            phase: SpeedPhase::Download
        }
    ));
    let ticks: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SpeedProgress::Throughput {
                elapsed_ms,
                warmup,
                mbps,
                avg_mbps,
                bytes,
                ..
            } => Some((*elapsed_ms, *warmup, *mbps, *avg_mbps, *bytes)),
            _ => None,
        })
        .collect();
    assert!(ticks.len() >= 4, "{ticks:?}");
    for (elapsed, warmup, mbps, avg, _) in &ticks {
        assert_eq!(*warmup, *elapsed <= 2000);
        near(*mbps, 16.0, 1.0);
        if *warmup {
            assert_eq!(*avg, 0.0);
        } else {
            near(*avg, 16.0, 1.0);
        }
    }
    assert!(ticks.windows(2).all(|w| w[0].4 <= w[1].4));
}

#[tokio::test(start_paused = true)]
async fn a_stalled_transfer_fails_instead_of_hanging() {
    let fake = FakeTransport::new();
    fake.set_rate(0);
    let s = server("a.example:443");
    let started = Instant::now();
    let error = client(&fake)
        .download(
            &s,
            None,
            &ThroughputOptions {
                stall_timeout: Duration::from_secs(5),
                ..quick(2, 60, 2)
            },
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        SpeedError::Transport {
            cause: TransportError::Timeout
        }
    );
    assert!(started.elapsed() <= Duration::from_secs(7));
}

#[tokio::test(start_paused = true)]
async fn an_invalid_test_id_is_refused_before_any_traffic() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let error = client(&fake)
        .download(
            &s,
            None,
            &ThroughputOptions {
                test_id: Some("has space".into()),
                ..quick(1, 1, 0)
            },
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, SpeedError::InvalidInput(_)));
    assert!(fake.calls().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_vanished_progress_receiver_cancels_the_run() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let (mut tx, rx) = mpsc::channel::<SpeedProgress>(1);
    drop(rx);
    let error = client(&fake)
        .download(&s, None, &quick(2, 5, 0), &CancelToken::new(), &mut tx)
        .await
        .unwrap_err();
    assert_eq!(error, SpeedError::Cancelled);
}

// ------------------------------------------------------------- cancellation

#[tokio::test]
async fn cancel_stops_all_traffic_immediately() {
    // Real clock: 50 MB/s per stream, 4 streams, a 20 s run that we cancel after 300 ms.
    let fake = FakeTransport::new();
    fake.set_rate(50_000_000);
    let s = server("a.example:443");
    let c = client(&fake);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let handle = tokio::spawn(async move {
        c.download(&s, None, &quick(4, 20, 2), &task_cancel, &mut NullSink)
            .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(fake.bytes_moved() > 0, "the transfer never started");

    let cancelled_at = std::time::Instant::now();
    cancel.cancel();
    let result = handle.await.unwrap();
    assert_eq!(result.unwrap_err(), SpeedError::Cancelled);
    assert!(
        cancelled_at.elapsed() < Duration::from_millis(250),
        "cancel took {:?}",
        cancelled_at.elapsed()
    );
    let at_return = fake.bytes_moved();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fake.bytes_moved(),
        at_return,
        "bytes kept flowing after cancel"
    );
}

#[tokio::test]
async fn an_already_cancelled_token_moves_nothing() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let cancel = CancelToken::new();
    cancel.cancel();
    let error = client(&fake)
        .download(&s, None, &quick(4, 5, 0), &cancel, &mut NullSink)
        .await
        .unwrap_err();
    assert_eq!(error, SpeedError::Cancelled);
    assert_eq!(fake.bytes_moved(), 0);
}

// ----------------------------------------------------------------- 429 / budget

#[tokio::test(start_paused = true)]
async fn a_429_fails_fast_with_the_retry_after_and_is_not_retried() {
    let fake = FakeTransport::new();
    fake.fail_transfers_with(Some(TransportError::Status {
        status: 429,
        retry_after_secs: Some(42),
        message: Some("too many tests".into()),
    }));
    let s = server("a.example:443");
    let started = Instant::now();
    let error = client(&fake)
        .download(
            &s,
            None,
            &quick(4, 10, 2),
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        SpeedError::RateLimited {
            retry_after_secs: Some(42)
        }
    );
    // One request per stream, never a second one, and the run did not wait for its 12 s.
    assert_eq!(fake.calls_of(CallKind::Download).len(), 4);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn a_429_on_a_bin_test_and_on_a_ping_also_fails_fast() {
    let fake = FakeTransport::new();
    fake.fail_transfers_with(Some(TransportError::Status {
        status: 429,
        retry_after_secs: Some(3),
        message: None,
    }));
    let s = server("a.example:443");
    let mut bin = BinOptions::new(BinSize::OneGib);
    bin.scale = 0.001;
    let error = client(&fake)
        .bin_test(&s, None, &bin, &CancelToken::new(), &mut NullSink)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        SpeedError::RateLimited {
            retry_after_secs: Some(3)
        }
    );

    let ping_fake = FakeTransport::new();
    ping_fake.set_ping_script(
        "a.example:443",
        vec![
            Ok(Duration::from_millis(5)),
            Err(TransportError::Status {
                status: 429,
                retry_after_secs: Some(9),
                message: None,
            }),
        ],
    );
    let error = client(&ping_fake)
        .latency(
            &s,
            &LatencyOptions::default(),
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        SpeedError::RateLimited {
            retry_after_secs: Some(9)
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_run_that_cannot_fit_the_published_budget_is_refused_before_any_traffic() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let small_budget = info(8, 10 * MIB);
    let mut bin = BinOptions::new(BinSize::OneGib);
    bin.scale = 1.0;
    let error = client(&fake)
        .bin_test(
            &s,
            Some(&small_budget),
            &bin,
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        SpeedError::BudgetExceeded {
            window: BudgetWindow::Hour,
            requested_bytes: 1 << 30,
            limit_bytes: 10 * MIB,
            available_bytes: 10 * MIB,
        }
    );
    assert!(fake.calls().is_empty());
    assert!(error.to_string().contains("hourly"));
}

#[tokio::test(start_paused = true)]
async fn earlier_runs_count_against_the_budget() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let budget = info(8, 10 * MIB);
    let c = client(&fake);
    let mut bin = BinOptions::new(BinSize::OneGib);
    // 6 MiB fits a 10 MiB hourly budget once, not twice.
    bin.scale = 6.0 * MIB as f64 / (1u64 << 30) as f64;
    c.bin_test(&s, Some(&budget), &bin, &CancelToken::new(), &mut NullSink)
        .await
        .unwrap();
    let error = c
        .bin_test(&s, Some(&budget), &bin, &CancelToken::new(), &mut NullSink)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SpeedError::BudgetExceeded {
            window: BudgetWindow::Hour,
            ..
        }
    ));
    // An hour later the window is clear again.
    tokio::time::advance(Duration::from_secs(3601)).await;
    c.bin_test(&s, Some(&budget), &bin, &CancelToken::new(), &mut NullSink)
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_duration_run_checks_its_up_front_request_size_against_the_budget() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    // 4 streams x 512 MiB default requests cannot fit a 100 MiB hourly budget.
    let error = client(&fake)
        .download(
            &s,
            Some(&info(8, 100 * MIB)),
            &quick(4, 5, 0),
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, SpeedError::BudgetExceeded { .. }));
    assert!(fake.calls().is_empty());
}

// ------------------------------------------------------------------- bin tests

#[tokio::test(start_paused = true)]
async fn the_50_gib_test_needs_an_explicit_confirmation() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let c = client(&fake);
    let mut bin = BinOptions::new(BinSize::FiftyGib);
    let expected = SpeedError::ConfirmationRequired {
        size_bytes: 50 << 30,
    };
    let error = c
        .bin_test(&s, None, &bin, &CancelToken::new(), &mut NullSink)
        .await
        .unwrap_err();
    assert_eq!(error, expected);
    // A tiny scale must not be a way around the guard.
    bin.scale = 1e-9;
    let error = c
        .bin_test(&s, None, &bin, &CancelToken::new(), &mut NullSink)
        .await
        .unwrap_err();
    assert_eq!(error, expected);
    assert!(fake.calls().is_empty());

    bin.confirm_large = true;
    bin.scale = 1e-6;
    let result = c
        .bin_test(&s, None, &bin, &CancelToken::new(), &mut NullSink)
        .await
        .unwrap();
    assert_eq!(result.size_bytes, 50 << 30);
    assert_eq!(result.bytes, ((50u64 << 30) as f64 * 1e-6).ceil() as u64);
}

#[tokio::test(start_paused = true)]
async fn smaller_bin_tests_need_no_confirmation_and_split_exactly_over_the_streams() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let c = client(&fake);
    for size in [BinSize::OneGib, BinSize::TenGib] {
        let mut bin = BinOptions::new(size);
        bin.scale = 0.000_01;
        let mut events = Vec::new();
        let result = c
            .bin_test(
                &s,
                Some(&info(8, 0)),
                &bin,
                &CancelToken::new(),
                &mut FnSink(|e| events.push(e)),
            )
            .await
            .unwrap();
        let wanted = (size.bytes() as f64 * 0.000_01).ceil() as u64;
        assert_eq!(result.size_bytes, size.bytes());
        assert_eq!(result.bytes, wanted);
        assert_eq!(result.streams, 4);
        assert!(valid_test_id(&result.test_id));
        assert!(result.avg_mbps > 0.0 && result.peak_mbps >= result.avg_mbps);
        assert!(matches!(
            events[0],
            SpeedProgress::Phase {
                phase: SpeedPhase::BinDownload
            }
        ));
    }
    // Both runs: every download call is one stream's part; the parts of a run sum to its size.
    let calls = fake.calls_of(CallKind::Download);
    assert_eq!(calls.len(), 8);
    let first: u64 = calls[..4].iter().map(|c| c.bytes).sum();
    assert_eq!(
        first,
        (BinSize::OneGib.bytes() as f64 * 0.000_01).ceil() as u64
    );
    let sizes: Vec<u64> = calls[..4].iter().map(|c| c.bytes).collect();
    assert!(sizes.iter().max().unwrap() - sizes.iter().min().unwrap() <= 1);
    // One test id per run, shared by its streams.
    assert!(calls[..4].iter().all(|c| c.test_id == calls[0].test_id));
    assert!(calls[4..].iter().all(|c| c.test_id == calls[4].test_id));
    assert_ne!(calls[0].test_id, calls[4].test_id);
}

#[tokio::test(start_paused = true)]
async fn bin_progress_ends_at_the_total_and_cancel_works() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    let mut bin = BinOptions::new(BinSize::OneGib);
    bin.scale = 8_000_000.0 / (1u64 << 30) as f64; // about 8 MB at 4 x 1 MB/s: 2 s
    let mut events = Vec::new();
    let result = client(&fake)
        .bin_test(
            &s,
            None,
            &bin,
            &CancelToken::new(),
            &mut FnSink(|e| events.push(e)),
        )
        .await
        .unwrap();
    let bins: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SpeedProgress::Bin {
                bytes_done,
                bytes_total,
                ..
            } => Some((*bytes_done, *bytes_total)),
            _ => None,
        })
        .collect();
    assert!(!bins.is_empty());
    assert!(bins
        .iter()
        .all(|(done, total)| done <= total && *total == result.bytes));
    assert!(
        result.duration_ms >= 1900 && result.duration_ms <= 2200,
        "{}",
        result.duration_ms
    );

    // Cancel a bin test mid-way.
    let fake = FakeTransport::new();
    let c = client(&fake);
    let cancel = CancelToken::new();
    let mut big = BinOptions::new(BinSize::OneGib);
    big.scale = 0.01;
    let canceller = cancel.clone();
    let mut sink = NullSink;
    let run = c.bin_test(&s, None, &big, &cancel, &mut sink);
    let stop = async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        canceller.cancel();
    };
    let (outcome, ()) = tokio::join!(run, stop);
    assert_eq!(outcome.unwrap_err(), SpeedError::Cancelled);
    let after = fake.bytes_moved();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(fake.bytes_moved(), after);
}

#[tokio::test(start_paused = true)]
async fn a_bad_scale_is_refused() {
    let fake = FakeTransport::new();
    let s = server("a.example:443");
    for scale in [0.0, -1.0, 1.5, f64::NAN, f64::INFINITY] {
        let mut bin = BinOptions::new(BinSize::OneGib);
        bin.scale = scale;
        let error = client(&fake)
            .bin_test(&s, None, &bin, &CancelToken::new(), &mut NullSink)
            .await
            .unwrap_err();
        assert!(matches!(error, SpeedError::InvalidInput(_)), "{scale}");
    }
}

// ---------------------------------------------------------------------- picker

fn pick_fixture() -> (FakeTransport, Vec<ServerEndpoint>) {
    let fake = FakeTransport::new();
    fake.set_latency("slow.example:443", Duration::from_millis(80));
    fake.set_latency("fast.example:443", Duration::from_millis(12));
    fake.set_latency("mid.example:443", Duration::from_millis(30));
    // dead.example has no script: every ping times out.
    let servers = ["slow", "dead", "fast", "mid"]
        .iter()
        .map(|n| server(&format!("{n}.example:443")))
        .collect();
    (fake, servers)
}

#[tokio::test(start_paused = true)]
async fn the_picker_chooses_the_lowest_latency_and_skips_dead_servers() {
    let (fake, servers) = pick_fixture();
    let result = client(&fake)
        .pick_server(&servers, &PickOptions::default(), &CancelToken::new())
        .await
        .unwrap();
    assert_eq!(result.best().unwrap().host, "fast.example");
    assert_eq!(result.probes.len(), 4);
    // Input order is preserved; the dead server is reported with a reason and no latency.
    assert_eq!(result.probes[1].server.host, "dead.example");
    assert_eq!(result.probes[1].latency_ms, None);
    assert!(result.probes[1].error.is_some());
    near(result.probes[2].latency_ms.unwrap(), 12.0, 1e-6);
}

#[tokio::test(start_paused = true)]
async fn the_picker_uses_the_best_of_its_probes_and_survives_a_flaky_first_ping() {
    let fake = FakeTransport::new();
    fake.set_ping_script(
        "a.example:443",
        vec![
            Err(TransportError::Timeout),
            Ok(Duration::from_millis(40)),
            Ok(Duration::from_millis(25)),
        ],
    );
    fake.set_latency("b.example:443", Duration::from_millis(30));
    let servers = vec![server("a.example:443"), server("b.example:443")];
    let result = client(&fake)
        .pick_server(&servers, &PickOptions::default(), &CancelToken::new())
        .await
        .unwrap();
    assert_eq!(result.best().unwrap().host, "a.example");
    near(result.probes[0].latency_ms.unwrap(), 25.0, 1e-6);
}

#[tokio::test(start_paused = true)]
async fn an_empty_or_all_dead_list_has_no_winner_and_is_not_an_error() {
    let fake = FakeTransport::new();
    let c = client(&fake);
    let empty = c
        .pick_server(&[], &PickOptions::default(), &CancelToken::new())
        .await
        .unwrap();
    assert!(empty.best().is_none() && empty.probes.is_empty());
    let dead = c
        .pick_server(
            &[server("x.example:443")],
            &PickOptions::default(),
            &CancelToken::new(),
        )
        .await
        .unwrap();
    assert!(dead.best().is_none());
    assert_eq!(dead.probes.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn equal_latencies_pick_the_first_listed() {
    let fake = FakeTransport::new();
    fake.set_latency("a.example:443", Duration::from_millis(10));
    fake.set_latency("b.example:443", Duration::from_millis(10));
    let servers = vec![server("b.example:443"), server("a.example:443")];
    let result = client(&fake)
        .pick_server(&servers, &PickOptions::default(), &CancelToken::new())
        .await
        .unwrap();
    assert_eq!(result.best, Some(0));
}

#[tokio::test(start_paused = true)]
async fn the_picker_probes_in_parallel() {
    // Every ping takes 0 virtual time in the fake, so check structurally: all servers were pinged `probes` times.
    let (fake, servers) = pick_fixture();
    client(&fake)
        .pick_server(
            &servers,
            &PickOptions {
                probes: 2,
                ..PickOptions::default()
            },
            &CancelToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(fake.calls_of(CallKind::Ping).len(), 8);
}

// ------------------------------------------------------------ latency / full run

#[tokio::test(start_paused = true)]
async fn latency_reports_loss_jitter_and_ignores_the_warm_up_ping() {
    let fake = FakeTransport::new();
    let ms = Duration::from_millis;
    fake.set_ping_script(
        "a.example:443",
        vec![
            Ok(ms(500)), // warm-up ping: not part of the result
            Ok(ms(10)),
            Ok(ms(14)),
            Err(TransportError::Timeout),
            Ok(ms(12)),
        ],
    );
    let s = server("a.example:443");
    let mut events = Vec::new();
    let result = client(&fake)
        .latency(
            &s,
            &LatencyOptions {
                count: 4,
                ..LatencyOptions::default()
            },
            &CancelToken::new(),
            &mut FnSink(|e| events.push(e)),
        )
        .await
        .unwrap();
    assert_eq!((result.sent, result.received, result.failed), (4, 3, 1));
    near(result.loss_percent, 25.0, 1e-9);
    near(result.min_ms.unwrap(), 10.0, 1e-6);
    near(result.max_ms.unwrap(), 14.0, 1e-6);
    near(result.jitter_ms.unwrap(), 3.0, 1e-6);
    let pings: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SpeedProgress::Ping { seq, rtt_ms } => Some((*seq, rtt_ms.is_some())),
            _ => None,
        })
        .collect();
    assert_eq!(pings, vec![(1, true), (2, true), (3, false), (4, true)]);
}

#[tokio::test(start_paused = true)]
async fn the_full_run_reports_the_source_ip_from_the_chosen_server() {
    let fake = FakeTransport::new();
    fake.set_latency("near.example:443", Duration::from_millis(10));
    fake.set_latency("far.example:443", Duration::from_millis(90));
    fake.set_info("near.example:443", Ok(info(8, 100 << 30)));
    let servers = vec![server("far.example:443"), server("near.example:443")];
    let options = RunOptions {
        download: Some(ThroughputOptions {
            max_bytes: Some(2 * MIB),
            ..quick(2, 2, 0)
        }),
        upload: None,
        ..RunOptions::default()
    };
    let result = client(&fake)
        .run(&servers, &options, &CancelToken::new(), &mut NullSink)
        .await
        .unwrap();
    assert_eq!(result.server.authority, "near.example:443");
    assert_eq!(result.server.name, "Miami");
    assert_eq!(result.server.location.as_deref(), Some("Miami, US"));
    assert_eq!(result.source_ip, Some("203.0.113.9".parse().unwrap()));
    assert_eq!(result.servers_probed.len(), 2);
    assert!(result.latency.is_some() && result.download.is_some() && result.upload.is_none());
    // The JSON form is what the engine will forward.
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["source_ip"], "203.0.113.9");
}

#[tokio::test(start_paused = true)]
async fn without_an_info_answer_the_source_ip_is_omitted_but_the_test_still_runs() {
    let fake = FakeTransport::new();
    fake.set_latency("a.example:443", Duration::from_millis(10));
    let options = RunOptions {
        download: Some(ThroughputOptions {
            max_bytes: Some(MIB),
            ..quick(1, 1, 0)
        }),
        upload: None,
        latency: None,
        ..RunOptions::default()
    };
    let result = client(&fake)
        .run(
            &[server("a.example:443")],
            &options,
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap();
    assert_eq!(result.source_ip, None);
    assert!(result.download.is_some());
    let json = serde_json::to_value(&result).unwrap();
    assert!(json["source_ip"].is_null());
}

#[tokio::test(start_paused = true)]
async fn no_candidates_or_no_answers_is_no_server() {
    let fake = FakeTransport::new();
    let c = client(&fake);
    for list in [vec![], vec![server("dead.example:443")]] {
        let error = c
            .run(
                &list,
                &RunOptions::default(),
                &CancelToken::new(),
                &mut NullSink,
            )
            .await
            .unwrap_err();
        assert_eq!(error, SpeedError::NoServer);
    }
    assert!(fake.calls_of(CallKind::Download).is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_future_of_a_run_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    let fake = FakeTransport::new();
    let c = client(&fake);
    let cancel = CancelToken::new();
    let s = server("a.example:443");
    let candidates = [s.clone()];
    let options = RunOptions::default();
    let mut sink = NullSink;
    assert_send(&c.run(&candidates, &options, &cancel, &mut sink));
    assert_send(&c.bin_test(
        &s,
        None,
        &BinOptions::new(BinSize::OneGib),
        &cancel,
        &mut sink,
    ));
    assert_send(&c.pick_server(&candidates, &PickOptions::default(), &cancel));
}

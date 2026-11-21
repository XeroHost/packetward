// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Multi-stream transfers: the engine shared by the duration-based download/upload and the bin tests.
//!
//! One run = N parallel streams, each a loop of bounded `/download` or `/upload` requests that all carry the same
//! `?test=<id>`. The streams add to one [`ByteMeter`]; this module samples it once per bucket, feeds the pure
//! functions of [`math`](super::math), and reports progress. Dropping the stream futures (cancel, deadline, first
//! error) closes their connections.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::{interval_at, sleep_until, Instant, MissedTickBehavior};

use crate::{CancelToken, Sink};

use super::client::{emit, SpeedClient};
use super::error::{SpeedError, TransportError};
use super::math::{mbps, measure, Sample};
use super::result::{Direction, SpeedPhase, SpeedProgress, ThroughputResult};
use super::server::{new_test_id, valid_test_id, ServerEndpoint, ServerInfo};
use super::transport::{ByteMeter, DownloadRequest, SpeedTransport, UploadRequest};

/// Hard upper bound on parallel streams.
pub const MAX_STREAMS: usize = 16;
const MIB: u64 = 1 << 20;
const DEFAULT_DOWNLOAD_REQUEST: u64 = 512 * MIB;
const DEFAULT_UPLOAD_REQUEST: u64 = 256 * MIB;

/// Options of a duration-based download or upload. Out-of-range values are clamped by `normalized()` rules
/// described per field.
#[derive(Debug, Clone)]
pub struct ThroughputOptions {
    /// Parallel streams, 1..=16 (and no more than the server's `max_streams_per_test`). Default 4.
    pub streams: usize,
    /// Measured duration after the warm-up, 1 s..=120 s. Default 10 s.
    pub duration: Duration,
    /// Warm-up excluded from the result, at most 10 s. Default 2 s.
    pub warmup: Duration,
    /// Optional cap on the total bytes of the run (warm-up included); the run ends early when reached. Shared out
    /// equally over the streams.
    pub max_bytes: Option<u64>,
    /// Bytes per request. Defaults to 512 MiB (download) / 256 MiB (upload), large enough that a fast link does not
    /// hit the server's request-rate limit; clamped to the server's published maximum.
    pub request_bytes: Option<u64>,
    /// Sampling bucket, 50 ms..=5 s. Default 1 s.
    pub bucket: Duration,
    /// Fail when no byte moved for this long, 1 s..=120 s. Default 15 s.
    pub stall_timeout: Duration,
    /// Use this `?test=` id instead of a fresh random one (1-64 characters of `A-Za-z0-9_-`).
    pub test_id: Option<String>,
}

impl Default for ThroughputOptions {
    fn default() -> Self {
        Self {
            streams: 4,
            duration: Duration::from_secs(10),
            warmup: Duration::from_secs(2),
            max_bytes: None,
            request_bytes: None,
            bucket: Duration::from_secs(1),
            stall_timeout: Duration::from_secs(15),
            test_id: None,
        }
    }
}

impl ThroughputOptions {
    fn normalized(&self) -> Self {
        Self {
            streams: self.streams.clamp(1, MAX_STREAMS),
            duration: self
                .duration
                .clamp(Duration::from_secs(1), Duration::from_secs(120)),
            warmup: self.warmup.min(Duration::from_secs(10)),
            max_bytes: self.max_bytes.map(|b| b.max(1)),
            request_bytes: self.request_bytes.map(|b| b.max(1)),
            bucket: self
                .bucket
                .clamp(Duration::from_millis(50), Duration::from_secs(5)),
            stall_timeout: self
                .stall_timeout
                .clamp(Duration::from_secs(1), Duration::from_secs(120)),
            test_id: self.test_id.clone(),
        }
    }
}

/// A pool of bytes still to be requested. Shared by the streams of a duration run (`u64::MAX` = unlimited) or
/// owned by one stream of a bin test.
#[derive(Debug)]
pub(crate) struct Quota(AtomicU64);

impl Quota {
    pub(crate) fn new(bytes: u64) -> Self {
        Self(AtomicU64::new(bytes))
    }

    /// Take up to `want` bytes; `0` means the pool is empty.
    pub(crate) fn take(&self, want: u64) -> u64 {
        match self
            .0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                Some(left - left.min(want))
            }) {
            Ok(previous) | Err(previous) => previous.min(want),
        }
    }
}

/// Everything the engine needs to run one transfer.
pub(crate) struct Run {
    pub direction: Direction,
    /// One quota per stream (clones of one `Arc` for a duration run).
    pub quotas: Vec<Arc<Quota>>,
    /// Largest single request.
    pub chunk: u64,
    pub test_id: String,
    pub warmup: Duration,
    /// Stop after this long; `None` = run until the streams are out of bytes.
    pub duration: Option<Duration>,
    pub bucket: Duration,
    pub stall: Duration,
    /// `Some` for a bin test: reported as `Bin` progress.
    pub bin_total: Option<u64>,
}

pub(crate) struct Outcome {
    pub samples: Vec<Sample>,
    pub total_bytes: u64,
}

fn join_failure(error: &tokio::task::JoinError) -> SpeedError {
    tracing::debug!(%error, "speed stream task failed");
    SpeedError::Transport {
        cause: TransportError::Io("a stream task failed".to_owned()),
    }
}

/// Parallel streams to use: the requested count within 1..=16 and the server's published per-test limit.
pub(crate) fn effective_streams(requested: usize, info: Option<&ServerInfo>) -> usize {
    let streams = requested.clamp(1, MAX_STREAMS);
    match info.and_then(ServerInfo::stream_limit) {
        Some(limit) => streams.min(limit.max(1)),
        None => streams,
    }
}

pub(crate) fn resolve_test_id(requested: Option<&String>) -> Result<String, SpeedError> {
    match requested {
        Some(id) if valid_test_id(id) => Ok(id.clone()),
        Some(_) => Err(SpeedError::InvalidInput(
            "the test id must be 1-64 characters of A-Z, a-z, 0-9, '-' and '_'".to_owned(),
        )),
        None => Ok(new_test_id()),
    }
}

impl<T: SpeedTransport> SpeedClient<T> {
    /// Multi-stream download for a fixed duration (warm-up excluded from the result). `info` (from
    /// [`server_info`](SpeedClient::server_info)) enables the server's published limits; pass `None` when the
    /// server did not answer `/info`.
    pub async fn download<S: Sink<SpeedProgress>>(
        &self,
        server: &ServerEndpoint,
        info: Option<&ServerInfo>,
        options: &ThroughputOptions,
        cancel: &CancelToken,
        sink: &mut S,
    ) -> Result<ThroughputResult, SpeedError> {
        self.throughput(Direction::Download, server, info, options, cancel, sink)
            .await
    }

    /// Multi-stream upload for a fixed duration (warm-up excluded). Data is generated from one reusable buffer.
    pub async fn upload<S: Sink<SpeedProgress>>(
        &self,
        server: &ServerEndpoint,
        info: Option<&ServerInfo>,
        options: &ThroughputOptions,
        cancel: &CancelToken,
        sink: &mut S,
    ) -> Result<ThroughputResult, SpeedError> {
        self.throughput(Direction::Upload, server, info, options, cancel, sink)
            .await
    }

    async fn throughput<S: Sink<SpeedProgress>>(
        &self,
        direction: Direction,
        server: &ServerEndpoint,
        info: Option<&ServerInfo>,
        options: &ThroughputOptions,
        cancel: &CancelToken,
        sink: &mut S,
    ) -> Result<ThroughputResult, SpeedError> {
        let options = options.normalized();
        let test_id = resolve_test_id(options.test_id.as_ref())?;
        let streams = effective_streams(options.streams, info);
        let (default_chunk, server_max) = match direction {
            Direction::Download => (
                DEFAULT_DOWNLOAD_REQUEST,
                info.map_or(0, |i| i.max_download_bytes),
            ),
            Direction::Upload => (
                DEFAULT_UPLOAD_REQUEST,
                info.map_or(0, |i| i.max_upload_bytes),
            ),
        };
        let mut chunk = options.request_bytes.unwrap_or(default_chunk);
        if server_max > 0 {
            chunk = chunk.min(server_max);
        }
        if let Some(cap) = options.max_bytes {
            // Share the cap out equally so every stream gets work.
            chunk = chunk.min(cap.div_ceil(streams as u64).max(1));
        }
        if let Some(info) = info {
            let needed = options
                .max_bytes
                .unwrap_or_else(|| chunk.saturating_mul(streams as u64));
            self.ledger
                .check(&server.authority(), needed, &info.limits, Instant::now())?;
        }
        let quota = Arc::new(Quota::new(options.max_bytes.unwrap_or(u64::MAX)));
        let run = Run {
            direction,
            quotas: vec![quota; streams],
            chunk,
            test_id: test_id.clone(),
            warmup: options.warmup,
            duration: Some(options.duration),
            bucket: options.bucket,
            stall: options.stall_timeout,
            bin_total: None,
        };
        emit(
            sink,
            SpeedProgress::Phase {
                phase: match direction {
                    Direction::Download => SpeedPhase::Download,
                    Direction::Upload => SpeedPhase::Upload,
                },
            },
        )
        .await?;
        let outcome = self.drive(server, run, cancel, sink).await?;
        let measured = measure(&outcome.samples, options.warmup, options.bucket / 2);
        Ok(ThroughputResult {
            direction,
            streams: streams as u32,
            avg_mbps: measured.avg_mbps,
            peak_mbps: measured.peak_mbps,
            bytes: measured.bytes,
            total_bytes: outcome.total_bytes,
            duration_ms: millis(measured.duration),
            warmup_ms: millis(measured.warmup),
            buckets_mbps: measured.buckets_mbps,
            test_id,
        })
    }

    /// Run the streams, sample, report progress, enforce cancellation. Records the bytes moved in the budget
    /// ledger however the run ends.
    pub(crate) async fn drive<S: Sink<SpeedProgress>>(
        &self,
        server: &ServerEndpoint,
        run: Run,
        cancel: &CancelToken,
        sink: &mut S,
    ) -> Result<Outcome, SpeedError> {
        let meter = ByteMeter::new();
        let result = self.drive_inner(server, run, &meter, cancel, sink).await;
        self.ledger
            .record(&server.authority(), meter.total(), Instant::now());
        result
    }

    async fn drive_inner<S: Sink<SpeedProgress>>(
        &self,
        server: &ServerEndpoint,
        run: Run,
        meter: &ByteMeter,
        cancel: &CancelToken,
        sink: &mut S,
    ) -> Result<Outcome, SpeedError> {
        let server = Arc::new(server.clone());
        let test_id: Arc<str> = Arc::from(run.test_id.as_str());
        let start = Instant::now();
        let mut set: JoinSet<Result<(), SpeedError>> = JoinSet::new();
        for quota in &run.quotas {
            set.spawn(stream_task(
                Arc::clone(&self.transport),
                Arc::clone(&server),
                run.direction,
                Arc::clone(&test_id),
                meter.clone(),
                Arc::clone(quota),
                run.chunk,
            ));
        }

        let deadline = run.duration.map(|d| start + run.warmup + d);
        let timer = sleep_until(deadline.unwrap_or(start + Duration::from_secs(86_400)));
        tokio::pin!(timer);
        let mut ticker = interval_at(start + run.bucket, run.bucket);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut samples: Vec<Sample> = Vec::new();
        let mut last = Sample {
            at: Duration::ZERO,
            bytes: 0,
        };
        let mut last_move = start;
        let outcome: Result<(), SpeedError> = loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break Err(SpeedError::Cancelled),
                joined = set.join_next() => match joined {
                    None => break Ok(()),
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(error)) => break Err(join_failure(&error)),
                },
                () = &mut timer, if deadline.is_some() => break Ok(()),
                _ = ticker.tick() => {
                    let now = Instant::now();
                    let sample = Sample { at: now - start, bytes: meter.total() };
                    samples.push(sample);
                    if sample.bytes != last.bytes {
                        last_move = now;
                    } else if now - last_move >= run.stall {
                        break Err(SpeedError::Transport { cause: TransportError::Timeout });
                    }
                    let bucket_mbps = mbps(sample.bytes - last.bytes, sample.at.saturating_sub(last.at));
                    last = sample;
                    let event = progress_event(&run, &samples, sample, bucket_mbps);
                    if let Err(error) = emit(sink, event).await {
                        break Err(error);
                    }
                    if deadline.is_some_and(|d| now >= d) {
                        break Ok(());
                    }
                }
            }
        };
        if outcome.is_ok() {
            let now = start.elapsed();
            if samples.last().is_none_or(|s| s.at < now) {
                samples.push(Sample {
                    at: now,
                    bytes: meter.total(),
                });
            }
        }
        // Abort every stream and wait until the futures are really gone: after this nothing moves any more.
        set.abort_all();
        while set.join_next().await.is_some() {}
        outcome?;
        Ok(Outcome {
            samples,
            total_bytes: meter.total(),
        })
    }
}

fn progress_event(
    run: &Run,
    samples: &[Sample],
    sample: Sample,
    bucket_mbps: f64,
) -> SpeedProgress {
    match run.bin_total {
        Some(total) => SpeedProgress::Bin {
            bytes_done: sample.bytes,
            bytes_total: total,
            mbps: bucket_mbps,
            avg_mbps: mbps(sample.bytes, sample.at),
            elapsed_ms: millis(sample.at),
        },
        None => SpeedProgress::Throughput {
            direction: run.direction,
            elapsed_ms: millis(sample.at),
            warmup: sample.at <= run.warmup,
            mbps: bucket_mbps,
            avg_mbps: if sample.at > run.warmup {
                measure(samples, run.warmup, run.bucket / 2).avg_mbps
            } else {
                0.0
            },
            bytes: sample.bytes,
        },
    }
}

pub(crate) fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// One stream: bounded requests until its quota is empty.
async fn stream_task<T: SpeedTransport>(
    transport: Arc<T>,
    server: Arc<ServerEndpoint>,
    direction: Direction,
    test_id: Arc<str>,
    meter: ByteMeter,
    quota: Arc<Quota>,
    chunk: u64,
) -> Result<(), SpeedError> {
    loop {
        let bytes = quota.take(chunk);
        if bytes == 0 {
            return Ok(());
        }
        match direction {
            Direction::Download => {
                let request = DownloadRequest {
                    bytes,
                    test_id: &test_id,
                };
                let received = transport.download(&server, &request, &meter).await?;
                if received != bytes {
                    return Err(SpeedError::Incomplete {
                        expected: bytes,
                        received,
                    });
                }
            }
            Direction::Upload => {
                let request = UploadRequest {
                    bytes,
                    test_id: &test_id,
                };
                let acknowledged = transport.upload(&server, &request, &meter).await?;
                if acknowledged != bytes {
                    tracing::warn!(
                        sent = bytes,
                        acknowledged,
                        "upload byte count differs from the server's"
                    );
                }
            }
        }
    }
}

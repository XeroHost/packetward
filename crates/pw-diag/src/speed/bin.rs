// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Bin tests: download a fixed amount of data (1, 10 or 50 GiB) split over the streams.
//!
//! Sizes are binary (1 GiB = 2^30 bytes): the server's default `max_download_bytes` is exactly 50 GiB. The 50 GiB
//! test moves a lot of data and time, so it refuses to start without `confirm_large: true` (the UI shows the
//! bandwidth/time warning first). The run is also refused up front when it cannot fit the server's published
//! per-IP budget, and a 429 stops it at once.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::{CancelToken, Sink};

use super::client::{emit, SpeedClient};
use super::error::SpeedError;
use super::math::measure;
use super::result::{BinResult, Direction, SpeedPhase, SpeedProgress};
use super::server::{ServerEndpoint, ServerInfo};
use super::throughput::{effective_streams, millis, resolve_test_id, Quota, Run};
use super::transport::SpeedTransport;

const GIB: u64 = 1 << 30;
/// Largest single `/download` request of a bin test (further clamped to the server's published maximum).
const MAX_REQUEST: u64 = 4 * GIB;

/// The fixed sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinSize {
    /// 1 GiB.
    OneGib,
    /// 10 GiB.
    TenGib,
    /// 50 GiB. Needs `confirm_large`.
    FiftyGib,
}

impl BinSize {
    /// Nominal size in bytes.
    pub fn bytes(self) -> u64 {
        match self {
            BinSize::OneGib => GIB,
            BinSize::TenGib => 10 * GIB,
            BinSize::FiftyGib => 50 * GIB,
        }
    }

    /// Whether the user must confirm explicitly.
    pub fn needs_confirmation(self) -> bool {
        self == BinSize::FiftyGib
    }
}

/// Bin test options.
#[derive(Debug, Clone)]
pub struct BinOptions {
    /// Which size.
    pub size: BinSize,
    /// Must be `true` for [`BinSize::FiftyGib`]; otherwise the call fails with
    /// [`SpeedError::ConfirmationRequired`] before any traffic. The guard looks at the nominal size, so a `scale`
    /// cannot be used to dodge it.
    pub confirm_large: bool,
    /// Fraction of the nominal size actually transferred, `0 < scale <= 1`. `1.0` in production; tests use tiny
    /// values to exercise the 10/50 GiB logic without moving gigabytes.
    pub scale: f64,
    /// Parallel streams, 1..=16 (and the server's limit). Default 4.
    pub streams: usize,
    /// Progress/sampling bucket, 50 ms..=5 s. Default 1 s.
    pub bucket: Duration,
    /// Fail when no byte moved for this long, 1 s..=120 s. Default 30 s.
    pub stall_timeout: Duration,
    /// Use this `?test=` id instead of a fresh one.
    pub test_id: Option<String>,
}

impl BinOptions {
    /// Default options for `size`.
    pub fn new(size: BinSize) -> Self {
        Self {
            size,
            confirm_large: false,
            scale: 1.0,
            streams: 4,
            bucket: Duration::from_secs(1),
            stall_timeout: Duration::from_secs(30),
            test_id: None,
        }
    }
}

/// `total` split over `n` streams: the parts differ by at most one byte and sum exactly to `total`.
pub(crate) fn split_evenly(total: u64, n: u64) -> Vec<u64> {
    let n = n.max(1);
    let base = total / n;
    let extra = total % n;
    (0..n).map(|i| base + u64::from(i < extra)).collect()
}

impl<T: SpeedTransport> SpeedClient<T> {
    /// Download a fixed amount of data over parallel streams, with progress, average and peak rate and duration.
    pub async fn bin_test<S: Sink<SpeedProgress>>(
        &self,
        server: &ServerEndpoint,
        info: Option<&ServerInfo>,
        options: &BinOptions,
        cancel: &CancelToken,
        sink: &mut S,
    ) -> Result<BinResult, SpeedError> {
        if options.size.needs_confirmation() && !options.confirm_large {
            return Err(SpeedError::ConfirmationRequired {
                size_bytes: options.size.bytes(),
            });
        }
        if !(options.scale.is_finite() && options.scale > 0.0 && options.scale <= 1.0) {
            return Err(SpeedError::InvalidInput(
                "the scale must be above 0 and at most 1".to_owned(),
            ));
        }
        let test_id = resolve_test_id(options.test_id.as_ref())?;
        let size_bytes = options.size.bytes();
        let total = ((size_bytes as f64 * options.scale).ceil() as u64).clamp(1, size_bytes);
        let streams = effective_streams(options.streams, info)
            .min(usize::try_from(total).unwrap_or(usize::MAX));
        let mut chunk = MAX_REQUEST;
        if let Some(info) = info {
            if info.max_download_bytes > 0 {
                chunk = chunk.min(info.max_download_bytes);
            }
            self.ledger
                .check(&server.authority(), total, &info.limits, Instant::now())?;
        }
        let bucket = options
            .bucket
            .clamp(Duration::from_millis(50), Duration::from_secs(5));
        let run = Run {
            direction: Direction::Download,
            quotas: split_evenly(total, streams as u64)
                .into_iter()
                .map(|part| Arc::new(Quota::new(part)))
                .collect(),
            chunk,
            test_id: test_id.clone(),
            warmup: Duration::ZERO,
            duration: None,
            bucket,
            stall: options
                .stall_timeout
                .clamp(Duration::from_secs(1), Duration::from_secs(120)),
            bin_total: Some(total),
        };
        emit(
            sink,
            SpeedProgress::Phase {
                phase: SpeedPhase::BinDownload,
            },
        )
        .await?;
        let outcome = self.drive(server, run, cancel, sink).await?;
        let measured = measure(&outcome.samples, Duration::ZERO, bucket / 2);
        Ok(BinResult {
            size_bytes,
            bytes: outcome.total_bytes,
            streams: streams as u32,
            duration_ms: millis(measured.duration),
            avg_mbps: measured.avg_mbps,
            peak_mbps: measured.peak_mbps,
            buckets_mbps: measured.buckets_mbps,
            test_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_binary() {
        assert_eq!(BinSize::OneGib.bytes(), 1 << 30);
        assert_eq!(BinSize::TenGib.bytes(), 10 << 30);
        assert_eq!(BinSize::FiftyGib.bytes(), 50 << 30);
        assert!(BinSize::FiftyGib.needs_confirmation());
        assert!(!BinSize::TenGib.needs_confirmation());
    }

    #[test]
    fn the_split_is_exact_and_even() {
        for (total, n) in [(10u64, 4u64), (3, 4), (50 << 30, 8), (1, 1), (7, 7)] {
            let parts = split_evenly(total, n);
            assert_eq!(parts.len() as u64, n);
            assert_eq!(parts.iter().sum::<u64>(), total);
            let (min, max) = (parts.iter().min().unwrap(), parts.iter().max().unwrap());
            assert!(max - min <= 1);
        }
    }
}

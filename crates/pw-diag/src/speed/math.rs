// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The arithmetic of a speed test, as pure functions: warm-up exclusion, bucketing, peak, latency statistics.

use std::time::Duration;

use super::result::LatencyResult;

/// A reading of the run's cumulative byte counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Time since the transfer started.
    pub at: Duration,
    /// Bytes moved since the transfer started (monotonic).
    pub bytes: u64,
}

/// The measured window of a transfer.
#[derive(Debug, Clone, PartialEq)]
pub struct Measured {
    /// Bytes inside the window.
    pub bytes: u64,
    /// Length of the window.
    pub duration: Duration,
    /// Warm-up that was cut off the front (zero if the run ended before the warm-up did).
    pub warmup: Duration,
    /// Mean rate over the window.
    pub avg_mbps: f64,
    /// Fastest bucket that is at least `min_bucket` long (never below `avg_mbps`).
    pub peak_mbps: f64,
    /// Rate of every bucket in the window, in order.
    pub buckets_mbps: Vec<f64>,
}

/// Megabits per second (1 Mbps = 10^6 bit/s) for `bytes` moved in `elapsed`.
pub fn mbps(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        0.0
    } else {
        bytes as f64 * 8.0 / secs / 1_000_000.0
    }
}

/// Cumulative bytes at time `t`, interpolating linearly between samples. The origin `(0, 0)` is implicit; after
/// the last sample the last value holds.
fn bytes_at(samples: &[Sample], t: Duration) -> f64 {
    let mut previous = Sample {
        at: Duration::ZERO,
        bytes: 0,
    };
    for sample in samples {
        if sample.at >= t {
            let span = sample.at.saturating_sub(previous.at);
            if span.is_zero() {
                return sample.bytes as f64;
            }
            let fraction = t.saturating_sub(previous.at).as_secs_f64() / span.as_secs_f64();
            return previous.bytes as f64
                + (sample.bytes.saturating_sub(previous.bytes)) as f64 * fraction;
        }
        previous = *sample;
    }
    previous.bytes as f64
}

/// Reduce `samples` (cumulative, ascending in time) to the measured window.
///
/// * The first `warmup` of the run is excluded: the window starts at `warmup` (the counter there is interpolated
///   between the two surrounding samples) and ends at the last sample. If the run ended before the warm-up did,
///   nothing would be left, so the whole run is measured and `warmup` of the result is zero.
/// * Buckets are the intervals between consecutive samples inside the window. Because the final sample is taken
///   when the run stops, the last bucket may be short; buckets shorter than `min_bucket` do not count for the peak
///   (a 5 ms sliver can otherwise show an absurd rate), but they are still listed.
pub fn measure(samples: &[Sample], warmup: Duration, min_bucket: Duration) -> Measured {
    let end = match samples.last() {
        Some(last) if !last.at.is_zero() => *last,
        _ => {
            return Measured {
                bytes: 0,
                duration: Duration::ZERO,
                warmup: Duration::ZERO,
                avg_mbps: 0.0,
                peak_mbps: 0.0,
                buckets_mbps: Vec::new(),
            }
        }
    };
    let warmup = if end.at > warmup {
        warmup
    } else {
        Duration::ZERO
    };
    let start_bytes = bytes_at(samples, warmup);
    let bytes = (end.bytes as f64 - start_bytes).max(0.0).round() as u64;
    let duration = end.at - warmup;
    let avg_mbps = mbps(bytes, duration);

    let mut buckets = Vec::new();
    let mut peak: Option<f64> = None;
    let mut longest_short_bucket = 0.0f64;
    let mut previous = (warmup, start_bytes);
    for sample in samples.iter().filter(|s| s.at > warmup) {
        let span = sample.at - previous.0;
        if !span.is_zero() {
            let moved = (sample.bytes as f64 - previous.1).max(0.0);
            let rate = moved * 8.0 / span.as_secs_f64() / 1_000_000.0;
            buckets.push(rate);
            if span >= min_bucket {
                peak = Some(peak.map_or(rate, |p| p.max(rate)));
            } else {
                longest_short_bucket = longest_short_bucket.max(rate);
            }
        }
        previous = (sample.at, sample.bytes as f64);
    }
    // Only slivers (a very short window): fall back to them rather than reporting 0.
    let peak_mbps = peak.unwrap_or(longest_short_bucket).max(avg_mbps);
    Measured {
        bytes,
        duration,
        warmup,
        avg_mbps,
        peak_mbps,
        buckets_mbps: buckets,
    }
}

/// Statistics of a ping series (`None` = the ping failed).
pub fn latency_stats(samples: &[Option<f64>]) -> LatencyResult {
    let answered: Vec<f64> = samples.iter().flatten().copied().collect();
    let sent = samples.len() as u32;
    let received = answered.len() as u32;
    let failed = sent - received;
    let (min_ms, avg_ms, max_ms) = if answered.is_empty() {
        (None, None, None)
    } else {
        (
            answered.iter().copied().reduce(f64::min),
            Some(answered.iter().sum::<f64>() / answered.len() as f64),
            answered.iter().copied().reduce(f64::max),
        )
    };
    let jitter_ms = (answered.len() >= 2).then(|| {
        let total: f64 = answered.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
        total / (answered.len() - 1) as f64
    });
    LatencyResult {
        sent,
        received,
        failed,
        loss_percent: if sent == 0 {
            0.0
        } else {
            f64::from(failed) * 100.0 / f64::from(sent)
        },
        min_ms,
        avg_ms,
        max_ms,
        jitter_ms,
        samples_ms: samples.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);
    const HALF: Duration = Duration::from_millis(500);

    fn sample(secs: f64, bytes: u64) -> Sample {
        Sample {
            at: Duration::from_secs_f64(secs),
            bytes,
        }
    }

    /// 1 MB per second after a slow start: 0.25 MB in the first second, 0.25 MB in the second.
    fn warmup_run() -> Vec<Sample> {
        // seconds:   1        2        3          4          5
        vec![
            sample(1.0, 250_000),
            sample(2.0, 500_000),
            sample(3.0, 1_500_000),
            sample(4.0, 2_500_000),
            sample(5.0, 3_500_000),
        ]
    }

    #[test]
    fn warm_up_is_excluded_from_bytes_duration_and_average() {
        let m = measure(&warmup_run(), 2 * SEC, HALF);
        assert_eq!(m.warmup, 2 * SEC);
        assert_eq!(m.bytes, 3_000_000);
        assert_eq!(m.duration, 3 * SEC);
        // 3 MB in 3 s = 8 Mbit/s. Including the warm-up it would have been 5.6 Mbit/s.
        assert!((m.avg_mbps - 8.0).abs() < 1e-9, "{}", m.avg_mbps);
        assert_eq!(m.buckets_mbps.len(), 3);
        assert!(m.buckets_mbps.iter().all(|b| (b - 8.0).abs() < 1e-9));
    }

    #[test]
    fn a_warm_up_between_two_samples_is_interpolated() {
        // Warm-up of 1.5 s: the counter at 1.5 s is 375 000 (halfway between 250 000 and 500 000).
        let m = measure(&warmup_run(), Duration::from_millis(1500), HALF);
        assert_eq!(m.bytes, 3_500_000 - 375_000);
        assert_eq!(m.duration, Duration::from_millis(3500));
        // First bucket is the 0.5 s remainder of the second second: 125 000 bytes in 0.5 s = 2 Mbit/s.
        assert!((m.buckets_mbps[0] - 2.0).abs() < 1e-9);
        assert_eq!(m.buckets_mbps.len(), 4);
    }

    #[test]
    fn peak_is_the_fastest_bucket_and_slivers_do_not_count() {
        let samples = vec![
            sample(1.0, 100_000),
            sample(2.0, 1_100_000),  // 8 Mbit/s
            sample(3.0, 1_600_000),  // 4 Mbit/s
            sample(3.01, 2_600_000), // a 10 ms sliver at 800 Mbit/s: must not be the peak
        ];
        let m = measure(&samples, Duration::ZERO, HALF);
        assert!((m.peak_mbps - 8.0).abs() < 1e-9, "{}", m.peak_mbps);
        assert_eq!(m.buckets_mbps.len(), 4);
        assert!(m.buckets_mbps[3] > 700.0);
        assert!(m.peak_mbps >= m.avg_mbps);
    }

    #[test]
    fn a_run_shorter_than_the_warm_up_is_measured_whole() {
        let samples = vec![sample(1.0, 1_000_000)];
        let m = measure(&samples, 2 * SEC, HALF);
        assert_eq!(m.warmup, Duration::ZERO);
        assert_eq!(m.bytes, 1_000_000);
        assert!((m.avg_mbps - 8.0).abs() < 1e-9);
    }

    #[test]
    fn no_samples_means_zero_not_a_panic() {
        let m = measure(&[], 2 * SEC, HALF);
        assert_eq!((m.bytes, m.avg_mbps, m.peak_mbps), (0, 0.0, 0.0));
        let m = measure(&[sample(0.0, 0)], Duration::ZERO, HALF);
        assert_eq!(m.bytes, 0);
    }

    #[test]
    fn duplicate_timestamps_do_not_divide_by_zero() {
        let samples = vec![sample(1.0, 1000), sample(1.0, 1000), sample(2.0, 2000)];
        let m = measure(&samples, Duration::ZERO, HALF);
        assert!(m.avg_mbps.is_finite() && m.peak_mbps.is_finite());
        assert_eq!(m.bytes, 2000);
    }

    #[test]
    fn mbps_uses_decimal_megabits() {
        assert!((mbps(125_000, SEC) - 1.0).abs() < 1e-12);
        assert_eq!(mbps(10, Duration::ZERO), 0.0);
    }

    #[test]
    fn latency_statistics() {
        let r = latency_stats(&[Some(10.0), Some(14.0), None, Some(12.0)]);
        assert_eq!((r.sent, r.received, r.failed), (4, 3, 1));
        assert!((r.loss_percent - 25.0).abs() < 1e-9);
        assert_eq!(r.min_ms, Some(10.0));
        assert_eq!(r.max_ms, Some(14.0));
        assert!((r.avg_ms.unwrap() - 12.0).abs() < 1e-9);
        // |14-10| = 4, |12-14| = 2 across the lost ping: mean 3.
        assert!((r.jitter_ms.unwrap() - 3.0).abs() < 1e-9);
        assert_eq!(r.samples_ms.len(), 4);
    }

    #[test]
    fn latency_with_no_answers_or_one_answer() {
        let none = latency_stats(&[None, None]);
        assert_eq!(none.received, 0);
        assert_eq!(none.min_ms, None);
        assert_eq!(none.jitter_ms, None);
        assert!((none.loss_percent - 100.0).abs() < 1e-9);
        let one = latency_stats(&[Some(5.0)]);
        assert_eq!(one.jitter_ms, None);
        assert_eq!(one.avg_ms, Some(5.0));
        assert_eq!(latency_stats(&[]).loss_percent, 0.0);
    }
}

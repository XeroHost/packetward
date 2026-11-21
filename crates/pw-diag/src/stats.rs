// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Bounded-memory round-trip statistics shared by ping and MTR.

use std::time::Duration;

/// Online accumulator for round-trip times, in milliseconds. Memory use is constant no matter how
/// many samples are added.
///
/// * `stddev` is the **sample** standard deviation (Welford, divisor `n - 1`); `0.0` with fewer
///   than two samples.
/// * `jitter` is the **mean absolute difference between successive samples**; `0.0` with fewer
///   than two samples.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RttStats {
    count: u64,
    last_ms: f64,
    min_ms: f64,
    max_ms: f64,
    mean_ms: f64,
    m2: f64,
    jitter_sum_ms: f64,
}

/// A read-only view of [`RttStats`] (all values in milliseconds).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RttSummary {
    /// Number of samples.
    pub count: u64,
    /// Most recent sample.
    pub last_ms: f64,
    /// Smallest sample.
    pub min_ms: f64,
    /// Mean of the samples.
    pub avg_ms: f64,
    /// Largest sample.
    pub max_ms: f64,
    /// Sample standard deviation.
    pub stddev_ms: f64,
    /// Mean absolute successive difference.
    pub jitter_ms: f64,
}

impl RttStats {
    /// Empty accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one sample.
    pub fn add(&mut self, rtt: Duration) {
        self.add_ms(rtt.as_secs_f64() * 1000.0);
    }

    /// Add one sample given in milliseconds. Non-finite or negative values are ignored.
    pub fn add_ms(&mut self, ms: f64) {
        if !ms.is_finite() || ms < 0.0 {
            return;
        }
        if self.count == 0 {
            self.min_ms = ms;
            self.max_ms = ms;
        } else {
            self.min_ms = self.min_ms.min(ms);
            self.max_ms = self.max_ms.max(ms);
            self.jitter_sum_ms += (ms - self.last_ms).abs();
        }
        self.count += 1;
        self.last_ms = ms;
        let delta = ms - self.mean_ms;
        self.mean_ms += delta / self.count as f64;
        self.m2 += delta * (ms - self.mean_ms);
    }

    /// Number of samples so far.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Summary of the samples, or `None` when there are none.
    pub fn summary(&self) -> Option<RttSummary> {
        if self.count == 0 {
            return None;
        }
        let stddev_ms = if self.count < 2 {
            0.0
        } else {
            (self.m2 / (self.count - 1) as f64).max(0.0).sqrt()
        };
        let jitter_ms = if self.count < 2 {
            0.0
        } else {
            self.jitter_sum_ms / (self.count - 1) as f64
        };
        Some(RttSummary {
            count: self.count,
            last_ms: self.last_ms,
            min_ms: self.min_ms,
            avg_ms: self.mean_ms,
            max_ms: self.max_ms,
            stddev_ms,
            jitter_ms,
        })
    }
}

/// Loss percentage in `0.0..=100.0`; `0.0` when nothing was sent.
pub fn loss_percent(sent: u64, received: u64) -> f64 {
    if sent == 0 {
        return 0.0;
    }
    let lost = sent.saturating_sub(received);
    lost as f64 * 100.0 / sent as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn empty_has_no_summary() {
        assert!(RttStats::new().summary().is_none());
    }

    #[test]
    fn single_sample_has_zero_spread() {
        let mut s = RttStats::new();
        s.add_ms(12.5);
        let r = s.summary().unwrap();
        assert_eq!(r.count, 1);
        assert!(close(r.min_ms, 12.5) && close(r.max_ms, 12.5) && close(r.avg_ms, 12.5));
        assert!(close(r.stddev_ms, 0.0) && close(r.jitter_ms, 0.0));
    }

    #[test]
    fn known_series() {
        let mut s = RttStats::new();
        for v in [10.0, 20.0, 30.0, 40.0] {
            s.add_ms(v);
        }
        let r = s.summary().unwrap();
        assert!(close(r.avg_ms, 25.0));
        assert!(close(r.min_ms, 10.0) && close(r.max_ms, 40.0) && close(r.last_ms, 40.0));
        // sample variance = 500/3
        assert!(close(r.stddev_ms, (500.0f64 / 3.0).sqrt()));
        assert!(close(r.jitter_ms, 10.0));
    }

    #[test]
    fn jitter_uses_absolute_successive_differences() {
        let mut s = RttStats::new();
        for v in [10.0, 30.0, 10.0, 30.0] {
            s.add_ms(v);
        }
        assert!(close(s.summary().unwrap().jitter_ms, 20.0));
    }

    #[test]
    fn ignores_garbage_samples() {
        let mut s = RttStats::new();
        s.add_ms(f64::NAN);
        s.add_ms(-1.0);
        s.add_ms(f64::INFINITY);
        assert_eq!(s.count(), 0);
    }

    #[test]
    fn duration_samples() {
        let mut s = RttStats::new();
        s.add(Duration::from_micros(1500));
        assert!(close(s.summary().unwrap().avg_ms, 1.5));
    }

    #[test]
    fn loss_math() {
        assert!(close(loss_percent(0, 0), 0.0));
        assert!(close(loss_percent(4, 3), 25.0));
        assert!(close(loss_percent(10, 0), 100.0));
        assert!(close(loss_percent(3, 5), 0.0));
    }
}

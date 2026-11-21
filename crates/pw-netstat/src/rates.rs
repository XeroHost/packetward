// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Turns monotonically growing interface counters into per-second rates.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Cumulative counters of one interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    pub in_octets: u64,
    pub out_octets: u64,
    pub in_packets: u64,
    pub out_packets: u64,
}

/// Rates over the last interval. Bits per second (octets × 8) and packets per second.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Rates {
    pub in_bps: f64,
    pub out_bps: f64,
    pub in_pps: f64,
    pub out_pps: f64,
}

/// Samples closer together than this reuse the previous rates (a rate over a few milliseconds is
/// mostly noise).
const MIN_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy)]
struct Previous {
    counters: Counters,
    at: Instant,
    rates: Rates,
}

/// Keeps the previous sample of every interface. Time is passed in, so tests are deterministic.
#[derive(Debug, Default)]
pub struct RateTracker {
    previous: HashMap<u32, Previous>,
}

impl RateTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one sample per interface and returns the rates for each of them.
    ///
    /// * The first sample of an interface yields zero rates.
    /// * A counter that went **down** (driver reset, adapter re-created) yields zero for that
    ///   interval and re-bases, instead of a huge bogus spike from unsigned wrap-around.
    /// * Interfaces missing from `samples` are forgotten, so one that comes back starts fresh.
    pub fn update(&mut self, now: Instant, samples: &[(u32, Counters)]) -> HashMap<u32, Rates> {
        let mut next = HashMap::with_capacity(samples.len());
        let mut result = HashMap::with_capacity(samples.len());
        for &(index, counters) in samples {
            let (rates, at) = match self.previous.get(&index) {
                None => (Rates::default(), now),
                Some(prev) => {
                    let elapsed = now.saturating_duration_since(prev.at);
                    if elapsed < MIN_INTERVAL {
                        // Keep the old reference time so the interval keeps growing.
                        (prev.rates, prev.at)
                    } else if went_backwards(prev.counters, counters) {
                        (Rates::default(), now)
                    } else {
                        (rates_between(prev.counters, counters, elapsed), now)
                    }
                }
            };
            let keep_counters = if at == now {
                counters
            } else {
                self.previous[&index].counters
            };
            next.insert(
                index,
                Previous {
                    counters: keep_counters,
                    at,
                    rates,
                },
            );
            result.insert(index, rates);
        }
        self.previous = next;
        result
    }
}

fn went_backwards(old: Counters, new: Counters) -> bool {
    new.in_octets < old.in_octets
        || new.out_octets < old.out_octets
        || new.in_packets < old.in_packets
        || new.out_packets < old.out_packets
}

fn rates_between(old: Counters, new: Counters, elapsed: Duration) -> Rates {
    let seconds = elapsed.as_secs_f64();
    let per_second = |delta: u64| delta as f64 / seconds;
    Rates {
        in_bps: per_second(new.in_octets - old.in_octets) * 8.0,
        out_bps: per_second(new.out_octets - old.out_octets) * 8.0,
        in_pps: per_second(new.in_packets - old.in_packets),
        out_pps: per_second(new.out_packets - old.out_packets),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters(in_octets: u64, out_octets: u64, in_packets: u64, out_packets: u64) -> Counters {
        Counters {
            in_octets,
            out_octets,
            in_packets,
            out_packets,
        }
    }

    fn secs(base: Instant, s: u64) -> Instant {
        base + Duration::from_secs(s)
    }

    #[test]
    fn the_first_sample_has_no_rate() {
        let t0 = Instant::now();
        let mut tracker = RateTracker::new();
        let rates = tracker.update(t0, &[(7, counters(1000, 2000, 10, 20))]);
        assert_eq!(rates[&7], Rates::default());
    }

    #[test]
    fn rates_are_bits_and_packets_per_second() {
        let t0 = Instant::now();
        let mut tracker = RateTracker::new();
        tracker.update(t0, &[(1, counters(0, 0, 0, 0))]);
        let rates = tracker.update(secs(t0, 2), &[(1, counters(250_000, 125_000, 400, 200))]);
        assert_eq!(rates[&1].in_bps, 1_000_000.0); // 125 000 B/s * 8
        assert_eq!(rates[&1].out_bps, 500_000.0);
        assert_eq!(rates[&1].in_pps, 200.0);
        assert_eq!(rates[&1].out_pps, 100.0);
    }

    #[test]
    fn a_counter_that_goes_backwards_is_a_reset_not_a_spike() {
        let t0 = Instant::now();
        let mut tracker = RateTracker::new();
        tracker.update(t0, &[(1, counters(1_000_000, 1_000_000, 1000, 1000))]);
        let rates = tracker.update(secs(t0, 1), &[(1, counters(10, 10, 1, 1))]);
        assert_eq!(rates[&1], Rates::default());
        // ...and the next interval is measured from the re-based counters.
        let rates = tracker.update(secs(t0, 2), &[(1, counters(1010, 10, 11, 1))]);
        assert_eq!(rates[&1].in_bps, 8000.0);
        assert_eq!(rates[&1].out_bps, 0.0);
    }

    #[test]
    fn an_interface_that_disappears_and_returns_starts_fresh() {
        let t0 = Instant::now();
        let mut tracker = RateTracker::new();
        tracker.update(t0, &[(1, counters(500, 500, 5, 5))]);
        tracker.update(secs(t0, 1), &[]);
        let rates = tracker.update(secs(t0, 2), &[(1, counters(900, 900, 9, 9))]);
        assert_eq!(rates[&1], Rates::default());
    }

    #[test]
    fn a_new_interface_does_not_disturb_the_others() {
        let t0 = Instant::now();
        let mut tracker = RateTracker::new();
        tracker.update(t0, &[(1, counters(0, 0, 0, 0))]);
        let rates = tracker.update(
            secs(t0, 1),
            &[
                (1, counters(1000, 0, 1, 0)),
                (2, counters(5000, 5000, 50, 50)),
            ],
        );
        assert_eq!(rates[&1].in_bps, 8000.0);
        assert_eq!(rates[&2], Rates::default());
    }

    #[test]
    fn samples_too_close_together_reuse_the_last_rates() {
        let t0 = Instant::now();
        let mut tracker = RateTracker::new();
        tracker.update(t0, &[(1, counters(0, 0, 0, 0))]);
        let first = tracker.update(secs(t0, 1), &[(1, counters(1000, 0, 10, 0))]);
        let soon = tracker.update(
            secs(t0, 1) + Duration::from_millis(5),
            &[(1, counters(9999, 0, 99, 0))],
        );
        assert_eq!(soon[&1], first[&1]);
        // The interval then continues from the earlier reference point.
        let later = tracker.update(secs(t0, 2), &[(1, counters(2000, 0, 20, 0))]);
        assert_eq!(later[&1].in_bps, 8000.0);
    }

    #[test]
    fn clock_going_backwards_does_not_panic() {
        let t0 = Instant::now();
        let mut tracker = RateTracker::new();
        tracker.update(secs(t0, 5), &[(1, counters(0, 0, 0, 0))]);
        let rates = tracker.update(secs(t0, 1), &[(1, counters(100, 0, 1, 0))]);
        assert_eq!(rates[&1], Rates::default());
    }
}

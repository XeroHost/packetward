// SPDX-License-Identifier: GPL-3.0-or-later
//! Cheap packet timestamps for sources that have no hardware or driver timestamp (raw sockets).
//!
//! The precise wall clock (`SystemTime::now`) is backed by the performance counter on Windows, and on
//! virtual machines without a fast time source one call was measured at about 24 microseconds on the dev
//! VPS: stamping every packet would cap the capture rate near 40 000 packets per second. So the precise
//! clock is read **once per coarse tick** (the millisecond tick counter, which is a plain memory read);
//! packets inside the same tick are spaced one microsecond apart (at most 1 ms worth), and stamps never go
//! backwards. The error against the true arrival time stays within one tick (about 1 to 16 ms), plenty for
//! 1-second statistics and for ordering packets in a capture file.

const STEP_NS: u64 = 1_000;
const MAX_STEPS: u64 = 1_000;

#[derive(Debug, Default)]
pub(crate) struct Stamper {
    started: bool,
    tick: u64,
    base_ns: u64,
    in_tick: u64,
    last: u64,
}

impl Stamper {
    /// `tick_ms` is a cheap, coarse, non-decreasing clock; `precise_ns` is only called when it advanced.
    pub(crate) fn stamp(&mut self, tick_ms: u64, precise_ns: impl FnOnce() -> u64) -> u64 {
        if !self.started || tick_ms != self.tick {
            self.started = true;
            self.tick = tick_ms;
            self.base_ns = precise_ns();
            self.in_tick = 0;
        } else {
            self.in_tick = (self.in_tick + 1).min(MAX_STEPS);
        }
        let stamp = self
            .base_ns
            .saturating_add(self.in_tick * STEP_NS)
            .max(self.last.saturating_add(1));
        self.last = stamp;
        stamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn reads_the_precise_clock_once_per_tick() {
        let calls = Cell::new(0u32);
        let mut s = Stamper::default();
        let mut out = Vec::new();
        for i in 0..1000u64 {
            // 100 packets per tick, ticks 1 ms apart
            let tick = 5_000 + i / 100;
            out.push(s.stamp(tick, || {
                calls.set(calls.get() + 1);
                tick * 1_000_000
            }));
        }
        assert_eq!(calls.get(), 10);
        assert!(out.windows(2).all(|w| w[0] < w[1]), "strictly increasing");
        assert_eq!(out[0], 5_000_000_000);
        assert_eq!(out[1], 5_000_001_000);
        assert_eq!(out[100], 5_001_000_000);
    }

    #[test]
    fn stays_monotonic_even_if_the_precise_clock_lags() {
        let mut s = Stamper::default();
        let mut last = 0;
        for i in 0..2000u64 {
            // One tick, thousands of packets: the 1 us steps cap at 1000, then +1 ns each.
            let t = s.stamp(1, || 1_000_000);
            assert!(t > last, "{i}");
            last = t;
        }
        // The next tick's precise reading is earlier than the extrapolated stamps: still increasing.
        let t = s.stamp(2, || 1_000_500);
        assert!(t > last);
    }
}

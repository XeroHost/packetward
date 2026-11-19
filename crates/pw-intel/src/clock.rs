// SPDX-License-Identifier: GPL-3.0-or-later
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch. Plain integers keep persisted state and tests trivial.
pub type UnixSecs = u64;

/// Injected time source: schedulers, caches and rate limiters never read the wall clock themselves.
pub trait Clock: Send + Sync {
    fn now(&self) -> UnixSecs;
}

/// The real clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixSecs {
        // A clock before 1970 is treated as 0: every deadline is then "in the future", which only delays work.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

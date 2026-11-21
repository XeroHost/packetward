// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The set of addresses with a successful RDP logon, shared between the event-log feed (which adds
//! to it from callback threads) and the poller (which publishes it).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pw_netstat::logon::TrustSet;
use pw_netstat::LogonSink;
use pw_proto::{TrustFeed, TrustedAddress};

use crate::poller::unix_ms;

/// Distinct addresses kept; far more than a real server ever sees, small enough to bound memory
/// under a flood of (spoofed or real) logon attempts that succeed.
const MAX_ADDRESSES: usize = 10_000;

pub const MIN_WINDOW_DAYS: u32 = 1;
pub const MAX_WINDOW_DAYS: u32 = 365;
pub const DEFAULT_WINDOW_DAYS: u32 = 30;

pub struct TrustState {
    set: Mutex<TrustSet>,
    feed: Mutex<TrustFeed>,
}

impl TrustState {
    /// `window_days` is clamped to 1..=365.
    pub fn new(window_days: u32) -> Arc<Self> {
        let days = window_days.clamp(MIN_WINDOW_DAYS, MAX_WINDOW_DAYS);
        Arc::new(Self {
            set: Mutex::new(TrustSet::new(days, MAX_ADDRESSES)),
            feed: Mutex::new(TrustFeed::Loading),
        })
    }

    fn set(&self) -> MutexGuard<'_, TrustSet> {
        self.set.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn window_days(&self) -> u32 {
        self.set().window_days()
    }

    pub fn window_ms(&self) -> u64 {
        u64::from(self.window_days()) * 24 * 60 * 60 * 1000
    }

    /// The callback the event-log feed calls for every successful RDP logon.
    pub fn sink(self: &Arc<Self>) -> LogonSink {
        let state = Arc::clone(self);
        Arc::new(move |event| state.set().record(event, unix_ms()))
    }

    pub fn set_feed(&self, state: TrustFeed) {
        *self.feed.lock().unwrap_or_else(PoisonError::into_inner) = state;
    }

    pub fn feed(&self) -> TrustFeed {
        *self.feed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn addresses(&self, now_unix_ms: u64) -> Vec<TrustedAddress> {
        self.set().addresses(now_unix_ms)
    }
}

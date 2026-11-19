// SPDX-License-Identifier: GPL-3.0-or-later
//! Deterministic tests of the detection engine, one file per concern.

mod boundaries;
mod detectors;
mod lifecycle;
mod limits;
mod time;

use std::net::IpAddr;

use pw_core::PacketMeta;

use crate::testgen::{replay, LogonFailure, SECOND};
use crate::{Alert, AlertPhase, Config, Engine};

/// Run a scenario on a fresh engine and return every alert.
pub(crate) fn run(
    config: Config,
    packets: Vec<PacketMeta>,
    logons: &[LogonFailure],
    start_ns: u64,
    end_ns: u64,
) -> Vec<Alert> {
    let mut engine = Engine::new(config);
    replay(&mut engine, packets, logons, start_ns, end_ns)
}

/// The `Started` alerts as `(summary key, source)` pairs, in emission order.
pub(crate) fn started(alerts: &[Alert]) -> Vec<(&'static str, Option<IpAddr>)> {
    alerts
        .iter()
        .filter(|a| a.phase == AlertPhase::Started)
        .map(|a| (a.summary_key, a.source))
        .collect()
}

pub(crate) fn has_started(alerts: &[Alert], key: &str, source: Option<IpAddr>) -> bool {
    alerts
        .iter()
        .any(|a| a.phase == AlertPhase::Started && a.summary_key == key && a.source == source)
}

/// Seconds as nanoseconds.
pub(crate) const fn secs(n: u64) -> u64 {
    n * SECOND
}

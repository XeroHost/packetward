// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! pw-detect — pure detection engine: per-source sliding windows and detectors. No OS dependencies,
//! no I/O, deterministic: every time value is passed in.
//!
//! ```text
//! PacketMeta ──ingest──►┐
//! netstat snapshots ───►│ Engine ──tick(now)──► Vec<Alert>   (Started / Escalated / Ended)
//! Security 4625 events ►│
//! link utilisation ────►┘
//! ```
//!
//! # Time
//!
//! All timestamps are `u64` nanoseconds since the Unix epoch, the unit of
//! `PacketMeta::timestamp_ns`. `tick(now_ns)` must use the same clock. (`docs/ARCHITECTURE.md` §6.2
//! says `now: Instant`; a plain integer is what `PacketMeta` carries and what tests can construct.)
//! The engine clock never goes backwards: late packets are counted at the current clock, `tick`
//! with a time slightly in the past is ignored and one more than an hour in the past re-bases the
//! clock; a packet timestamp more than an hour ahead is ignored as an anomaly (see
//! [`EngineStats`]).
//!
//! # Windows
//!
//! Counters live in 1-second cells (and 10-second cells for the 60 s window). A window covers the
//! last `N` **completed** epochs; the one in progress is excluded (see [`Window`]). Thresholds are
//! counts in the window. Distinct port/host sets also include the in-progress second.
//!
//! # Memory and the hot path
//!
//! `ingest` does one hash lookup and a few saturating increments. Memory is bounded by
//! [`Limits`]: at most `max_sources` tracked sources (~0.7 KB each); a full table rejects packets
//! of *new* sources (counted in `packets_untracked`, still included in the machine-wide counters)
//! until the next `tick` trims it to 75 %, dropping the quietest sources first, so a spoofed-source
//! flood cannot evict loud real attackers. Expanded scan sets come from a bounded, recycled pool.
//!
//! # Limitations
//!
//! * IPv6 sources are tracked per address; an attacker rotating inside a /64 shows up only in the
//!   unattributed detectors and as table churn.
//! * The 60 s counter window has 10 s granularity (up to 10 s extra latency).
//! * Scans slower than `min_ports` per 60 s are not detected.

mod alert;
mod config;
mod engine;
mod eval;
mod scan;
mod wheel;

#[cfg(any(test, feature = "testgen"))]
pub mod testgen;

#[cfg(test)]
mod tests;

pub use alert::{Alert, AlertPhase, DetectorKind, Metric};
pub use config::{
    AggregateConfig, Config, ConfigError, ConnFloodConfig, IcmpFloodConfig, Limits, PortScanConfig,
    Preset, RdpBruteForceConfig, Severity, SynFloodConfig, UdpFloodConfig, Window,
};
pub use engine::{ConnectionCounts, Engine, EngineStats, NS_PER_SEC};

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The alert type the engine emits and its lifecycle.
//!
//! One attack is one *incident* (per detector variant and source). The engine emits:
//!
//! 1. [`AlertPhase::Started`] once, when the incident opens;
//! 2. [`AlertPhase::Escalated`] each time the severity rises (same `id`, higher `severity`);
//! 3. [`AlertPhase::Ended`] once, when the condition has been false for the detector's
//!    `cooldown_secs` (same `id`; `severity` and `metrics` are the peak values).
//!
//! While the attack continues and the severity does not rise, nothing is emitted (dedup). If the
//! attack resumes after `Ended`, a new incident with a new `id` starts.

use std::net::IpAddr;

use serde::Serialize;

use crate::config::Severity;

/// Which detector raised the alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorKind {
    SynFlood,
    UdpFlood,
    IcmpFlood,
    PortScan,
    ConnFlood,
    RdpBruteForce,
    Aggregate,
}

impl DetectorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DetectorKind::SynFlood => "syn_flood",
            DetectorKind::UdpFlood => "udp_flood",
            DetectorKind::IcmpFlood => "icmp_flood",
            DetectorKind::PortScan => "port_scan",
            DetectorKind::ConnFlood => "conn_flood",
            DetectorKind::RdpBruteForce => "rdp_brute_force",
            DetectorKind::Aggregate => "aggregate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertPhase {
    Started,
    Escalated,
    Ended,
}

/// One named number. The unit is part of the key (`..._permille`, `..._bytes`, `..._secs`) so the
/// values stay integers and the alert is `Eq` and deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Metric {
    pub key: &'static str,
    pub value: u64,
}

impl Metric {
    pub(crate) fn new(key: &'static str, value: u64) -> Self {
        Self { key, value }
    }
}

/// An alert. Serialize-only: `summary_key` and metric keys are `'static` strings; the IPC layer
/// mirrors this type in `pw-proto`.
///
/// `summary_key` is a stable machine-readable string meant for i18n lookup: `syn_flood`,
/// `syn_flood_distributed`, `udp_flood`, `udp_flood_distributed`, `icmp_flood`,
/// `icmp_flood_distributed`, `port_scan_vertical`, `port_scan_horizontal`, `conn_flood`,
/// `rdp_brute_force`, `volumetric_attack`.
///
/// # `protected`
///
/// Alerts are **always raised**, also for protected sources. `protected` is `true` when the source
/// address is inside the `CidrSet` the caller gave the engine (`Engine::set_protected`: RDP trust
/// set, allowlist, gateway, DNS, management ranges). The engine never blocks anything; the Guardian
/// uses the flag (and re-checks its own protected set) to decide. Unattributed alerts
/// (`source == None`) are never protected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    /// Stable for the whole incident (`Started`, `Escalated`, `Ended`); unique per engine, increasing.
    pub id: u64,
    pub phase: AlertPhase,
    pub kind: DetectorKind,
    pub severity: Severity,
    pub source: Option<IpAddr>,
    pub summary_key: &'static str,
    pub metrics: Vec<Metric>,
    /// The detector window the metrics were measured over, in seconds.
    pub window_secs: u32,
    /// Nanoseconds since the Unix epoch of the first tick at which the condition held.
    pub first_seen_ns: u64,
    /// Nanoseconds since the Unix epoch of the latest tick at which the condition held.
    pub last_seen_ns: u64,
    pub protected: bool,
}

impl Alert {
    /// The value of a named metric.
    pub fn metric(&self, key: &str) -> Option<u64> {
        self.metrics.iter().find(|m| m.key == key).map(|m| m.value)
    }
}

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Alerts (M5): what the detectors raise, as the inbox and the notifications see it.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum AlertPhaseView {
    Started,
    /// The severity went up.
    Escalated,
    /// The condition has been false for the cooldown.
    Ended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum AlertKindView {
    SynFlood,
    UdpFlood,
    IcmpFlood,
    PortScan,
    ConnFlood,
    RdpBruteForce,
    Aggregate,
    /// A successful Remote Desktop logon from an address never seen before.
    RdpNewLogon,
}

/// A named number of an alert; the unit is part of the key (`_permille`, `_bytes`, `_secs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AlertMetric {
    pub key: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub value: u64,
}

/// One incident: a detector firing for a source, from its start until it ends. The same `id`
/// is used by every update of the incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AlertView {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub id: u64,
    pub phase: AlertPhaseView,
    pub kind: AlertKindView,
    pub severity: AlertSeverity,
    /// The attacking address; absent for attacks from many addresses at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub source: Option<String>,
    /// Stable key for the translated description, for example `syn_flood` or `port_scan_vertical`.
    pub summary_key: String,
    pub metrics: Vec<AlertMetric>,
    /// The detector window the metrics were measured over.
    pub window_secs: u32,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub first_seen_unix_ms: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub last_seen_unix_ms: u64,
    /// The source is one PacketWard never blocks (a trusted RDP client, the allowlist…).
    pub protected: bool,
    /// Highest severity reached during the incident.
    pub peak_severity: AlertSeverity,
}

/// Reply to `alerts.list`: the most recent incidents, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AlertList {
    pub alerts: Vec<AlertView>,
    /// Incidents dropped to keep the list bounded.
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub dropped: u64,
}

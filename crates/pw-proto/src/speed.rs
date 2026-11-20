// SPDX-License-Identifier: GPL-3.0-or-later
//! Speed test (M9): runs against XeroHost nodes or the user's own `speed-server`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum SpeedKind {
    /// Latency, jitter, then a timed download and upload.
    Quick,
    /// A fixed 1 GiB download.
    Bin1,
    /// A fixed 10 GiB download.
    Bin10,
    /// A fixed 50 GiB download (needs `confirm_large`).
    Bin50,
}

/// Payload of `speed.start`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SpeedRequest {
    pub kind: SpeedKind,
    /// Servers added by the user (`https://host:port`, `http://…` or `host[:port]`), used in addition to
    /// the XeroHost nodes. At least one server must be available.
    #[serde(default)]
    pub servers: Vec<String>,
    /// Parallel streams (1..=16); absent = 4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub streams: Option<u32>,
    /// Which provider to use: `auto` (the default: the fastest of everything available), `xerohost`,
    /// `custom` (only the servers in `servers`), `cloudflare`, `hetzner` or `ovh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub provider: Option<String>,
    /// Seconds each of download and upload run for (quick test); absent = 10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub duration_secs: Option<u32>,
    /// The user saw the bandwidth and time warning of the 50 GiB test.
    #[serde(default)]
    pub confirm_large: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SpeedStarted {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub job_id: u64,
    /// Servers refused before the run (placeholders, bad addresses), with the reason.
    pub rejected: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SpeedLatencyView {
    pub sent: u32,
    pub received: u32,
    pub loss_percent: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub min_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub avg_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub max_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub jitter_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SpeedTransferView {
    pub streams: u32,
    pub avg_mbps: f64,
    pub peak_mbps: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub bytes: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub duration_ms: u64,
    /// Rate of every second, for a chart.
    pub buckets_mbps: Vec<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SpeedServerView {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub location: Option<String>,
    /// Round trip to it while choosing; absent when it did not answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub latency_ms: Option<f64>,
    pub custom: bool,
    /// The built-in provider (`cloudflare`, `hetzner`, `ovh`); absent for XeroHost nodes and custom servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub provider: Option<String>,
}

/// The report of a finished run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SpeedResultView {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub started_unix_ms: u64,
    pub kind: SpeedKind,
    pub server: SpeedServerView,
    /// Every candidate with its latency.
    pub candidates: Vec<SpeedServerView>,
    /// This machine's public address as the server sees it; absent when the server did not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub source_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub latency: Option<SpeedLatencyView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub download: Option<SpeedTransferView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub upload: Option<SpeedTransferView>,
    /// The server the upload was measured against when it is not `server` (the chosen provider only
    /// downloads, like a static mirror).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub upload_server: Option<SpeedServerView>,
}

/// One message of the `speed.progress` topic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SpeedEvent {
    /// `picking_server`, `server_info`, `latency`, `download`, `upload` or `bin_download`.
    Phase {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        phase: String,
    },
    Ping {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        seq: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts-export", ts(optional))]
        rtt_ms: Option<f64>,
    },
    /// Rate of the last second; `direction` is `download` or `upload`.
    Rate {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        direction: String,
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        elapsed_ms: u64,
        warmup: bool,
        mbps: f64,
        avg_mbps: f64,
    },
    /// A fixed-size download in progress.
    Bin {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        bytes_done: u64,
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        bytes_total: u64,
        mbps: f64,
        avg_mbps: f64,
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        elapsed_ms: u64,
    },
    Done {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        result: Box<SpeedResultView>,
    },
    /// `cancelled`, `no_server`, `confirmation_required`, `rate_limited`, `budget_exceeded`, `server`,
    /// `invalid`, `incomplete` or `transport`.
    Failed {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        code: String,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts-export", ts(optional))]
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        retry_after_secs: Option<u64>,
    },
}

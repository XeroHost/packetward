// SPDX-License-Identifier: GPL-3.0-or-later
//! Result and progress types of the speed test. Plain serde types; the IPC mapping lives in `pw-proto`.
//!
//! Units: throughput in megabits per second (1 Mbps = 1 000 000 bit/s), sizes in bytes, times in milliseconds.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::server::{ServerEndpoint, ServerInfo};

/// Transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Server to this machine.
    Download,
    /// This machine to the server.
    Upload,
}

/// The step a run is in (first event of every step).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedPhase {
    /// Measuring latency to every candidate to choose one.
    PickingServer,
    /// Fetching `/info` of the chosen server.
    ServerInfo,
    /// Ping round trips.
    Latency,
    /// Multi-stream download.
    Download,
    /// Multi-stream upload.
    Upload,
    /// Fixed-size download.
    BinDownload,
}

/// Progress events, sent to the caller's [`Sink`](crate::Sink) (a bounded channel or a callback).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpeedProgress {
    /// A new step starts.
    Phase {
        /// Which one.
        phase: SpeedPhase,
    },
    /// One ping finished.
    Ping {
        /// 1-based sequence number.
        seq: u32,
        /// Round trip in ms; `None` when the ping failed or timed out.
        rtt_ms: Option<f64>,
    },
    /// Once per bucket (1 s) during a duration-based download or upload.
    Throughput {
        /// Direction.
        direction: Direction,
        /// Time since the transfer started.
        elapsed_ms: u64,
        /// `true` while the warm-up period (excluded from the result) is running.
        warmup: bool,
        /// Rate of the last bucket.
        mbps: f64,
        /// Average since the warm-up ended (0 during warm-up).
        avg_mbps: f64,
        /// Bytes moved since the start (including warm-up).
        bytes: u64,
    },
    /// Once per bucket during a bin test.
    Bin {
        /// Bytes received so far.
        bytes_done: u64,
        /// Bytes the test will receive.
        bytes_total: u64,
        /// Rate of the last bucket.
        mbps: f64,
        /// Average since the start.
        avg_mbps: f64,
        /// Time since the start.
        elapsed_ms: u64,
    },
}

/// Latency and jitter of a server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatencyResult {
    /// Pings sent (the unmeasured connection warm-up ping is not counted).
    pub sent: u32,
    /// Pings answered.
    pub received: u32,
    /// Pings that failed or timed out.
    pub failed: u32,
    /// `failed / sent`, in percent.
    pub loss_percent: f64,
    /// Fastest round trip.
    pub min_ms: Option<f64>,
    /// Mean round trip.
    pub avg_ms: Option<f64>,
    /// Slowest round trip.
    pub max_ms: Option<f64>,
    /// Mean absolute difference between consecutive answered pings (needs two answers).
    pub jitter_ms: Option<f64>,
    /// Every ping in order (`None` = failed), for a chart.
    pub samples_ms: Vec<Option<f64>>,
}

/// Outcome of a duration-based download or upload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThroughputResult {
    /// Direction.
    pub direction: Direction,
    /// Parallel streams actually used (after clamping to 1..=16 and the server's published limit).
    pub streams: u32,
    /// Average over the measured window (warm-up excluded).
    pub avg_mbps: f64,
    /// Fastest 1-second bucket of the measured window.
    pub peak_mbps: f64,
    /// Bytes moved in the measured window.
    pub bytes: u64,
    /// Bytes moved in total, warm-up included.
    pub total_bytes: u64,
    /// Length of the measured window.
    pub duration_ms: u64,
    /// Warm-up that was excluded from the window (0 if the run ended before the warm-up did).
    pub warmup_ms: u64,
    /// Rate of every bucket of the measured window, for a chart.
    pub buckets_mbps: Vec<f64>,
    /// The `?test=` id all streams of the run sent.
    pub test_id: String,
}

/// Outcome of a bin test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinResult {
    /// Nominal size of the test (1, 10 or 50 GiB).
    pub size_bytes: u64,
    /// Bytes actually downloaded (smaller than `size_bytes` only when a scale below 1 was requested).
    pub bytes: u64,
    /// Parallel streams used.
    pub streams: u32,
    /// Wall-clock duration.
    pub duration_ms: u64,
    /// Average rate over the whole transfer.
    pub avg_mbps: f64,
    /// Fastest 1-second bucket.
    pub peak_mbps: f64,
    /// Rate of every bucket.
    pub buckets_mbps: Vec<f64>,
    /// The `?test=` id all streams sent.
    pub test_id: String,
}

/// Which server was used, without anything that could identify the user's setup beyond the address they chose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSummary {
    /// Node id (or authority for a custom server).
    pub id: String,
    /// Display name (the server's own `node_name` when `/info` answered).
    pub name: String,
    /// `host:port`.
    pub authority: String,
    /// `https` or `http`.
    pub scheme: String,
    /// Free-text location from `/info`.
    pub location: Option<String>,
    /// A server the user added.
    pub custom: bool,
    /// The built-in provider group (`cloudflare`, `hetzner`, `ovh`), if it is one.
    pub provider: Option<String>,
}

impl ServerSummary {
    pub(crate) fn new(server: &ServerEndpoint, info: Option<&ServerInfo>) -> Self {
        let from_info = |text: &str| (!text.trim().is_empty()).then(|| text.trim().to_owned());
        Self {
            id: server.id.clone(),
            name: info
                .and_then(|i| from_info(&i.node_name))
                .unwrap_or_else(|| server.name.clone()),
            authority: server.authority(),
            scheme: server.scheme.as_str().to_owned(),
            location: info.and_then(|i| from_info(&i.location)),
            custom: server.custom,
            provider: super::providers::builtin_of(server).map(|b| b.group.to_owned()),
        }
    }
}

/// Latency to one candidate during server selection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerProbe {
    /// The candidate.
    pub server: ServerEndpoint,
    /// Best round trip of the probes; `None` when every probe failed (a dead server).
    pub latency_ms: Option<f64>,
    /// Why it counts as dead.
    pub error: Option<String>,
}

/// The full report of one speed test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpeedResult {
    /// Unix time (ms) when the run started.
    pub started_at_unix_ms: u64,
    /// The server used.
    pub server: ServerSummary,
    /// This machine's public IP as the chosen server saw it (`/info.client_ip`). Absent when `/info` did not
    /// answer: nothing else is ever asked.
    pub source_ip: Option<IpAddr>,
    /// Every candidate with its latency (for the picker UI).
    pub servers_probed: Vec<ServerProbe>,
    /// Latency and jitter, when requested.
    pub latency: Option<LatencyResult>,
    /// Download, when requested.
    pub download: Option<ThroughputResult>,
    /// Upload, when requested.
    pub upload: Option<ThroughputResult>,
    /// The server the upload was measured against, when it is not the one of the download (the chosen
    /// provider is download-only).
    pub upload_server: Option<ServerSummary>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_events_carry_a_kind_tag() {
        let event = SpeedProgress::Phase {
            phase: SpeedPhase::BinDownload,
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"kind":"phase","phase":"bin_download"}"#
        );
        let back: SpeedProgress =
            serde_json::from_str(r#"{"kind":"ping","seq":2,"rtt_ms":null}"#).unwrap();
        assert_eq!(
            back,
            SpeedProgress::Ping {
                seq: 2,
                rtt_ms: None
            }
        );
    }
}

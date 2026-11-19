// SPDX-License-Identifier: GPL-3.0-or-later
//! Diagnostics (M3): ping, MTR, DNS lookup and port checks.

use serde::{Deserialize, Serialize};

/// Payload of `diag.ping.start`. Missing options use the agent's defaults (all clamped by the agent).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct PingStartRequest {
    /// Host name or IP address (IPv4 or IPv6).
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub timeout_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub packet_size: Option<u16>,
}

/// Payload of `diag.mtr.start`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct MtrStartRequest {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub cycles: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub max_hops: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub timeout_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub packet_size: Option<u16>,
    /// Look up the host name of each hop (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub resolve_names: Option<bool>,
}

/// Reply to a `diag.*.start`: the job whose events arrive on the \`diag.progress\` topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct DiagStartResponse {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub job_id: u64,
    /// The address actually probed (the target after name resolution).
    pub target_ip: String,
}

/// Payload of `diag.cancel` and `diag.mtr.report`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct DiagJobRequest {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub job_id: u64,
}

/// Reply to `diag.mtr.report`: the plain-text report to copy for support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct MtrReport {
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum EchoOutcome {
    Success,
    TtlExpired,
    Unreachable,
    TimedOut,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct PingReplyView {
    pub seq: u32,
    pub outcome: EchoOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional, type = "number"))]
    pub rtt_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub ttl: Option<u8>,
    pub bytes: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub error: Option<String>,
}

/// Round-trip statistics in milliseconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RttView {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub count: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub last_ms: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub min_ms: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub avg_ms: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub max_ms: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub stddev_ms: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub jitter_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct PingSummaryView {
    pub target: String,
    pub sent: u32,
    pub received: u32,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub loss_percent: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub rtt: Option<RttView>,
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct MtrHopView {
    pub ttl: u8,
    /// Most recent responder; `None` while the hop has never answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub addr: Option<String>,
    /// Other routers that answered at this hop (load balancing / route changes).
    pub other_addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub name: Option<String>,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub sent: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub received: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub loss_percent: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub rtt: Option<RttView>,
    pub address_changes: u32,
}

/// All hops after one MTR cycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct MtrView {
    pub target: String,
    pub cycle: u32,
    pub total_cycles: u32,
    pub hops: Vec<MtrHopView>,
    pub destination_reached: bool,
    pub cancelled: bool,
}

/// One message of the `diag.progress` topic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DiagEvent {
    PingReply {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        reply: PingReplyView,
    },
    PingDone {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        summary: PingSummaryView,
    },
    MtrSnapshot {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        snapshot: MtrView,
    },
    MtrDone {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        cancelled: bool,
    },
    Failed {
        #[cfg_attr(feature = "ts-export", ts(type = "number"))]
        job_id: u64,
        message: String,
    },
}

/// Payload of `diag.dns.lookup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct DnsLookupRequest {
    pub name: String,
    /// "A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "PTR" or "ALL".
    pub record_type: String,
    /// "system", "cloudflare", "google" or "custom".
    pub resolver: String,
    /// Servers for `custom` (at most 4).
    #[serde(default)]
    pub custom_servers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct DnsRecordView {
    pub name: String,
    pub record_type: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct DnsErrorView {
    pub record_type: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct DnsLookupView {
    pub query: String,
    pub requested: String,
    pub records: Vec<DnsRecordView>,
    /// Record types that failed while others succeeded (ALL).
    pub errors: Vec<DnsErrorView>,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub elapsed_ms: u64,
}

/// Payload of `diag.port.check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct PortCheckRequest {
    pub host: String,
    pub port: u16,
    /// "tcp" or "udp".
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub timeout_ms: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum PortStateView {
    Open,
    Closed,
    Filtered,
    /// UDP without a reply: it proves nothing.
    Inconclusive,
    /// The check itself failed (unresolvable name, no route); see `PortCheckView::error`.
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct PortCheckView {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub state: PortStateView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub remote: Option<String>,
    /// Why the check failed, when `state` is `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub error: Option<String>,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub elapsed_ms: u64,
}

/// A local socket that accepts connections (TCP listener) or receives datagrams (UDP endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct LocalPort {
    pub proto: crate::Proto,
    pub addr: String,
    pub port: u16,
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub process: Option<String>,
}

/// Reply to `diag.ports.local`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct LocalPorts {
    pub ports: Vec<LocalPort>,
}

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
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
    /// How the probes are sent (default `icmp`). `udp` and `tcp` need a capture backend on the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub mode: Option<MtrModeView>,
    /// Destination port of `udp` (default 33434) and `tcp` (default 443) probes; ignored for `icmp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub port: Option<u16>,
    /// Time between the starts of two cycles in milliseconds (the agent keeps it at 200 ms or more).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub interval_ms: Option<u32>,
    /// Prefer an IPv6 address when `target` is a host name with both families (default: IPv4 first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub prefer_ipv6: Option<bool>,
}

/// How MTR probes are sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum MtrModeView {
    /// ICMP echo (works everywhere, no capture backend needed).
    #[default]
    Icmp,
    /// UDP datagrams to a high port (classic traceroute).
    Udp,
    /// TCP SYN to a port: reaches hosts that drop ICMP and UDP.
    Tcp,
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

/// Format of `diag.mtr.export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum MtrExportFormat {
    Csv,
    Json,
    /// The plain-text report for support.
    Text,
}

/// Payload of `diag.mtr.export`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct MtrExportRequest {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub job_id: u64,
    pub format: MtrExportFormat,
    /// This machine's public IP (for the report header), when the app knows it (speed test).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub source_ip: Option<String>,
}

/// Reply to `diag.mtr.export`: the rendered file, ready to copy or save.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct MtrExport {
    pub format: MtrExportFormat,
    /// A safe file name (no path, no characters Windows refuses), e.g.
    /// `packetward-mtr-1.1.1.1-20260101-120000.csv`.
    pub filename: String,
    pub content: String,
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
    /// Autonomous system number of `addr` (local GeoIP database; absent for private addresses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub asn: Option<u32>,
    /// Organisation that owns the autonomous system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub as_org: Option<String>,
    /// ISO 3166-1 alpha-2 country code of `addr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub country: Option<String>,
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
    /// How the probes were sent (absent from agents older than protocol 1.10: ICMP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub mode: Option<MtrModeView>,
    /// Destination port of the probes (UDP and TCP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub port: Option<u16>,
    /// How the destination answered: `echo-reply`, `port-unreachable`, `syn-ack` or `rst`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub reach: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_old_mtr_request_still_parses_and_new_fields_default_to_none() {
        let request: MtrStartRequest =
            serde_json::from_str(r#"{"target":"1.1.1.1","cycles":5}"#).unwrap();
        assert_eq!(request.mode, None);
        assert_eq!(request.port, None);
        assert_eq!(request.interval_ms, None);
        let json = serde_json::to_string(&request).unwrap();
        assert!(
            !json.contains("mode"),
            "absent options are not sent: {json}"
        );
    }

    #[test]
    fn the_modes_and_formats_use_snake_case() {
        let request: MtrStartRequest =
            serde_json::from_str(r#"{"target":"x","mode":"tcp","port":443}"#).unwrap();
        assert_eq!(request.mode, Some(MtrModeView::Tcp));
        let export: MtrExportRequest =
            serde_json::from_str(r#"{"job_id":3,"format":"csv"}"#).unwrap();
        assert_eq!(export.format, MtrExportFormat::Csv);
        assert_eq!(export.source_ip, None);
    }

    #[test]
    fn an_old_mtr_snapshot_without_the_new_fields_parses() {
        let hop = r#"{"ttl":1,"other_addrs":[],"sent":1,"received":1,"loss_percent":0.0,"address_changes":0}"#;
        let json = format!(
            r#"{{"target":"1.1.1.1","cycle":1,"total_cycles":1,"hops":[{hop}],"destination_reached":false,"cancelled":false}}"#
        );
        let view: MtrView = serde_json::from_str(&json).unwrap();
        assert_eq!(view.mode, None);
        assert_eq!(view.hops[0].asn, None);
    }
}

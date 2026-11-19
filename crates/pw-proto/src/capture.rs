// SPDX-License-Identifier: GPL-3.0-or-later
//! Packet capture (M4): backend explanation, live traffic statistics and recordings.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum BackendKindView {
    Npcap,
    RawSocket,
}

/// One capture backend and whether it can run on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct BackendStatusView {
    pub kind: BackendKindView,
    pub available: bool,
    /// Why it is unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub reason: Option<String>,
    /// Sees the packets this machine sends as well as the ones it receives.
    pub sees_outbound: bool,
    /// Can push filters down to the kernel (BPF).
    pub bpf: bool,
}

/// Something that would improve capture and is not installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct MissingView {
    /// Machine-readable kind, for example `npcap` or `administrator`.
    pub kind: String,
    /// Capture cannot work at all without it.
    pub required: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub install_url: Option<String>,
}

/// Which backend is used and what is missing; absent backends are not errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct CaptureSelection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub selected: Option<BackendKindView>,
    pub npcap: BackendStatusView,
    pub raw_socket: BackendStatusView,
    pub missing: Vec<MissingView>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct InterfaceView {
    pub id: String,
    pub name: String,
    pub description: String,
    pub addrs: Vec<String>,
    pub up: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum CaptureRunState {
    Stopped,
    Running,
    /// Ended by an error; see `CaptureStatus::error`.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct CaptureCounters {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub received: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub delivered: u64,
    /// Packets lost before they were counted: queue overflow plus kernel drops. Never hidden.
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub dropped: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum RecordModeView {
    /// Stops by itself after the duration.
    Timed,
    /// Keeps the most recent data in a bounded set of files until stopped.
    Ring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum PayloadView {
    /// First 128 bytes of each packet (default): headers, not content.
    Headers,
    /// Whole packets, content included. Needs an explicit confirmation.
    Full,
}

/// What a finished recording produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RecordingResult {
    pub files: Vec<String>,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub packets: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub bytes: u64,
    /// `requested`, `duration`, `size_limit`, `source_ended` or `error`.
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RecordingView {
    pub running: bool,
    pub name: String,
    pub mode: RecordModeView,
    pub payload: PayloadView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub filter: Option<String>,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub started_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub duration_secs: Option<u32>,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub packets_written: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub bytes_written: u64,
    /// Present once the recording has ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub result: Option<RecordingResult>,
}

/// Reply to `capture.status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct CaptureStatus {
    pub selection: CaptureSelection,
    pub state: CaptureRunState,
    /// Name of the adapter being captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub error: Option<String>,
    /// Outbound packets are seen but no inbound ones: the backend cannot see what this machine
    /// receives, so flood detection from capture is unreliable. See the capture page for the fix.
    pub blind: bool,
    pub counters: CaptureCounters,
    pub interfaces: Vec<InterfaceView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub recording: Option<RecordingView>,
    /// Where recordings are written (readable by administrators only).
    pub captures_dir: String,
}

/// Payload of `capture.start`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct CaptureStartRequest {
    /// Adapter name, GUID or address. Default: the main adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub interface: Option<String>,
}

/// Payload of `capture.record.start`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RecordStartRequest {
    /// File name prefix; only letters, digits, `-` and `_` are kept.
    pub name: String,
    pub mode: RecordModeView,
    /// Seconds, for `timed` (1..=3600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub duration_secs: Option<u32>,
    /// A filter such as `tcp and port 3389` or `src net 203.0.113.0/24`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub filter: Option<String>,
    pub payload: PayloadView,
    /// Must be true for `full`: the capture will contain the content of the traffic.
    #[serde(default)]
    pub confirm_full_payload: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct CaptureFile {
    pub name: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub bytes: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub modified_unix_ms: u64,
}

/// Reply to `capture.files`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct CaptureFiles {
    pub dir: String,
    pub files: Vec<CaptureFile>,
}

/// Payload of `capture.files.delete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct CaptureFileRequest {
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RateView {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub pps: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ProtocolRate {
    /// `tcp`, `udp`, `icmp` or `other`.
    pub proto: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub pps: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct TalkerView {
    pub addr: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub packets: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub bytes: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub tcp_packets: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub udp_packets: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub icmp_packets: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub other_packets: u64,
}

/// One message of the `capture.stats` topic, once per second while a capture runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct CaptureLive {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub unix_ms: u64,
    pub blind: bool,
    pub inbound: RateView,
    pub outbound: RateView,
    pub protocols: Vec<ProtocolRate>,
    /// Inbound sources by packets in the last interval.
    pub top_talkers: Vec<TalkerView>,
    /// Packets lost in total (queue overflow plus kernel drops).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub dropped: u64,
    /// Packets from sources the table had no room for (still counted in the rates).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub untracked_packets: u64,
}

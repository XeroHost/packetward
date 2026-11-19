// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-proto — IPC and shared DTOs (serde + ts-rs). Versioned, no logic.
//!
//! Every type that crosses the agent ⇄ UI/CLI boundary lives here. With the `ts-export`
//! feature the types also derive `ts_rs::TS`; `cargo test -p pw-proto --features ts-export`
//! regenerates `apps/desktop/src/types/generated`.

mod alerts;
mod bridge;
mod capture;
mod diag;
mod envelope;
mod error;
mod firewall;
mod handshake;
mod live;
mod netstat;
mod rdp;
mod subscribe;
mod support;
mod system;

pub use alerts::{AlertKindView, AlertList, AlertMetric, AlertPhaseView, AlertSeverity, AlertView};
pub use bridge::{AccessReason, AgentConnection, BridgeEvent, ElevatedAction, ElevationOutcome};
pub use capture::{
    BackendKindView, BackendStatusView, CaptureCounters, CaptureFile, CaptureFileRequest,
    CaptureFiles, CaptureLive, CaptureRunState, CaptureSelection, CaptureStartRequest,
    CaptureStatus, InterfaceView, MissingView, PayloadView, ProtocolRate, RateView, RecordModeView,
    RecordStartRequest, RecordingResult, RecordingView, TalkerView,
};
pub use diag::{
    DiagEvent, DiagJobRequest, DiagStartResponse, DnsErrorView, DnsLookupRequest, DnsLookupView,
    DnsRecordView, EchoOutcome, LocalPort, LocalPorts, MtrHopView, MtrReport, MtrStartRequest,
    MtrView, PingReplyView, PingStartRequest, PingSummaryView, PortCheckRequest, PortCheckView,
    PortStateView, RttView,
};
pub use envelope::{Envelope, Kind, ShapeError, ENVELOPE_VERSION, MAX_FRAME_BYTES};
pub use error::{ErrorCode, ErrorPayload};
pub use firewall::{
    AllowlistConfig, BlockList, BlockRefusal, BlockRequest, BlockResult, BlockSource, BlockView,
    FirewallRuleAction, FirewallRuleEdit, FirewallRuleView, FirewallRules, FirewallRulesRequest,
    GuardianDecision, GuardianMode, GuardianPolicy, GuardianPreset, GuardianStatus, ProtectedEntry,
    PurgeRequest, PurgeResult, RuleAction, RuleDirection, SetGuardianPolicy, UnblockRequest,
};
pub use handshake::{ClientKind, HelloRequest, HelloResponse, PROTOCOL_MAJOR, PROTOCOL_MINOR};
pub use live::Heartbeat;
pub use netstat::{
    AuditState, Connection, ConnectionCounts, ConnectionsRequest, ConnectionsResponse,
    InterfaceKind, InterfaceStats, LiveStats, LogonAudit, Proto, RdpSession, RdpSessionState,
    RdpTrust, RemoteTalker, TcpState, TrafficTotals, TrustFeed, TrustedAddress,
    DEFAULT_CONNECTION_LIMIT,
};
pub use rdp::{
    RdpAttempts, RdpAudit, RdpConfirmRequest, RdpEndSessionRequest, RdpFinding, RdpLockoutRequest,
    RdpNlaRequest, RdpPending, RdpPortRequest, RdpRestrictRequest,
};
pub use subscribe::{SubscribeRequest, SubscribeResponse, UnsubscribeRequest};
pub use support::{
    SavedBundle, SupportBundleInfo, SupportBundleRequest, SupportChunk, SupportDiscardRequest,
    SupportItem, SupportPreview, SupportReadRequest,
};
pub use system::SystemInfo;

/// Request method names.
pub mod method {
    /// Must be the first request on every connection.
    pub const HELLO: &str = "session.hello";
    pub const SYSTEM_INFO: &str = "system.info";
    /// Full connection table (capped), see [`crate::ConnectionsResponse`].
    pub const NETSTAT_CONNECTIONS: &str = "netstat.connections";
    pub const DIAG_PING_START: &str = "diag.ping.start";
    pub const DIAG_MTR_START: &str = "diag.mtr.start";
    pub const DIAG_CANCEL: &str = "diag.cancel";
    pub const DIAG_MTR_REPORT: &str = "diag.mtr.report";
    pub const DIAG_DNS_LOOKUP: &str = "diag.dns.lookup";
    pub const DIAG_PORT_CHECK: &str = "diag.port.check";
    pub const DIAG_PORTS_LOCAL: &str = "diag.ports.local";
    pub const CAPTURE_STATUS: &str = "capture.status";
    pub const CAPTURE_START: &str = "capture.start";
    pub const CAPTURE_STOP: &str = "capture.stop";
    pub const CAPTURE_RECORD_START: &str = "capture.record.start";
    pub const CAPTURE_RECORD_STOP: &str = "capture.record.stop";
    pub const CAPTURE_FILES: &str = "capture.files";
    pub const CAPTURE_FILES_DELETE: &str = "capture.files.delete";
    pub const SUPPORT_PREVIEW: &str = "support.bundle.preview";
    pub const SUPPORT_CREATE: &str = "support.bundle.create";
    pub const SUPPORT_READ: &str = "support.bundle.read";
    pub const SUPPORT_DISCARD: &str = "support.bundle.discard";
    pub const FIREWALL_RULES: &str = "firewall.rules";
    pub const FIREWALL_RULE_ADD: &str = "firewall.rule.add";
    pub const FIREWALL_RULE_UPDATE: &str = "firewall.rule.update";
    pub const FIREWALL_RULE_REMOVE: &str = "firewall.rule.remove";
    pub const FIREWALL_RULE_ENABLE: &str = "firewall.rule.enable";
    pub const FIREWALL_BLOCKS: &str = "firewall.blocks";
    pub const FIREWALL_BLOCK: &str = "firewall.block";
    pub const FIREWALL_UNBLOCK: &str = "firewall.unblock";
    pub const FIREWALL_UNBLOCK_ALL: &str = "firewall.unblock_all";
    pub const FIREWALL_PURGE: &str = "firewall.purge";
    pub const GUARDIAN_STATUS: &str = "guardian.status";
    pub const GUARDIAN_SET_POLICY: &str = "guardian.set_policy";
    pub const GUARDIAN_ALLOWLIST: &str = "guardian.allowlist";
    pub const GUARDIAN_SET_ALLOWLIST: &str = "guardian.set_allowlist";
    pub const RDP_AUDIT: &str = "rdp.audit";
    pub const RDP_RESTRICT: &str = "rdp.restrict";
    pub const RDP_UNRESTRICT: &str = "rdp.unrestrict";
    pub const RDP_PORT: &str = "rdp.port";
    pub const RDP_NLA: &str = "rdp.nla";
    pub const RDP_LOCKOUT: &str = "rdp.lockout";
    pub const RDP_ATTEMPTS: &str = "rdp.attempts";
    pub const RDP_CONFIRM: &str = "rdp.confirm";
    pub const RDP_CANCEL: &str = "rdp.cancel";
    pub const RDP_RESET: &str = "rdp.reset";
    pub const RDP_END_SESSION: &str = "rdp.end_session";
    pub const ALERTS_LIST: &str = "alerts.list";
    pub const ALERTS_CLEAR: &str = "alerts.clear";
    pub const SUBSCRIBE: &str = "subscribe";
    pub const UNSUBSCRIBE: &str = "unsubscribe";
}

/// Server-push topic names.
pub mod topic {
    /// One event per second while subscribed; proves the agent is alive.
    pub const LIVE_HEARTBEAT: &str = "live.heartbeat";
    /// Aggregated traffic, connection counts and RDP sessions, once per second.
    pub const LIVE_STATS: &str = "live.stats";
    /// Progress of diagnostics jobs (ping replies, MTR snapshots), see [`crate::DiagEvent`].
    /// Live capture statistics once per second, see [`crate::CaptureLive`].
    pub const CAPTURE_STATS: &str = "capture.stats";
    /// Every change of an incident (started, escalated, ended), see [`crate::AlertView`].
    pub const ALERTS: &str = "alerts";
    pub const DIAG_PROGRESS: &str = "diag.progress";
}

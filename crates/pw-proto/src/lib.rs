// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-proto — IPC and shared DTOs (serde + ts-rs). Versioned, no logic.
//!
//! Every type that crosses the agent ⇄ UI/CLI boundary lives here. With the `ts-export`
//! feature the types also derive `ts_rs::TS`; `cargo test -p pw-proto --features ts-export`
//! regenerates `apps/desktop/src/types/generated`.

mod bridge;
mod diag;
mod envelope;
mod error;
mod handshake;
mod live;
mod netstat;
mod subscribe;
mod system;

pub use bridge::{AccessReason, AgentConnection, BridgeEvent, ElevatedAction, ElevationOutcome};
pub use diag::{
    DiagEvent, DiagJobRequest, DiagStartResponse, DnsErrorView, DnsLookupRequest, DnsLookupView,
    DnsRecordView, EchoOutcome, LocalPort, LocalPorts, MtrHopView, MtrReport, MtrStartRequest,
    MtrView, PingReplyView, PingStartRequest, PingSummaryView, PortCheckRequest, PortCheckView,
    PortStateView, RttView,
};
pub use envelope::{Envelope, Kind, ShapeError, ENVELOPE_VERSION, MAX_FRAME_BYTES};
pub use error::{ErrorCode, ErrorPayload};
pub use handshake::{ClientKind, HelloRequest, HelloResponse, PROTOCOL_MAJOR, PROTOCOL_MINOR};
pub use live::Heartbeat;
pub use netstat::{
    AuditState, Connection, ConnectionCounts, ConnectionsRequest, ConnectionsResponse,
    InterfaceKind, InterfaceStats, LiveStats, LogonAudit, Proto, RdpSession, RdpSessionState,
    RdpTrust, RemoteTalker, TcpState, TrafficTotals, TrustFeed, TrustedAddress,
    DEFAULT_CONNECTION_LIMIT,
};
pub use subscribe::{SubscribeRequest, SubscribeResponse, UnsubscribeRequest};
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
    pub const DIAG_PROGRESS: &str = "diag.progress";
}

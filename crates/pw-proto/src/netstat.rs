// SPDX-License-Identifier: GPL-3.0-or-later
//! Network state shared between the agent and its clients: connections, interfaces, RDP sessions
//! and the `live.stats` aggregate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Largest number of connection rows the agent returns by default (and at most). A SYN flood can
/// push the TCP table to tens of thousands of rows; the 4 MB frame cap must never be the limit.
pub const DEFAULT_CONNECTION_LIMIT: u32 = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

/// TCP connection state (`MIB_TCP_STATE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
}

/// One TCP connection / listener or UDP endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct Connection {
    pub proto: Proto,
    pub local_addr: String,
    pub local_port: u16,
    /// Empty for UDP endpoints and listeners bound to the wildcard.
    pub remote_addr: String,
    pub remote_port: u16,
    /// `None` for UDP, which has no state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub state: Option<TcpState>,
    pub pid: u32,
}

/// Payload of `netstat.connections`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ConnectionsRequest {
    /// Maximum rows to return; clamped to [`DEFAULT_CONNECTION_LIMIT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub limit: Option<u32>,
}

/// Reply to `netstat.connections`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ConnectionsResponse {
    pub connections: Vec<Connection>,
    /// Process names for the PIDs in `connections` (one entry per PID, not per row).
    #[cfg_attr(feature = "ts-export", ts(type = "Record<number, string>"))]
    pub processes: BTreeMap<u32, String>,
    /// Rows in the full table; `connections.len()` is smaller when `truncated`.
    pub total: u32,
    pub truncated: bool,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub sampled_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Ethernet,
    Wireless,
    /// VPN / tunnel adapters (WireGuard, ZeroTier, Radmin, TAP, ...): shown, never summed.
    Tunnel,
    Loopback,
    Other,
}

/// Rates of one network interface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct InterfaceStats {
    pub index: u32,
    pub name: String,
    pub description: String,
    pub kind: InterfaceKind,
    pub up: bool,
    /// Whether this interface is part of the totals (real adapters only).
    pub counts_toward_total: bool,
    /// Negotiated link speed in bits per second (0 when unknown).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub link_speed_bps: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub in_bps: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub out_bps: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub in_pps: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub out_pps: f64,
}

/// Sum over the interfaces that count toward the total.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct TrafficTotals {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub in_bps: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub out_bps: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub in_pps: f64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub out_pps: f64,
    /// Slowest negotiated link speed among the counted interfaces (0 when unknown).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub link_speed_bps: u64,
}

/// How many connections are in each state, computed from the full table.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ConnectionCounts {
    /// All TCP rows plus UDP endpoints.
    pub total: u32,
    pub established: u32,
    pub listen: u32,
    pub time_wait: u32,
    pub syn_received: u32,
    /// TCP rows in any other state.
    pub other_tcp: u32,
    pub udp: u32,
}

/// A remote address and how many connections it holds open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RemoteTalker {
    pub addr: String,
    pub connections: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum RdpSessionState {
    Active,
    Connected,
    Disconnected,
    Other,
}

/// A Remote Desktop session.
///
/// `reported_addr` is what the **client says** its address is (`WTSClientAddress`). It is often not
/// the address the server sees: behind NAT, a VPN or an overlay network it differs from the TCP peer
/// (verified on a live session: reported 100.x, TCP peer a public address). Anything that must act
/// on the real source (the badge, the Guardian's protected set) uses [`LiveStats::rdp_peers`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpSession {
    pub session_id: u32,
    pub user: String,
    pub state: RdpSessionState,
    /// The address the client reports for itself; informational only, see above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub reported_addr: Option<String>,
    pub client_name: String,
}

/// Payload of the `live.stats` topic (one per second).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct LiveStats {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub seq: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub unix_ms: u64,
    pub interfaces: Vec<InterfaceStats>,
    pub totals: TrafficTotals,
    pub connections: ConnectionCounts,
    pub top_remote: Vec<RemoteTalker>,
    pub rdp_sessions: Vec<RdpSession>,
    /// Addresses with an established TCP connection to the RDP port: the real RDP clients as the
    /// server sees them. Sorted, de-duplicated, loopback excluded.
    pub rdp_peers: Vec<String>,
    /// The TCP port the RDP listener uses (3389 unless reconfigured).
    pub rdp_port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_connection_has_no_state_on_the_wire() {
        let conn = Connection {
            proto: Proto::Udp,
            local_addr: "0.0.0.0".into(),
            local_port: 5353,
            remote_addr: String::new(),
            remote_port: 0,
            state: None,
            pid: 4,
        };
        let json = serde_json::to_string(&conn).unwrap();
        assert!(!json.contains("state"));
        assert_eq!(serde_json::from_str::<Connection>(&json).unwrap(), conn);
    }

    #[test]
    fn tcp_state_uses_snake_case() {
        assert_eq!(
            serde_json::to_string(&TcpState::SynReceived).unwrap(),
            r#""syn_received""#
        );
        assert_eq!(
            serde_json::from_str::<TcpState>(r#""time_wait""#).unwrap(),
            TcpState::TimeWait
        );
    }

    #[test]
    fn an_empty_connections_request_means_default_limit() {
        let request: ConnectionsRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(request.limit, None);
        assert_eq!(serde_json::to_string(&request).unwrap(), "{}");
    }
}

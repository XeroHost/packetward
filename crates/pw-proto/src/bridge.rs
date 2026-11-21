// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Types the desktop shell sends to its webview (not part of the agent protocol).
//!
//! They live here so every type crossing a process boundary is exported to TypeScript from one
//! place.

use serde::{Deserialize, Serialize};

use crate::{AlertView, CaptureLive, DiagEvent, Heartbeat, LiveStats, McpPendingList, SpeedEvent};

/// Why the agent pipe refused this Windows user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum AccessReason {
    /// The `PacketWard Operators` group does not exist.
    GroupMissing,
    /// The group exists but this user is not in it.
    NotMember,
    /// The user was added but must sign out and back in for Windows to apply it.
    SignOutRequired,
    /// Member, token is current, yet access was denied.
    Unexplained,
}

/// Where the connection to the agent stands. Anything but `connected` means the app shows the
/// "agent unavailable" screen instead of a half-working UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AgentConnection {
    Connecting,
    Connected {
        agent_version: String,
        protocol_major: u16,
        protocol_minor: u16,
    },
    /// The service is not registered with Windows.
    NotInstalled,
    /// Registered but not running.
    Stopped,
    /// Start requested; the pipe is not up yet.
    Starting,
    AccessDenied {
        reason: AccessReason,
    },
    /// The agent speaks an older protocol than this app.
    AgentOutdated {
        agent_version: String,
    },
    /// The agent speaks a newer protocol than this app.
    UiOutdated {
        agent_version: String,
    },
    Error {
        message: String,
    },
}

/// One message on the `agent_watch` channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum BridgeEvent {
    Status(AgentConnection),
    Heartbeat(Heartbeat),
    Stats(LiveStats),
    Diag(DiagEvent),
    Capture(CaptureLive),
    Alert(AlertView),
    Speed(SpeedEvent),
    /// The whole MCP approval queue, on every change (see ARCHITECTURE 6.14).
    McpPending(McpPendingList),
}

/// What the UI may ask the agent executable to do with administrator rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum ElevatedAction {
    /// Start the installed service.
    Start,
    /// Install or repair the service and the operators group, then start it.
    Repair,
}

/// Outcome of an elevated Start/Repair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ElevationOutcome {
    Done,
    /// The user declined the UAC prompt.
    Cancelled,
    Failed {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_tagged_by_state() {
        let json = serde_json::to_string(&AgentConnection::AccessDenied {
            reason: AccessReason::SignOutRequired,
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"state":"access_denied","reason":"sign_out_required"}"#
        );
        let json = serde_json::to_string(&AgentConnection::NotInstalled).unwrap();
        assert_eq!(json, r#"{"state":"not_installed"}"#);
    }

    #[test]
    fn events_are_adjacently_tagged() {
        let beat = Heartbeat {
            seq: 3,
            uptime_secs: 9,
            unix_ms: 1,
        };
        let json = serde_json::to_string(&BridgeEvent::Heartbeat(beat)).unwrap();
        assert_eq!(
            json,
            r#"{"type":"heartbeat","data":{"seq":3,"uptime_secs":9,"unix_ms":1}}"#
        );
        let pending = McpPendingList {
            actions: vec![crate::McpPendingAction {
                id: 7,
                tool: "block_ip".into(),
                args: serde_json::json!({ "ip": "203.0.113.9" }),
                summary: "Block 203.0.113.9".into(),
                created_ts: 1_000,
                expires_ts: 300_000_001_000,
            }],
        };
        let json = serde_json::to_string(&BridgeEvent::McpPending(pending)).unwrap();
        assert_eq!(
            json,
            r#"{"type":"mcp_pending","data":{"actions":[{"id":7,"tool":"block_ip","args":{"ip":"203.0.113.9"},"summary":"Block 203.0.113.9","created_ts":1000,"expires_ts":300000001000}]}}"#
        );
    }
}

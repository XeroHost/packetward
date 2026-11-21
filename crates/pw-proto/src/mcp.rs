// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! MCP server settings and the pending-action approval flow (milestone M11, ARCHITECTURE 6.14).

use serde::{Deserialize, Serialize};

/// Level of an execution tool in the MCP policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub enum McpToolLevel {
    /// Not offered to the AI at all (the default).
    Disabled,
    /// Runs at once, under the Guardian's safety rules and the MCP write rate limit.
    Automatic,
    /// Waits in the agent for the owner's approval in the desktop, for 5 minutes.
    Approval,
}

/// One execution tool and its level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct McpToolSetting {
    pub tool: String,
    pub level: McpToolLevel,
}

/// Reply to `mcp.settings.get`: the MCP policy as the Settings page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct McpSettingsView {
    /// The master switch (off by default). While it is off the agent refuses every MCP request.
    pub enabled: bool,
    /// All MCP writes together, per minute (default 6); an over-limit call is refused, not queued.
    pub write_limit_per_min: u32,
    /// One entry per execution tool; read tools are always on once the switch is on.
    pub tools: Vec<McpToolSetting>,
}

/// Payload of `mcp.settings.set`; an absent field keeps the saved value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct McpSettingsSetRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub write_limit_per_min: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub tools: Option<Vec<McpToolSetting>>,
}

/// An `approval`-level call waiting for the owner's decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct McpPendingAction {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub id: u64,
    pub tool: String,
    /// The full arguments the AI sent.
    #[cfg_attr(feature = "ts-export", ts(type = "unknown"))]
    pub args: serde_json::Value,
    /// Plain-words description of the action, shown in the banner/dialog.
    pub summary: String,
    /// Created at, nanoseconds since the Unix epoch (the agent clock).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub created_ts: u64,
    /// Expires at, nanoseconds since the Unix epoch (5 minutes after `created_ts`).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub expires_ts: u64,
}

/// Reply to `mcp.pending.list` and the payload of the `mcp.pending` topic: a full snapshot on every
/// change.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct McpPendingList {
    pub actions: Vec<McpPendingAction>,
}

/// Payload of `mcp.approve` (desktop and `pwctl` only; refused for `ClientKind::Mcp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct McpApproveRequest {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub id: u64,
}

/// Payload of `mcp.reject` (desktop and `pwctl` only; refused for `ClientKind::Mcp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct McpRejectRequest {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub id: u64,
}

/// Payload of `mcp.action.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct McpActionStatusRequest {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub id: u64,
}

/// Outcome of a pending action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub enum McpActionStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Failed,
}

/// Reply to `mcp.action.status` (`action_status` in the MCP tool catalog).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct McpActionStatusView {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub id: u64,
    pub status: McpActionStatus,
    /// The tool's result once it ran (only with `approved`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional, type = "unknown"))]
    pub result: Option<serde_json::Value>,
    /// Why it failed (only with `failed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_use_lowercase() {
        let json = serde_json::to_string(&McpToolLevel::Approval).unwrap();
        assert_eq!(json, r#""approval""#);
        let level: McpToolLevel = serde_json::from_str(r#""automatic""#).unwrap();
        assert_eq!(level, McpToolLevel::Automatic);
    }

    #[test]
    fn statuses_use_lowercase() {
        let json = serde_json::to_string(&McpActionStatus::Expired).unwrap();
        assert_eq!(json, r#""expired""#);
        let status: McpActionStatus = serde_json::from_str(r#""pending""#).unwrap();
        assert_eq!(status, McpActionStatus::Pending);
    }

    #[test]
    fn a_pending_action_round_trips() {
        let action = McpPendingAction {
            id: 7,
            tool: "block_ip".into(),
            args: serde_json::json!({ "ip": "203.0.113.9", "ttl_secs": 3600 }),
            summary: "Block 203.0.113.9 for one hour".into(),
            created_ts: 1_000,
            expires_ts: 300_000_001_000,
        };
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""tool":"block_ip""#));
        assert!(json.contains(r#""created_ts":1000"#));
        let back: McpPendingAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, action);
    }

    #[test]
    fn an_empty_settings_update_keeps_every_value() {
        let request: McpSettingsSetRequest = serde_json::from_str("{}").unwrap();
        assert!(request.enabled.is_none());
        assert!(request.write_limit_per_min.is_none());
        assert!(request.tools.is_none());
        assert_eq!(serde_json::to_string(&request).unwrap(), "{}");
        let view = McpSettingsView {
            enabled: false,
            write_limit_per_min: 6,
            tools: vec![McpToolSetting {
                tool: "block_ip".into(),
                level: McpToolLevel::Disabled,
            }],
        };
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains(r#""level":"disabled""#));
        assert!(json.contains(r#""write_limit_per_min":6"#));
    }

    #[test]
    fn the_status_view_omits_an_absent_result_and_error() {
        let view = McpActionStatusView {
            id: 7,
            status: McpActionStatus::Pending,
            result: None,
            error: None,
        };
        let json = serde_json::to_string(&view).unwrap();
        assert_eq!(json, r#"{"id":7,"status":"pending"}"#);
        let done: McpActionStatusView =
            serde_json::from_str(r#"{"id":7,"status":"approved","result":{"ok":true}}"#).unwrap();
        assert_eq!(done.result, Some(serde_json::json!({ "ok": true })));
        assert!(done.error.is_none());
    }
}

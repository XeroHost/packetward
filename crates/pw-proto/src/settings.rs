// SPDX-License-Identifier: GPL-3.0-or-later
//! Agent settings (M11) and the audit log viewer.

use serde::{Deserialize, Serialize};

/// Settings of the agent, as shown by the Settings page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AgentSettingsView {
    /// The proxy saved in the settings (`http://`, `https://`, `socks5://`); absent = the system proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub proxy: Option<String>,
    /// The proxy the running agent was started with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub applied_proxy: Option<String>,
    /// The saved proxy differs from the running one: restart the PacketWard service to apply it.
    pub restart_required: bool,
}

/// Payload of `settings.set_proxy`; an absent proxy goes back to the system proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ProxyRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub proxy: Option<String>,
}

/// Payload of `logs.audit`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AuditQuery {
    /// Newest entries returned, 1..=2000 (default 500).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub limit: Option<u32>,
    /// Keep only entries whose actor, action, target, detail or result contain this text (case-insensitive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub search: Option<String>,
}

/// One audited action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AuditEntryView {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub unix_ms: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub result: String,
}

/// Reply to `logs.audit`, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AuditView {
    pub entries: Vec<AuditEntryView>,
    /// More entries matched than were returned.
    pub truncated: bool,
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! RDP Shield (M7b): exposure audit and the guarded changes to Remote Desktop.

use serde::{Deserialize, Serialize};

use crate::AlertSeverity;

/// One thing the audit found, with the severity of leaving it as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpFinding {
    /// Stable key for the translated title and recommendation, for example `nla_off`.
    pub id: String,
    pub severity: AlertSeverity,
    /// A value to show with the finding (the port, the number of failures…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub value: Option<String>,
}

/// A change waiting for confirmation: without it the agent puts everything back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpPending {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub id: u64,
    /// `restrict`, `port`, `nla` or `lockout`.
    pub kind: String,
    /// What was changed, in plain words.
    pub description: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub deadline_unix_ms: u64,
}

/// Attempt limit per address: this many failed logons within the window raise the brute-force alert
/// that the Guardian acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpAttempts {
    pub threshold: u32,
    pub window_secs: u32,
}

/// Reply to `rdp.audit` and to every change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpAudit {
    pub enabled: bool,
    pub port: u16,
    pub nla_required: bool,
    /// 0 RDP, 1 negotiate, 2 TLS.
    pub security_layer: u32,
    /// Failed logons before Windows locks the account; 0 = never.
    pub lockout_threshold: u32,
    pub lockout_window_mins: u32,
    pub lockout_duration_mins: u32,
    pub remote_desktop_users: Vec<String>,
    /// An enabled inbound rule lets any address reach the RDP port.
    pub open_to_any: bool,
    /// PacketWard restricts RDP to `allowed`.
    pub restricted: bool,
    pub allowed: Vec<String>,
    pub builtin_rules_enabled: bool,
    pub attempts: RdpAttempts,
    pub findings: Vec<RdpFinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub pending: Option<RdpPending>,
    /// Seconds the user has to confirm a change before it is reverted.
    pub confirm_secs: u32,
}

/// Payload of `rdp.restrict`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpRestrictRequest {
    /// Addresses or CIDR blocks that may connect, in addition to every address with a successful
    /// logon (those are always included).
    pub allowed: Vec<String>,
    /// Also turn the built-in Remote Desktop rules off (they allow everybody). Needs the typed phrase.
    #[serde(default)]
    pub disable_builtin: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub confirmation: Option<String>,
}

/// Payload of `rdp.port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpPortRequest {
    pub port: u16,
    /// The user understands every Remote Desktop session is disconnected when the service restarts.
    #[serde(default)]
    pub i_understand: bool,
}

/// Payload of `rdp.nla`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpNlaRequest {
    pub required: bool,
}

/// Payload of `rdp.lockout` (Windows account lockout; off by default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpLockoutRequest {
    /// 0 turns the lockout off.
    pub threshold: u32,
    pub window_mins: u32,
    pub duration_mins: u32,
    /// The user understands an attacker can lock a legitimate account on purpose.
    #[serde(default)]
    pub understand_dos: bool,
}

/// Payload of `rdp.confirm` and `rdp.cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpConfirmRequest {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub id: u64,
}

/// Payload of `rdp.end_session`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct RdpEndSessionRequest {
    pub session_id: u32,
    /// End the session (log off) instead of only disconnecting it.
    #[serde(default)]
    pub logoff: bool,
}

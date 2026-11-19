// SPDX-License-Identifier: GPL-3.0-or-later
//! Types for the RDP Shield primitives (M7b): a restricted allow rule, the built-in rules' previous
//! state, and a serializable snapshot a caller can persist and use to revert.

use std::net::IpAddr;

use pw_core::Cidr;
use serde::{Deserialize, Serialize};

use crate::model::Rule;

/// Current snapshot format version.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Name and enabled flag of a rule, to restore it later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleState {
    pub name: String,
    pub enabled: bool,
}

/// RDP-related firewall state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdpState {
    /// The RDP port when the snapshot was taken.
    pub port: u16,
    /// Built-in "Remote Desktop" allow rules and whether they were enabled.
    pub builtin: Vec<RuleState>,
    /// PacketWard's own RDP allow rules (`PW-RDP-Allow`, `PW-RDP-Allow-UDP`) as they existed; empty
    /// when the shield was not active.
    pub shield: Vec<Rule>,
}

/// Everything needed to put the RDP-related firewall state back. Persist it (it is plain serde)
/// before applying a change so a revert survives an agent restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallSnapshot {
    pub version: u32,
    /// Unix seconds supplied by the caller.
    pub taken_at: u64,
    pub rdp: RdpState,
}

/// Request to restrict RDP to a list of remote addresses.
#[derive(Debug, Clone, Copy)]
pub struct RdpRestrict<'a> {
    pub port: u16,
    /// Remote addresses allowed to connect. Must not be empty.
    pub allowed: &'a [Cidr],
    /// Addresses that must remain reachable (the current and trusted RDP clients). The request is
    /// refused when the allow list does not cover every one of them.
    pub required_clients: &'a [IpAddr],
    /// Also create the UDP rule (`PW-RDP-Allow-UDP`).
    pub include_udp: bool,
    /// Turn the built-in Remote Desktop rules off (they allow everybody). Needs the typed
    /// confirmation; without it the allow rule is only added.
    pub disable_builtin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpRestrictOutcome {
    /// State before the change; pass it to `restore_snapshot` to revert.
    pub snapshot: FirewallSnapshot,
    pub created_or_updated: Vec<String>,
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub reenabled: Vec<String>,
    pub redisabled: Vec<String>,
    pub shield_removed: Vec<String>,
    pub shield_restored: Vec<String>,
    /// Built-in rules named in the snapshot that no longer exist.
    pub missing: Vec<String>,
}

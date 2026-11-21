// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Firewall manager and Guardian (M6, M7): rules, blocks, protected set, audit.

use serde::{Deserialize, Serialize};

use crate::AlertSeverity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum RuleDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Block,
}

/// One Windows Firewall rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct FirewallRuleView {
    pub name: String,
    pub description: String,
    /// Rule group (`PacketWard` for rules this app made).
    pub group: String,
    pub direction: RuleDirection,
    pub action: RuleAction,
    pub enabled: bool,
    /// `any`, `tcp`, `udp`, `icmpv4`, `icmpv6` or an IP protocol number.
    pub protocol: String,
    /// `*` or a list such as `80,443,1000-2000`.
    pub local_ports: String,
    pub remote_ports: String,
    pub local_addresses: String,
    pub remote_addresses: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub service: Option<String>,
    /// Created by PacketWard (group `PacketWard`).
    pub managed: bool,
    /// One of the built-in Remote Desktop rules: turning it off can lock you out.
    pub builtin_rdp: bool,
}

/// Payload of `firewall.rules`; every field narrows the list.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct FirewallRulesRequest {
    #[serde(default)]
    pub managed_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub direction: Option<RuleDirection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub enabled: Option<bool>,
    /// Matches the name, description, group or program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct FirewallRules {
    pub rules: Vec<FirewallRuleView>,
    /// Rules that matched before the list was cut to a displayable size.
    pub total: u32,
    pub truncated: bool,
}

/// Payload of `firewall.rule.add` and `firewall.rule.update`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct FirewallRuleEdit {
    pub rule: FirewallRuleView,
    /// The user saw the warning that this is not a PacketWard rule.
    #[serde(default)]
    pub allow_foreign_edit: bool,
    /// The typed lock-out confirmation phrase, when the change can cut RDP off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub confirmation: Option<String>,
}

/// Payload of `firewall.rule.remove` and `firewall.rule.enable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct FirewallRuleAction {
    pub name: String,
    /// Only for `enable`: the new state.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_foreign_edit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub confirmation: Option<String>,
}

/// Payload of `firewall.block`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct BlockRequest {
    /// Addresses or CIDR blocks, for example `203.0.113.7` or `198.51.100.0/24`.
    pub targets: Vec<String>,
    /// Remove the block after this many seconds; absent = until removed by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub reason: String,
    /// Allow blocks wider than /8 (IPv4) or /16 (IPv6).
    #[serde(default)]
    pub allow_broad: bool,
}

/// Reply to `firewall.block`: what was done and what was refused (never silently).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct BlockResult {
    pub blocked: Vec<String>,
    /// Refused because they are protected (RDP client, gateway, DNS, allowlist…), with the reason.
    pub refused_protected: Vec<BlockRefusal>,
    /// Refused because the range is too wide.
    pub refused_broad: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct BlockRefusal {
    pub target: String,
    pub reason: String,
}

/// Payload of `firewall.unblock`; empty `targets` is an error (use `firewall.unblock_all`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct UnblockRequest {
    pub targets: Vec<String>,
}

/// Where a block came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum BlockSource {
    /// By hand (UI or pwctl).
    Manual,
    /// By the Guardian after an alert.
    Guardian,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct BlockView {
    pub cidr: String,
    pub source: BlockSource,
    pub reason: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub created_unix_ms: u64,
    /// Absent = permanent until removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub expires_unix_ms: Option<u64>,
    /// The alert that caused a Guardian block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub alert_id: Option<u64>,
    /// How many times this address was blocked before (drives longer blocks).
    pub escalation: u8,
}

/// Reply to `firewall.blocks`, `firewall.unblock` and `firewall.unblock_all`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct BlockList {
    pub blocks: Vec<BlockView>,
    /// Firewall rules the blocks occupy (many addresses share one rule).
    pub rules_used: u32,
}

/// Payload of `firewall.purge`: removes every PacketWard rule.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct PurgeRequest {
    /// The typed phrase, needed when a PacketWard RDP rule exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub confirmation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct PurgeResult {
    pub removed_rules: Vec<String>,
}

// ---- Guardian ---------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum GuardianMode {
    /// Does nothing.
    Off,
    /// Decides but only records what it would block (the default of a fresh install).
    Monitor,
    /// Blocks automatically, with limits.
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum GuardianPreset {
    Gentle,
    Balanced,
    Strict,
}

/// What the Guardian does. Every value is validated and clamped by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct GuardianPolicy {
    pub mode: GuardianMode,
    /// How sensitive the detectors are (Gentle/Balanced/Strict).
    pub preset: GuardianPreset,
    /// Only alerts at or above this severity can lead to a block.
    pub min_severity: AlertSeverity,
    /// Block durations: the first offence gets the first entry, a repeat the next, and so on.
    /// Seconds, each between a minute and 30 days, at most 6 steps.
    #[cfg_attr(feature = "ts-export", ts(type = "Array<number>"))]
    pub ttl_ladder_secs: Vec<u64>,
    /// Circuit breaker: at most this many automatic blocks per hour (1..=500); beyond that the
    /// Guardian stops blocking, records it and waits.
    pub max_blocks_per_hour: u32,
}

impl Default for GuardianPolicy {
    fn default() -> Self {
        Self {
            mode: GuardianMode::Monitor,
            preset: GuardianPreset::Balanced,
            min_severity: AlertSeverity::High,
            ttl_ladder_secs: vec![15 * 60, 60 * 60, 24 * 60 * 60, 7 * 24 * 60 * 60],
            max_blocks_per_hour: 20,
        }
    }
}

/// Why an address is protected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ProtectedEntry {
    pub cidr: String,
    /// `loopback`, `gateway`, `dns`, `rdp_client`, `allowlist` or `management`.
    pub reason: String,
}

/// One decision the Guardian took (or, in Monitor mode, would have taken).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct GuardianDecision {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub unix_ms: u64,
    pub source: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub alert_id: u64,
    pub summary_key: String,
    pub severity: AlertSeverity,
    /// `blocked`, `would_block`, `skipped_protected`, `skipped_circuit`, `skipped_below_threshold`,
    /// `skipped_failed`.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub ttl_secs: Option<u64>,
    /// Plain-language explanation ("why was this blocked").
    pub why: String,
}

/// Reply to `guardian.status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct GuardianStatus {
    pub policy: GuardianPolicy,
    /// The circuit breaker tripped: no automatic blocks until it resets.
    pub circuit_open: bool,
    pub blocks_last_hour: u32,
    pub protected: Vec<ProtectedEntry>,
    /// Newest first, bounded.
    pub decisions: Vec<GuardianDecision>,
    /// Monitor report: addresses it would have blocked in the last 24 hours.
    pub would_block_24h: u32,
}

/// Payload of `guardian.set_policy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SetGuardianPolicy {
    pub policy: GuardianPolicy,
    /// Required when switching to `active`: the user saw the Monitor report and confirmed.
    #[serde(default)]
    pub confirm_active: bool,
}

/// The user's allowlist and management ranges, kept in the agent.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AllowlistConfig {
    /// Addresses or CIDR blocks that are never blocked.
    pub allowlist: Vec<String>,
    /// XeroHost management ranges (also never blocked).
    pub management: Vec<String>,
}

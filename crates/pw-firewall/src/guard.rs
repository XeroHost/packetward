// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure safety checks applied before anything is written to the firewall.
//!
//! * protected set: never block loopback, the gateway, DNS, the allowlist, RDP clients, ...
//! * breadth: refuse a /0 or absurdly short prefixes without an explicit override
//! * lockout: refuse deleting/disabling the RDP allow rules (or adding a block that cuts RDP off)
//!   without a typed confirmation

use std::collections::HashSet;
use std::fmt;

use pw_core::{Cidr, CidrSet};

use crate::addr::{self, cidr_span, AddrToken, Span};
use crate::error::{FirewallError, RefusedBlocks, Result};
use crate::model::{Action, Direction, Protocol, Rule};

/// IPv4 blocks shorter than this are "too broad" without `allow_broad`.
pub const MIN_PREFIX_V4: u8 = 8;
/// IPv6 blocks shorter than this are "too broad" without `allow_broad`.
pub const MIN_PREFIX_V6: u8 = 16;

/// Addresses that are never blocked, whatever the caller supplies: loopback, unspecified, link-local
/// and multicast. The caller's protected set adds the gateway, DNS, allowlist, RDP clients, ...
pub fn hard_floor() -> CidrSet {
    let mut set = CidrSet::new();
    for block in [
        "127.0.0.0/8",
        "0.0.0.0/32",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "::1/128",
        "::/128",
        "fe80::/10",
        "ff00::/8",
    ] {
        // The literals above are valid; a parse failure would just leave the floor smaller, which is
        // caught by the `hard_floor_has_every_block` test.
        let _ = set.insert_str(block);
    }
    set
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtectedPolicy {
    /// Any protected or too-broad entry fails the whole operation; nothing is applied.
    #[default]
    Fail,
    /// Drop the offending entries, apply the rest, and report what was skipped.
    SkipProtected,
}

#[derive(Debug, Clone, Copy)]
pub struct BlockOptions<'a> {
    /// Addresses that must never be blocked (in addition to the built-in floor).
    pub protected: &'a CidrSet,
    pub policy: ProtectedPolicy,
    /// Allow prefixes shorter than /8 (IPv4) or /16 (IPv6). Protected addresses still win.
    pub allow_broad: bool,
}

impl<'a> BlockOptions<'a> {
    pub fn new(protected: &'a CidrSet) -> Self {
        Self {
            protected,
            policy: ProtectedPolicy::Fail,
            allow_broad: false,
        }
    }

    pub fn skip_protected(mut self) -> Self {
        self.policy = ProtectedPolicy::SkipProtected;
        self
    }

    pub fn allow_broad(mut self) -> Self {
        self.allow_broad = true;
        self
    }
}

/// Result of screening a candidate list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Screened {
    pub accepted: Vec<Cidr>,
    pub skipped_protected: Vec<Cidr>,
    pub skipped_broad: Vec<Cidr>,
}

/// The protected spans, computed once per call.
pub struct ProtectedSpans(Vec<Span>);

impl ProtectedSpans {
    pub fn new(protected: &CidrSet) -> Self {
        let mut spans: Vec<Span> = hard_floor().iter().map(cidr_span).collect();
        spans.extend(protected.iter().map(cidr_span));
        Self(spans)
    }

    pub fn overlaps(&self, span: &Span) -> bool {
        self.0.iter().any(|p| p.overlaps(span))
    }
}

pub fn is_too_broad(block: &Cidr) -> bool {
    let min = if block.network().is_ipv4() {
        MIN_PREFIX_V4
    } else {
        MIN_PREFIX_V6
    };
    block.prefix() < min
}

/// Checks `candidates` against the protected set and the breadth limit. With `Fail`, any problem is a
/// typed error listing everything refused; with `SkipProtected` the offenders are dropped and listed.
pub fn screen_blocks(candidates: &[Cidr], opts: &BlockOptions<'_>) -> Result<Screened> {
    let spans = ProtectedSpans::new(opts.protected);
    let mut seen = HashSet::new();
    let mut out = Screened::default();
    for block in candidates {
        if !seen.insert(*block) {
            continue;
        }
        if spans.overlaps(&cidr_span(block)) {
            out.skipped_protected.push(*block);
        } else if !opts.allow_broad && is_too_broad(block) {
            out.skipped_broad.push(*block);
        } else {
            out.accepted.push(*block);
        }
    }
    let refused = !out.skipped_protected.is_empty() || !out.skipped_broad.is_empty();
    if refused && opts.policy == ProtectedPolicy::Fail {
        return Err(FirewallError::Refused(RefusedBlocks {
            protected: out.skipped_protected,
            too_broad: out.skipped_broad,
        }));
    }
    Ok(out)
}

/// Why an operation needs the typed confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockoutReason {
    /// A built-in "Remote Desktop" allow rule.
    BuiltinRdpRule,
    /// An inbound allow rule for the RDP port.
    RdpPortAllow { port: u16 },
    /// A block rule that would cut off RDP for every address.
    BlocksRdp { port: u16 },
    /// Disabling the built-in rules is the point of the RDP restriction.
    RestrictRdp,
}

impl fmt::Display for LockoutReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuiltinRdpRule => f.write_str("built-in Remote Desktop allow rule"),
            Self::RdpPortAllow { port } => write!(f, "inbound allow rule for RDP port {port}"),
            Self::BlocksRdp { port } => write!(f, "block rule that cuts off RDP port {port}"),
            Self::RestrictRdp => f.write_str("restricting RDP turns the built-in rules off"),
        }
    }
}

/// What a user must type to confirm an operation that can lock them out of RDP.
pub const CONFIRMATION_PHRASE: &str = "I understand this may lock me out of RDP";

/// Proof that the user typed [`CONFIRMATION_PHRASE`]. Only constructible through
/// [`Confirmation::from_phrase`], so a caller cannot pass one without asking.
#[derive(Debug, Clone)]
pub struct Confirmation(());

impl Confirmation {
    pub fn from_phrase(typed: &str) -> Result<Self> {
        let norm = |s: &str| {
            s.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase()
        };
        if norm(typed) == norm(CONFIRMATION_PHRASE) {
            Ok(Self(()))
        } else {
            Err(FirewallError::BadConfirmation)
        }
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Group resource strings of the built-in Remote Desktop rules as COM reports them (observed on
/// Windows Server 2025: `Name` comes back resolved, `Grouping` as the resource string).
const RDP_GROUP_TOKENS: [&str; 2] = ["@FirewallAPI.dll,-28752", "@FirewallAPI.dll,-28782"];

/// The built-in "Remote Desktop - User Mode (TCP-In/UDP-In)" family (inbound allow rules of the
/// Remote Desktop group). Matches on the group, whether Windows reports it resolved ("Remote
/// Desktop") or as a resource string (`@FirewallAPI.dll,-28752`), and on the name.
pub fn is_builtin_rdp_rule(rule: &Rule) -> bool {
    if rule.direction != Direction::Inbound || rule.action != Action::Allow || rule.is_managed() {
        return false;
    }
    if contains_ci(&rule.name, "shadow") {
        return false;
    }
    contains_ci(&rule.grouping, "remote desktop")
        || RDP_GROUP_TOKENS
            .iter()
            .any(|t| rule.grouping.eq_ignore_ascii_case(t))
        || contains_ci(&rule.name, "remote desktop")
}

/// An enabled inbound allow rule that names the RDP port explicitly.
pub fn is_rdp_port_allow(rule: &Rule, port: u16) -> bool {
    rule.direction == Direction::Inbound
        && rule.action == Action::Allow
        && rule.enabled
        && rule.protocol.has_ports()
        && !addr::ports_any(&rule.local_ports)
        && addr::ports_include(&rule.local_ports, port)
}

/// An enabled inbound block rule that denies RDP to every address.
pub fn blocks_rdp_for_everyone(rule: &Rule, port: u16) -> bool {
    rule.direction == Direction::Inbound
        && rule.action == Action::Block
        && rule.enabled
        && matches!(rule.protocol, Protocol::Any | Protocol::Tcp | Protocol::Udp)
        && (!rule.protocol.has_ports() || addr::ports_include(&rule.local_ports, port))
        && rule.remote_is_any()
}

/// Is this existing rule one whose removal/disabling can lock the user out of RDP?
pub fn lockout_class(rule: &Rule, rdp_port: u16) -> Option<LockoutReason> {
    if is_builtin_rdp_rule(rule) {
        Some(LockoutReason::BuiltinRdpRule)
    } else if is_rdp_port_allow(rule, rdp_port) {
        Some(LockoutReason::RdpPortAllow { port: rdp_port })
    } else {
        None
    }
}

/// Does turning `old` into `new` materially change a lockout-critical rule? (A description change is
/// fine; anything about *who or what* it admits is not.)
pub fn materially_changes(old: &Rule, new: &Rule) -> bool {
    old.enabled != new.enabled
        || old.direction != new.direction
        || old.action != new.action
        || old.protocol != new.protocol
        || old.local_ports != new.local_ports
        || old.profiles != new.profiles
        || addr::windows_readback(&old.remote_addresses)
            != addr::windows_readback(&new.remote_addresses)
}

/// Checks a block rule the user wants to add or edit through the generic rule API (batch blocks have
/// their own path through [`screen_blocks`]). Returns the lockout reason when the rule would cut off
/// RDP for everyone.
pub fn check_block_rule(
    rule: &Rule,
    protected: &CidrSet,
    allow_broad: bool,
    rdp_port: u16,
) -> Result<Option<LockoutReason>> {
    let spans = ProtectedSpans::new(protected);
    let mut refused = RefusedBlocks::default();
    for token in rule.remote_tokens() {
        match token {
            AddrToken::Any => {}
            AddrToken::Keyword(k) => {
                return Err(FirewallError::InvalidRule(format!(
                    "block rules cannot use the address keyword {k}"
                )))
            }
            AddrToken::Invalid(t) => {
                return Err(FirewallError::InvalidRule(format!(
                    "unrecognized remote address {t:?}"
                )))
            }
            AddrToken::Span(span) => {
                let block = span.to_cidr();
                if spans.overlaps(&span) {
                    // A range that is not a block is reported by its first address.
                    match block.or_else(|| single_host(&span)) {
                        Some(b) => refused.protected.push(b),
                        None => {
                            return Err(FirewallError::InvalidRule(
                                "remote address range overlaps a protected address".into(),
                            ))
                        }
                    }
                } else if !allow_broad && block.is_some_and(|b| is_too_broad(&b)) {
                    refused.too_broad.extend(block);
                }
            }
        }
    }
    if !refused.is_empty() {
        return Err(FirewallError::Refused(refused));
    }
    Ok(blocks_rdp_for_everyone(rule, rdp_port)
        .then_some(LockoutReason::BlocksRdp { port: rdp_port }))
}

fn single_host(span: &Span) -> Option<Cidr> {
    if span.v6 {
        Cidr::new(std::net::Ipv6Addr::from(span.lo).into(), 128).ok()
    } else {
        let v4 = std::net::Ipv4Addr::from(u32::try_from(span.lo).ok()?);
        Cidr::new(v4.into(), 32).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(t: &str) -> Cidr {
        t.parse().unwrap()
    }

    fn set(blocks: &[&str]) -> CidrSet {
        let mut s = CidrSet::new();
        for b in blocks {
            s.insert_str(b).unwrap();
        }
        s
    }

    #[test]
    fn hard_floor_has_every_block() {
        assert_eq!(hard_floor().len(), 8);
    }

    #[test]
    fn a_protected_address_refuses_the_whole_batch() {
        let protected = set(&["203.0.113.9", "192.0.2.0/24"]);
        let opts = BlockOptions::new(&protected);
        let err = screen_blocks(
            &[
                cidr("198.51.100.1"),
                cidr("203.0.113.9"),
                cidr("192.0.2.77"),
            ],
            &opts,
        )
        .unwrap_err();
        match err {
            FirewallError::Refused(r) => {
                assert_eq!(r.protected, vec![cidr("203.0.113.9"), cidr("192.0.2.77")]);
                assert!(r.too_broad.is_empty());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn overlap_not_just_containment_is_refused() {
        // The /24 contains the protected gateway even though no listed address equals it.
        let protected = set(&["203.0.113.1"]);
        let opts = BlockOptions::new(&protected);
        assert!(screen_blocks(&[cidr("203.0.113.0/24")], &opts).is_err());
        assert!(screen_blocks(&[cidr("203.0.114.0/24")], &opts).is_ok());
    }

    #[test]
    fn skip_policy_keeps_the_rest_and_reports_the_skipped() {
        let protected = set(&["203.0.113.9"]);
        let opts = BlockOptions::new(&protected).skip_protected();
        let out = screen_blocks(
            &[
                cidr("198.51.100.1"),
                cidr("203.0.113.9"),
                cidr("198.51.100.1"),
            ],
            &opts,
        )
        .unwrap();
        assert_eq!(out.accepted, vec![cidr("198.51.100.1")]);
        assert_eq!(out.skipped_protected, vec![cidr("203.0.113.9")]);
    }

    #[test]
    fn the_floor_applies_even_with_an_empty_protected_set() {
        let none = CidrSet::new();
        let opts = BlockOptions::new(&none);
        for bad in [
            "127.0.0.1",
            "127.0.0.0/8",
            "::1",
            "169.254.1.1",
            "fe80::1",
            "224.0.0.1",
        ] {
            assert!(screen_blocks(&[cidr(bad)], &opts).is_err(), "{bad}");
        }
        // Even the override cannot block everything: the whole space includes loopback.
        let opts = BlockOptions::new(&none).allow_broad();
        assert!(screen_blocks(&[cidr("0.0.0.0/0")], &opts).is_err());
        assert!(screen_blocks(&[cidr("::/0")], &opts).is_err());
    }

    #[test]
    fn broad_prefixes_need_the_override() {
        let none = CidrSet::new();
        let opts = BlockOptions::new(&none);
        for broad in ["8.0.0.0/6", "12.0.0.0/7", "2000::/3", "2001::/15"] {
            match screen_blocks(&[cidr(broad)], &opts) {
                Err(FirewallError::Refused(r)) => assert_eq!(r.too_broad, vec![cidr(broad)]),
                other => panic!("{broad}: {other:?}"),
            }
        }
        for fine in ["10.0.0.0/8", "11.0.0.0/8", "2001::/16", "1.2.3.4"] {
            assert!(screen_blocks(&[cidr(fine)], &opts).is_ok(), "{fine}");
        }
        let opts = BlockOptions::new(&none).allow_broad();
        assert!(screen_blocks(&[cidr("8.0.0.0/6")], &opts).is_ok());
        // ...but a short prefix that swallows loopback, link-local or multicast is still refused.
        assert!(screen_blocks(&[cidr("128.0.0.0/1")], &opts).is_err());
    }

    #[test]
    fn confirmation_must_be_typed() {
        assert!(Confirmation::from_phrase("i UNDERSTAND this  may lock me out of rdp ").is_ok());
        assert_eq!(
            Confirmation::from_phrase("yes").unwrap_err(),
            FirewallError::BadConfirmation
        );
        assert!(Confirmation::from_phrase("").is_err());
    }

    fn rdp_rule(name: &str, group: &str) -> Rule {
        let mut r = Rule::new(name, Direction::Inbound, Action::Allow);
        r.grouping = group.into();
        r.protocol = Protocol::Tcp;
        r.local_ports = "3389".into();
        r
    }

    #[test]
    fn builtin_rdp_rules_are_recognised_resolved_or_as_resource_strings() {
        assert!(is_builtin_rdp_rule(&rdp_rule(
            "Remote Desktop - User Mode (TCP-In)",
            "Remote Desktop"
        )));
        assert!(is_builtin_rdp_rule(&rdp_rule(
            "@FirewallAPI.dll,-28775",
            "@FirewallAPI.dll,-28752"
        )));
        // What Windows Server 2025 reports (names resolved, groups as resource strings).
        assert!(is_builtin_rdp_rule(&rdp_rule(
            "Remote Desktop - (TCP-WSS-In)",
            "@FirewallAPI.dll,-28782"
        )));
        assert!(is_builtin_rdp_rule(&rdp_rule(
            "Ein lokalisierter Name",
            "@FirewallAPI.dll,-28752"
        )));
        assert!(!is_builtin_rdp_rule(&rdp_rule(
            "Remote Desktop - Shadow (TCP-In)",
            "Remote Desktop"
        )));
        assert!(!is_builtin_rdp_rule(&rdp_rule(
            "Web",
            "World Wide Web Services"
        )));
        let mut out = rdp_rule("Remote Desktop - User Mode (TCP-In)", "Remote Desktop");
        out.direction = Direction::Outbound;
        assert!(!is_builtin_rdp_rule(&out));
    }

    #[test]
    fn rdp_port_allow_and_block_classification() {
        let mut allow = rdp_rule("my rdp", "");
        assert_eq!(
            lockout_class(&allow, 3389),
            Some(LockoutReason::RdpPortAllow { port: 3389 })
        );
        assert_eq!(lockout_class(&allow, 3390), None);
        allow.enabled = false;
        assert_eq!(lockout_class(&allow, 3389), None);

        let mut block = Rule::new("b", Direction::Inbound, Action::Block);
        block.protocol = Protocol::Tcp;
        block.local_ports = "3389".into();
        assert!(blocks_rdp_for_everyone(&block, 3389));
        block.remote_addresses = "203.0.113.0/24".into();
        assert!(!blocks_rdp_for_everyone(&block, 3389));
        block.remote_addresses = "*".into();
        block.local_ports = "445".into();
        assert!(!blocks_rdp_for_everyone(&block, 3389));
    }

    #[test]
    fn block_rules_through_the_generic_api_are_screened() {
        let protected = set(&["203.0.113.1"]);
        let mut r = Rule::new("b", Direction::Inbound, Action::Block);
        r.remote_addresses = "198.51.100.0/24".into();
        assert_eq!(check_block_rule(&r, &protected, false, 3389).unwrap(), None);
        r.remote_addresses = "198.51.100.0/24,203.0.113.0/24".into();
        assert!(matches!(
            check_block_rule(&r, &protected, false, 3389),
            Err(FirewallError::Refused(_))
        ));
        r.remote_addresses = "203.0.113.0-203.0.113.5".into();
        assert!(check_block_rule(&r, &protected, false, 3389).is_err());
        r.remote_addresses = "DefaultGateway".into();
        assert!(matches!(
            check_block_rule(&r, &protected, false, 3389),
            Err(FirewallError::InvalidRule(_))
        ));
        r.remote_addresses = "*".into();
        assert_eq!(
            check_block_rule(&r, &protected, false, 3389).unwrap(),
            Some(LockoutReason::BlocksRdp { port: 3389 })
        );
    }

    #[test]
    fn material_changes_ignore_descriptions_and_address_spelling() {
        let mut a = rdp_rule("x", "g");
        a.remote_addresses = "1.2.3.4".into();
        let mut b = a.clone();
        b.description = "other".into();
        b.remote_addresses = "1.2.3.4/255.255.255.255".into();
        assert!(!materially_changes(&a, &b));
        b.enabled = false;
        assert!(materially_changes(&a, &b));
    }
}

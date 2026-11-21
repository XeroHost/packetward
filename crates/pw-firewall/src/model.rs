// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Firewall rule model and listing filters.

use std::net::IpAddr;

use pw_core::Cidr;
use serde::{Deserialize, Serialize};

use crate::addr::{self, AddrToken};
use crate::names::{GROUP, MARKER};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmpv4,
    Icmpv6,
    /// Any other IANA protocol number.
    Other(u8),
}

impl Protocol {
    /// The `NET_FW_IP_PROTOCOL` value (256 is "any").
    pub fn number(self) -> i32 {
        match self {
            Protocol::Any => 256,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmpv4 => 1,
            Protocol::Icmpv6 => 58,
            Protocol::Other(n) => i32::from(n),
        }
    }

    pub fn from_number(n: i32) -> Self {
        match n {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmpv4,
            58 => Protocol::Icmpv6,
            0..=255 => Protocol::Other(n as u8),
            _ => Protocol::Any,
        }
    }

    pub fn has_ports(self) -> bool {
        matches!(self, Protocol::Tcp | Protocol::Udp)
    }
}

/// All three profiles (domain, private, public).
pub const PROFILES_ALL: u32 = 0x7FFF_FFFF;

/// Windows may report "all profiles" as 7 (the three profile bits) or as 0x7FFFFFFF.
pub fn normalize_profiles(profiles: u32) -> u32 {
    if profiles & 0x7 == 0x7 {
        PROFILES_ALL
    } else {
        profiles
    }
}

/// One Windows Firewall rule as far as PacketWard models it. Properties that are not modelled
/// (interfaces, ICMP types, edge traversal) are left untouched when an existing rule is updated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub description: String,
    /// Rule group; `PacketWard` for everything this crate creates.
    pub grouping: String,
    pub direction: Direction,
    pub action: Action,
    pub enabled: bool,
    pub protocol: Protocol,
    /// `*` or a list like `80,443,1000-2000`.
    pub local_ports: String,
    pub remote_ports: String,
    pub local_addresses: String,
    /// Comma separated, as Windows stores it. `*` (or empty) means any address.
    pub remote_addresses: String,
    pub application: Option<String>,
    pub service: Option<String>,
    pub profiles: u32,
}

impl Rule {
    /// A new inbound/outbound rule open on everything; the caller narrows it down.
    pub fn new(name: &str, direction: Direction, action: Action) -> Self {
        Self {
            name: name.to_owned(),
            description: String::new(),
            grouping: String::new(),
            direction,
            action,
            enabled: true,
            protocol: Protocol::Any,
            local_ports: "*".into(),
            remote_ports: "*".into(),
            local_addresses: "*".into(),
            remote_addresses: "*".into(),
            application: None,
            service: None,
            profiles: PROFILES_ALL,
        }
    }

    /// Created by PacketWard (member of the `PacketWard` group).
    pub fn is_managed(&self) -> bool {
        self.grouping == GROUP
    }

    pub fn has_marker(&self) -> bool {
        self.description.contains(MARKER)
    }

    pub fn remote_tokens(&self) -> Vec<AddrToken> {
        addr::parse_list(&self.remote_addresses)
    }

    /// The exact blocks in `remote_addresses` and how many entries were something else.
    pub fn remote_cidrs(&self) -> (Vec<Cidr>, usize) {
        addr::parse_cidrs(&self.remote_addresses)
    }

    pub fn remote_is_any(&self) -> bool {
        self.remote_tokens()
            .iter()
            .any(|t| matches!(t, AddrToken::Any))
    }

    /// Does the rule's remote address list include `ip`?
    pub fn remote_includes(&self, ip: IpAddr) -> bool {
        self.remote_tokens().iter().any(|t| match t {
            AddrToken::Any => true,
            AddrToken::Span(span) => span.contains_addr(ip),
            _ => false,
        })
    }
}

/// Filters for `Firewall::list_rules`; `None` fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleFilter {
    pub group: Option<String>,
    pub direction: Option<Direction>,
    pub action: Option<Action>,
    pub enabled: Option<bool>,
    /// Case-insensitive substring of name or description.
    pub text: Option<String>,
    /// Rules that apply to this local or remote port.
    pub port: Option<u16>,
    /// Rules whose remote address list includes this address.
    pub address: Option<IpAddr>,
}

impl RuleFilter {
    pub fn group(group: &str) -> Self {
        Self {
            group: Some(group.to_owned()),
            ..Self::default()
        }
    }

    pub fn matches(&self, rule: &Rule) -> bool {
        if let Some(group) = &self.group {
            if !rule.grouping.eq_ignore_ascii_case(group) {
                return false;
            }
        }
        if self.direction.is_some_and(|d| d != rule.direction)
            || self.action.is_some_and(|a| a != rule.action)
            || self.enabled.is_some_and(|e| e != rule.enabled)
        {
            return false;
        }
        if let Some(text) = &self.text {
            let needle = text.to_lowercase();
            if !rule.name.to_lowercase().contains(&needle)
                && !rule.description.to_lowercase().contains(&needle)
            {
                return false;
            }
        }
        if let Some(port) = self.port {
            // A rule on "any protocol" has no ports at all. Local "*" means every local port; a
            // remote port only counts when it is listed explicitly.
            let hit = rule.protocol.has_ports()
                && (addr::ports_include(&rule.local_ports, port)
                    || (!addr::ports_any(&rule.remote_ports)
                        && addr::ports_include(&rule.remote_ports, port)));
            if !hit {
                return false;
            }
        }
        if let Some(ip) = self.address {
            if !rule.remote_includes(ip) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str) -> Rule {
        let mut r = Rule::new(name, Direction::Inbound, Action::Allow);
        r.protocol = Protocol::Tcp;
        r.local_ports = "3389".into();
        r.remote_addresses = "10.0.0.0/255.0.0.0,2001:db8::/32".into();
        r.grouping = "Remote Desktop".into();
        r.description = "Lets people in".into();
        r
    }

    #[test]
    fn filters_combine_with_and() {
        let r = rule("RDP in");
        assert!(RuleFilter::default().matches(&r));
        assert!(RuleFilter::group("remote desktop").matches(&r));
        assert!(!RuleFilter::group("PacketWard").matches(&r));
        let f = RuleFilter {
            text: Some("PEOPLE".into()),
            port: Some(3389),
            address: Some("10.1.2.3".parse().unwrap()),
            enabled: Some(true),
            direction: Some(Direction::Inbound),
            action: Some(Action::Allow),
            ..RuleFilter::default()
        };
        assert!(f.matches(&r));
        assert!(!RuleFilter {
            port: Some(80),
            ..f.clone()
        }
        .matches(&r));
        assert!(!RuleFilter {
            address: Some("11.0.0.1".parse().unwrap()),
            ..f.clone()
        }
        .matches(&r));
        assert!(!RuleFilter {
            enabled: Some(false),
            ..f.clone()
        }
        .matches(&r));
        assert!(!RuleFilter {
            direction: Some(Direction::Outbound),
            ..f
        }
        .matches(&r));
    }

    #[test]
    fn protocol_numbers_round_trip() {
        for p in [
            Protocol::Any,
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Icmpv4,
            Protocol::Icmpv6,
            Protocol::Other(47),
        ] {
            assert_eq!(Protocol::from_number(p.number()), p);
        }
    }

    #[test]
    fn rules_serialize() {
        let r = rule("x");
        let back: Rule = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }
}

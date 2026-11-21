// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Parsing and arithmetic for the address and port strings Windows Firewall uses.
//!
//! Windows reads IPv4 addresses back as `a.b.c.d/255.255.255.255` (mask form) even when they were
//! written as `a.b.c.d`, so every comparison in this crate goes through these helpers and works on
//! parsed values, never on strings.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pw_core::Cidr;

/// An inclusive address interval inside one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub v6: bool,
    pub lo: u128,
    pub hi: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrToken {
    /// `*`, or an empty list (Windows treats both as "any").
    Any,
    /// `LocalSubnet`, `DefaultGateway`, `DNS`, ...
    Keyword(String),
    Span(Span),
    Invalid(String),
}

const KEYWORDS: [&str; 9] = [
    "LocalSubnet",
    "DNS",
    "DHCP",
    "WINS",
    "DefaultGateway",
    "Internet",
    "Intranet",
    "IntranetRemoteAccess",
    "PlayToDevice",
];

fn bits(addr: IpAddr) -> (bool, u128) {
    match addr.to_canonical() {
        IpAddr::V4(v4) => (false, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (true, u128::from(v6)),
    }
}

/// The interval a block covers.
pub fn cidr_span(block: &Cidr) -> Span {
    let (v6, lo) = bits(block.network());
    let width: u32 = if v6 { 128 } else { 32 };
    let host = width - u32::from(block.prefix());
    let host_mask = if host >= 128 {
        u128::MAX
    } else {
        (1u128 << host) - 1
    };
    Span {
        v6,
        lo,
        hi: lo | host_mask,
    }
}

impl Span {
    pub fn overlaps(&self, other: &Span) -> bool {
        self.v6 == other.v6 && self.lo <= other.hi && other.lo <= self.hi
    }

    pub fn contains_addr(&self, addr: IpAddr) -> bool {
        let (v6, value) = bits(addr);
        self.v6 == v6 && self.lo <= value && value <= self.hi
    }

    /// The block this interval is exactly, when it is aligned like one.
    pub fn to_cidr(&self) -> Option<Cidr> {
        let size = self.hi.checked_sub(self.lo)?.checked_add(1).or(Some(0));
        let host_bits = match size {
            Some(0) => 128, // the full 128-bit space
            Some(n) if n.is_power_of_two() => n.trailing_zeros(),
            _ => return None,
        };
        let width: u32 = if self.v6 { 128 } else { 32 };
        if host_bits > width || (host_bits < 128 && self.lo & ((1u128 << host_bits) - 1) != 0) {
            return None;
        }
        let addr = if self.v6 {
            IpAddr::V6(Ipv6Addr::from(self.lo))
        } else {
            IpAddr::V4(Ipv4Addr::from(u32::try_from(self.lo).ok()?))
        };
        Cidr::new(addr, u8::try_from(width - host_bits).ok()?).ok()
    }
}

/// Do two blocks share at least one address? (`CidrSet::contains` only answers for one address, which
/// is not enough: a /24 that merely *contains* a protected /32 must be refused too.)
pub fn cidrs_overlap(a: &Cidr, b: &Cidr) -> bool {
    cidr_span(a).overlaps(&cidr_span(b))
}

/// Total order used for deterministic output (IPv4 before IPv6, then address, then prefix).
pub fn cidr_key(block: &Cidr) -> (bool, u128, u8) {
    let (v6, value) = bits(block.network());
    (v6, value, block.prefix())
}

fn mask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let m = u32::from(mask);
    let ones = m.leading_ones();
    // A contiguous mask is ones followed by zeros.
    let rebuilt = if ones == 0 {
        0
    } else {
        u32::MAX << (32 - ones)
    };
    (rebuilt == m).then_some(ones as u8)
}

pub fn parse_token(token: &str) -> AddrToken {
    let token = token.trim();
    let invalid = || AddrToken::Invalid(token.chars().take(64).collect());
    if token.is_empty() || token == "*" {
        return AddrToken::Any;
    }
    if let Some((addr, tail)) = token.split_once('/') {
        let Ok(addr) = addr.trim().parse::<IpAddr>() else {
            return invalid();
        };
        let tail = tail.trim();
        let prefix = if tail.contains('.') {
            match tail.parse::<Ipv4Addr>().ok().and_then(mask_to_prefix) {
                Some(p) if addr.is_ipv4() => p,
                _ => return invalid(),
            }
        } else {
            match tail.parse::<u8>() {
                Ok(p) => p,
                Err(_) => return invalid(),
            }
        };
        return match Cidr::new(addr, prefix) {
            Ok(c) => AddrToken::Span(cidr_span(&c)),
            Err(_) => invalid(),
        };
    }
    if let Ok(addr) = token.parse::<IpAddr>() {
        let (v6, value) = bits(addr);
        return AddrToken::Span(Span {
            v6,
            lo: value,
            hi: value,
        });
    }
    if let Some((lo, hi)) = token.split_once('-') {
        if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<IpAddr>(), hi.trim().parse::<IpAddr>()) {
            let (v6a, lo) = bits(lo);
            let (v6b, hi) = bits(hi);
            return if v6a == v6b && lo <= hi {
                AddrToken::Span(Span { v6: v6a, lo, hi })
            } else {
                invalid()
            };
        }
    }
    match KEYWORDS.iter().find(|k| k.eq_ignore_ascii_case(token)) {
        Some(k) => AddrToken::Keyword((*k).to_owned()),
        None => invalid(),
    }
}

pub fn parse_list(text: &str) -> Vec<AddrToken> {
    if text.trim().is_empty() {
        return vec![AddrToken::Any];
    }
    text.split(',').map(parse_token).collect()
}

/// The exact blocks in `text` plus how many tokens were something else (keywords, ranges that are not
/// a block, `*`, garbage). Used to read back PacketWard's own batch rules.
pub fn parse_cidrs(text: &str) -> (Vec<Cidr>, usize) {
    let mut out = Vec::new();
    let mut other = 0;
    for token in parse_list(text) {
        match token {
            AddrToken::Span(span) => match span.to_cidr() {
                Some(c) => out.push(c),
                None => other += 1,
            },
            _ => other += 1,
        }
    }
    (out, other)
}

/// `a.b.c.d/p` / `addr/p`: the form this crate writes.
pub fn format_cidr(block: &Cidr) -> String {
    block.to_string()
}

pub fn format_cidrs(blocks: &[Cidr]) -> String {
    blocks.iter().map(format_cidr).collect::<Vec<_>>().join(",")
}

/// The way Windows reports an address list after storing it (IPv4 as `addr/mask`, IPv6 as
/// `addr/prefix`). The fake backend applies this so tests exercise the same read-back as production.
pub fn windows_readback(text: &str) -> String {
    text.split(',')
        .map(|token| match parse_token(token) {
            AddrToken::Span(span) => match span.to_cidr() {
                Some(c) if c.network().is_ipv4() => {
                    let host = 32 - u32::from(c.prefix());
                    let mask = if host >= 32 { 0 } else { u32::MAX << host };
                    format!("{}/{}", c.network(), Ipv4Addr::from(mask))
                }
                Some(c) => c.to_string(),
                None => token.trim().to_owned(),
            },
            _ => token.trim().to_owned(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Does a firewall port list (`*`, `80`, `80,443`, `1000-2000`) include `port`?
pub fn ports_include(text: &str, port: u16) -> bool {
    let text = text.trim();
    if text.is_empty() || text == "*" {
        return true;
    }
    text.split(',').any(|token| {
        let token = token.trim();
        match token.split_once('-') {
            Some((a, b)) => matches!(
                (a.trim().parse::<u16>(), b.trim().parse::<u16>()),
                (Ok(a), Ok(b)) if a <= port && port <= b
            ),
            None => token.parse::<u16>() == Ok(port),
        }
    })
}

/// Strict check used for rules the user creates: `*`, or numbers and number ranges.
pub fn ports_valid(text: &str) -> bool {
    let text = text.trim();
    if text == "*" {
        return true;
    }
    if text.is_empty() || text.len() > 1024 {
        return false;
    }
    text.split(',').all(|token| {
        let token = token.trim();
        let ok = |s: &str| s.trim().parse::<u16>().is_ok_and(|p| p != 0);
        match token.split_once('-') {
            Some((a, b)) => ok(a) && ok(b),
            None => ok(token),
        }
    })
}

/// Whether `text` is a port list that is just "any".
pub fn ports_any(text: &str) -> bool {
    let text = text.trim();
    text.is_empty() || text == "*"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    #[test]
    fn mask_form_and_cidr_form_are_the_same_block() {
        let a = parse_cidrs("1.2.3.4/255.255.255.255,10.0.0.0/255.0.0.0,2001:db8::/32");
        assert_eq!(a.1, 0);
        assert_eq!(
            a.0,
            vec![cidr("1.2.3.4"), cidr("10.0.0.0/8"), cidr("2001:db8::/32")]
        );
        // Non-contiguous masks are not a block.
        assert_eq!(parse_cidrs("10.0.0.0/255.0.255.0").1, 1);
    }

    #[test]
    fn readback_matches_what_windows_reports() {
        assert_eq!(
            windows_readback("1.2.3.4,10.0.0.0/8,2001:db8::1"),
            "1.2.3.4/255.255.255.255,10.0.0.0/255.0.0.0,2001:db8::1/128"
        );
        // Idempotent.
        let once = windows_readback("1.2.3.4,10.0.0.0/8");
        assert_eq!(windows_readback(&once), once);
        assert_eq!(windows_readback("*"), "*");
        assert_eq!(windows_readback("LocalSubnet"), "LocalSubnet");
    }

    #[test]
    fn overlap_is_not_containment() {
        assert!(cidrs_overlap(&cidr("203.0.113.0/24"), &cidr("203.0.113.7")));
        assert!(cidrs_overlap(&cidr("203.0.113.7"), &cidr("203.0.113.0/24")));
        assert!(cidrs_overlap(&cidr("0.0.0.0/0"), &cidr("8.8.8.8")));
        assert!(!cidrs_overlap(
            &cidr("203.0.113.0/24"),
            &cidr("203.0.114.0/24")
        ));
        assert!(!cidrs_overlap(&cidr("::/0"), &cidr("8.8.8.8")));
        assert!(cidrs_overlap(&cidr("::/0"), &cidr("2001:db8::1")));
    }

    #[test]
    fn spans_round_trip_to_blocks() {
        for text in [
            "0.0.0.0/0",
            "10.0.0.0/8",
            "1.2.3.4",
            "::/0",
            "2001:db8::/32",
            "::1",
        ] {
            let c = cidr(text);
            assert_eq!(cidr_span(&c).to_cidr(), Some(c), "{text}");
        }
        // 10.0.0.1-10.0.0.2 is not a block.
        assert_eq!(parse_cidrs("10.0.0.1-10.0.0.2"), (vec![], 1));
        assert_eq!(
            parse_cidrs("10.0.0.0-10.0.0.255").0,
            vec![cidr("10.0.0.0/24")]
        );
    }

    #[test]
    fn tokens() {
        assert_eq!(parse_token("*"), AddrToken::Any);
        assert_eq!(parse_token(""), AddrToken::Any);
        assert_eq!(
            parse_token("defaultgateway"),
            AddrToken::Keyword("DefaultGateway".into())
        );
        assert!(matches!(parse_token("1.2.3.4/33"), AddrToken::Invalid(_)));
        assert!(matches!(parse_token("evil;rm"), AddrToken::Invalid(_)));
        assert!(matches!(
            parse_token("1.2.3.9-1.2.3.1"),
            AddrToken::Invalid(_)
        ));
        assert_eq!(parse_list(""), vec![AddrToken::Any]);
    }

    #[test]
    fn ports() {
        assert!(ports_include("*", 3389));
        assert!(ports_include("3389", 3389));
        assert!(ports_include("80, 3389", 3389));
        assert!(ports_include("3000-4000", 3389));
        assert!(!ports_include("3390", 3389));
        assert!(!ports_include("RPC", 3389));
        assert!(ports_valid("*") && ports_valid("80,443") && ports_valid("1-65535"));
        assert!(
            !ports_valid("0") && !ports_valid("70000") && !ports_valid("80;") && !ports_valid("")
        );
        assert!(!ports_valid("RPC"));
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! IP helpers: CIDR matching, client-IP resolution behind a reverse proxy, limiter keys, log anonymization.

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use axum::http::{HeaderMap, HeaderName};

/// A CIDR block (`10.0.0.0/8`, `::1/128`, or a bare address meaning a single host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

/// CIDR parse errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CidrError {
    /// Not an IP address.
    #[error("invalid address {0:?}")]
    Address(String),
    /// Missing, malformed or out-of-range prefix length.
    #[error("invalid prefix length {0:?}")]
    Prefix(String),
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_s, prefix_s) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_s
            .trim()
            .parse()
            .map_err(|_| CidrError::Address(s.to_string()))?;
        let addr = normalize(addr);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_s {
            None => max,
            Some(p) => {
                let mut n: u8 = p
                    .trim()
                    .parse()
                    .map_err(|_| CidrError::Prefix(p.to_string()))?;
                // A prefix written against an IPv4-mapped IPv6 address is relative to 128 bits.
                if addr.is_ipv4() && matches!(addr_s.trim().parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
                    n = n
                        .checked_sub(96)
                        .ok_or_else(|| CidrError::Prefix(p.to_string()))?;
                }
                n
            }
        };
        if prefix > max {
            return Err(CidrError::Prefix(prefix_s.unwrap_or_default().to_string()));
        }
        Ok(Self { addr, prefix })
    }
}

impl Cidr {
    /// Does this block contain `ip` (IPv4-mapped IPv6 addresses are treated as IPv4)?
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalize(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                mask_v4(u32::from(net), self.prefix) == mask_v4(u32::from(ip), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                mask_v6(u128::from(net), self.prefix) == mask_v6(u128::from(ip), self.prefix)
            }
            _ => false,
        }
    }
}

fn mask_v4(v: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        v & (u32::MAX << (32 - u32::from(prefix)))
    }
}

fn mask_v6(v: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        v & (u128::MAX << (128 - u32::from(prefix)))
    }
}

/// Map IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to plain IPv4.
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// The key used for per-client limits: IPv4 as is, IPv6 collapsed to its /64 so that one host with a
/// whole /64 cannot trivially multiply its quotas.
pub fn limiter_key(ip: IpAddr) -> IpAddr {
    match normalize(ip) {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(mask_v6(u128::from(v6), 64))),
        v4 => v4,
    }
}

/// Truncated form for logs: IPv4 `a.b.c.0/24`, IPv6 `/48`. Enough to spot abuse by network, not to
/// identify a subscriber.
pub fn anonymize(ip: IpAddr) -> String {
    match normalize(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => format!("{}/48", Ipv6Addr::from(mask_v6(u128::from(v6), 48))),
    }
}

/// How the client IP is derived when a reverse proxy sits in front.
#[derive(Debug, Clone)]
pub struct ProxyPolicy {
    /// Honor `header` at all.
    pub enabled: bool,
    /// Header carrying the client address.
    pub header: HeaderName,
    /// Proxies allowed to set it.
    pub trusted: Vec<Cidr>,
}

impl ProxyPolicy {
    /// A policy that never trusts any header.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            header: HeaderName::from_static("x-forwarded-for"),
            trusted: Vec::new(),
        }
    }

    /// Is `peer` one of the configured reverse proxies (and is the feature on)?
    pub fn is_trusted_proxy(&self, peer: IpAddr) -> bool {
        self.enabled && self.trusted.iter().any(|c| c.contains(peer))
    }

    /// Resolve the client IP: the TCP peer, unless the header is enabled **and** the peer is a trusted
    /// proxy, in which case the right-most header entry that is not itself a trusted proxy wins. A missing
    /// or malformed header falls back to the peer address.
    pub fn resolve(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = normalize(peer);
        if !self.is_trusted_proxy(peer) {
            return peer;
        }
        for value in headers.get_all(&self.header).iter().rev() {
            let Ok(text) = value.to_str() else {
                return peer;
            };
            for entry in text.rsplit(',') {
                match parse_header_ip(entry) {
                    Some(ip) if self.trusted.iter().any(|c| c.contains(ip)) => continue,
                    Some(ip) => return ip,
                    None => return peer,
                }
            }
        }
        peer
    }
}

fn parse_header_ip(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(normalize(ip));
    }
    // `1.2.3.4:5678` and `[::1]:5678` forms.
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Some(normalize(sa.ip()));
    }
    // Bracketed IPv6 without a port.
    let inner = s.strip_prefix('[')?.strip_suffix(']')?;
    inner
        .parse::<Ipv6Addr>()
        .ok()
        .map(|v| normalize(IpAddr::V6(v)))
}

/// Test helper.
#[cfg(test)]
pub(crate) fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn policy(enabled: bool) -> ProxyPolicy {
        ProxyPolicy {
            enabled,
            header: HeaderName::from_static("x-forwarded-for"),
            trusted: vec![
                "127.0.0.0/8".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
                "::1/128".parse().unwrap(),
            ],
        }
    }

    fn headers(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn cidr_contains() {
        let c: Cidr = "192.168.1.0/24".parse().unwrap();
        assert!(c.contains(v4(192, 168, 1, 200)));
        assert!(!c.contains(v4(192, 168, 2, 1)));
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(v4(8, 8, 8, 8)));
        let host: Cidr = "1.2.3.4".parse().unwrap();
        assert!(host.contains(v4(1, 2, 3, 4)) && !host.contains(v4(1, 2, 3, 5)));
        let v6: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert!(!v6.contains(v4(1, 2, 3, 4)));
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!("127.0.0.0/8".parse::<Cidr>().unwrap().contains(mapped));
    }

    #[test]
    fn cidr_rejects_garbage() {
        assert!("nope".parse::<Cidr>().is_err());
        assert!("1.2.3.4/33".parse::<Cidr>().is_err());
        assert!("1.2.3.4/x".parse::<Cidr>().is_err());
        assert!("::1/129".parse::<Cidr>().is_err());
    }

    #[test]
    fn keys_and_anonymization() {
        let a: IpAddr = "2001:db8:aaaa:bbbb:1:2:3:4".parse().unwrap();
        let b: IpAddr = "2001:db8:aaaa:bbbb:ffff::1".parse().unwrap();
        assert_eq!(limiter_key(a), limiter_key(b));
        assert_eq!(
            limiter_key("::ffff:1.2.3.4".parse().unwrap()),
            v4(1, 2, 3, 4)
        );
        assert_eq!(anonymize(v4(203, 0, 113, 77)), "203.0.113.0/24");
        assert_eq!(anonymize(a), "2001:db8:aaaa::/48");
    }

    #[test]
    fn header_ignored_unless_enabled() {
        let h = headers("203.0.113.9");
        assert_eq!(
            policy(false).resolve(v4(127, 0, 0, 1), &h),
            v4(127, 0, 0, 1)
        );
        assert_eq!(
            policy(true).resolve(v4(127, 0, 0, 1), &h),
            v4(203, 0, 113, 9)
        );
    }

    #[test]
    fn header_ignored_from_untrusted_peer() {
        let h = headers("203.0.113.9");
        assert_eq!(
            policy(true).resolve(v4(198, 51, 100, 1), &h),
            v4(198, 51, 100, 1)
        );
    }

    #[test]
    fn rightmost_untrusted_entry_wins_so_spoofing_does_not_help() {
        // client spoofed "6.6.6.6"; our proxy appended the real peer 203.0.113.9; an inner proxy 10.0.0.5.
        let h = headers("6.6.6.6, 203.0.113.9, 10.0.0.5");
        assert_eq!(
            policy(true).resolve(v4(127, 0, 0, 1), &h),
            v4(203, 0, 113, 9)
        );
    }

    #[test]
    fn malformed_or_missing_header_falls_back_to_peer() {
        let p = policy(true);
        assert_eq!(
            p.resolve(v4(127, 0, 0, 1), &headers("garbage")),
            v4(127, 0, 0, 1)
        );
        assert_eq!(
            p.resolve(v4(127, 0, 0, 1), &HeaderMap::new()),
            v4(127, 0, 0, 1)
        );
        assert_eq!(
            p.resolve(v4(127, 0, 0, 1), &headers("10.1.1.1")),
            v4(127, 0, 0, 1)
        );
    }

    #[test]
    fn header_with_port_and_ipv6() {
        let p = policy(true);
        assert_eq!(
            p.resolve(v4(127, 0, 0, 1), &headers("203.0.113.9:4444")),
            v4(203, 0, 113, 9)
        );
        assert_eq!(
            p.resolve(v4(127, 0, 0, 1), &headers("[2001:db8::7]")),
            "2001:db8::7".parse::<IpAddr>().unwrap()
        );
    }
}

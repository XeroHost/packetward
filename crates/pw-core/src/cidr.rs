// SPDX-License-Identifier: GPL-3.0-or-later
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CidrError {
    #[error("not an IP address or CIDR: {0:?}")]
    Invalid(String),
    #[error("prefix length {0} is too long for the address family")]
    PrefixTooLong(u8),
}

/// An address block such as `203.0.113.0/24` or `2001:db8::/32`; a bare address is a /32 or /128.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

fn bits(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

impl Cidr {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, CidrError> {
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(CidrError::PrefixTooLong(prefix));
        }
        // Normalize host bits to zero so equal blocks compare equal.
        let width = u32::from(max);
        let host = width - u32::from(prefix);
        // `host` can be the full width (a /0 block): shifting by it would overflow.
        let masked = match bits(addr).checked_shr(host) {
            Some(shifted) => shifted.checked_shl(host).unwrap_or(0),
            None => 0,
        };
        let network = match addr {
            IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::from(masked as u32)),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::from(masked)),
        };
        Ok(Self { network, prefix })
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        let addr = addr.to_canonical();
        if addr.is_ipv4() != self.network.is_ipv4() {
            return false;
        }
        let max = if addr.is_ipv4() { 32u32 } else { 128u32 };
        let host = max - u32::from(self.prefix);
        host >= 128 || (bits(addr) >> host) == (bits(self.network) >> host)
    }
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(text: &str) -> Result<Self, CidrError> {
        let invalid = || CidrError::Invalid(text.to_owned());
        match text.trim().split_once('/') {
            Some((addr, prefix)) => {
                let addr = addr.parse::<IpAddr>().map_err(|_| invalid())?;
                let prefix = prefix.parse::<u8>().map_err(|_| invalid())?;
                Self::new(addr, prefix)
            }
            None => {
                let addr = text.trim().parse::<IpAddr>().map_err(|_| invalid())?;
                Self::new(
                    addr,
                    if addr.to_canonical().is_ipv4() {
                        32
                    } else {
                        128
                    },
                )
            }
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// A set of blocks (allowlist, protected set, management ranges).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CidrSet {
    blocks: Vec<Cidr>,
}

impl CidrSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, block: Cidr) {
        if !self.blocks.contains(&block) {
            self.blocks.push(block);
        }
    }

    pub fn insert_str(&mut self, text: &str) -> Result<(), CidrError> {
        self.insert(text.parse()?);
        Ok(())
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        self.blocks.iter().any(|block| block.contains(addr))
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Cidr> {
        self.blocks.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn contains_follows_the_prefix() {
        let block: Cidr = "203.0.113.0/24".parse().unwrap();
        assert!(block.contains(ip("203.0.113.1")));
        assert!(block.contains(ip("203.0.113.255")));
        assert!(!block.contains(ip("203.0.114.1")));
        assert!(!block.contains(ip("2001:db8::1")));
    }

    #[test]
    fn a_bare_address_is_a_single_host_and_host_bits_are_normalized() {
        let host: Cidr = "198.51.100.7".parse().unwrap();
        assert_eq!(host.prefix(), 32);
        assert!(host.contains(ip("198.51.100.7")));
        assert!(!host.contains(ip("198.51.100.8")));
        let a: Cidr = "10.1.2.3/8".parse().unwrap();
        let b: Cidr = "10.0.0.0/8".parse().unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn ipv6_and_mapped_addresses() {
        let block: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(block.contains(ip("2001:db8:ffff::1")));
        assert!(!block.contains(ip("2001:db9::1")));
        let v4: Cidr = "203.0.113.0/24".parse().unwrap();
        assert!(v4.contains(ip("::ffff:203.0.113.9")));
        let everything: Cidr = "::/0".parse().unwrap();
        assert!(everything.contains(ip("2001:db8::1")));
        let all4: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all4.contains(ip("8.8.8.8")));
    }

    #[test]
    fn invalid_input_is_rejected() {
        for bad in [
            "",
            "abc",
            "1.2.3.4/33",
            "1.2.3.4/-1",
            "1.2.3/24",
            "::1/129",
            "1.2.3.4/",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_set_matches_any_member_and_ignores_duplicates() {
        let mut set = CidrSet::new();
        set.insert_str("10.0.0.0/8").unwrap();
        set.insert_str("10.0.0.0/8").unwrap();
        set.insert_str("192.0.2.1").unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(ip("10.9.9.9")));
        assert!(set.contains(ip("192.0.2.1")));
        assert!(!set.contains(ip("192.0.2.2")));
        assert!(set.insert_str("nope").is_err());
    }
}

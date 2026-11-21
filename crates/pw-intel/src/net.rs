// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The one definition of reserved address space.
//!
//! Used in three places, so they can never disagree: addresses that are never sent to an external service
//! (AbuseIPDB), never looked up in GeoIP, and ranges that are stripped out of every blocklist (a list such as
//! FireHOL level 1 legitimately contains bogons like `10.0.0.0/8`, which must never become firewall rules on a
//! server whose management network lives there).

use std::net::IpAddr;
use std::sync::OnceLock;

use pw_core::Cidr;

const RESERVED_V4: &[&str] = &[
    "0.0.0.0/8",       // "this" network
    "10.0.0.0/8",      // private
    "100.64.0.0/10",   // carrier-grade NAT
    "127.0.0.0/8",     // loopback
    "169.254.0.0/16",  // link-local
    "172.16.0.0/12",   // private
    "192.0.0.0/24",    // IETF protocol assignments
    "192.0.2.0/24",    // TEST-NET-1
    "192.88.99.0/24",  // deprecated 6to4 relay anycast
    "192.168.0.0/16",  // private
    "198.18.0.0/15",   // benchmarking
    "198.51.100.0/24", // TEST-NET-2
    "203.0.113.0/24",  // TEST-NET-3
    "224.0.0.0/4",     // multicast
    "240.0.0.0/4",     // reserved + limited broadcast
];

const RESERVED_V6: &[&str] = &[
    "::/128",        // unspecified
    "::1/128",       // loopback
    "64:ff9b::/96",  // NAT64 well-known prefix
    "100::/64",      // discard-only
    "2001:db8::/32", // documentation
    "3fff::/20",     // documentation
    "fc00::/7",      // unique local
    "fe80::/10",     // link-local
    "fec0::/10",     // deprecated site-local
    "ff00::/8",      // multicast
];

/// All reserved blocks (IPv4 and IPv6), parsed once.
pub fn reserved_blocks() -> &'static [Cidr] {
    static BLOCKS: OnceLock<Vec<Cidr>> = OnceLock::new();
    BLOCKS.get_or_init(|| {
        RESERVED_V4
            .iter()
            .chain(RESERVED_V6)
            // The tables above are constants covered by a unit test; an unparsable entry is dropped, not a panic.
            .filter_map(|text| text.parse::<Cidr>().ok())
            .collect()
    })
}

/// `true` for an address that is not in reserved space. IPv4-mapped IPv6 addresses are classified as the IPv4
/// address they wrap.
pub fn is_public_ip(addr: IpAddr) -> bool {
    let addr = addr.to_canonical();
    !reserved_blocks().iter().any(|block| block.contains(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_tables_parse_completely() {
        assert_eq!(
            reserved_blocks().len(),
            RESERVED_V4.len() + RESERVED_V6.len()
        );
    }

    #[test]
    fn reserved_addresses_are_not_public() {
        for text in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.10.10",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.5",
            "198.51.100.5",
            "203.0.113.5",
            "198.19.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public_ip(ip(text)), "{text}");
        }
    }

    #[test]
    fn global_addresses_are_public() {
        for text in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "172.15.255.255",
            "100.128.0.1",
            "198.20.0.1",
            "45.33.32.156",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public_ip(ip(text)), "{text}");
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Decoding of `WTS_CLIENT_ADDRESS`: the address an RDP **client reports for itself**.
//!
//! That is not the address the server sees. On a live session the client reported `100.102.180.59`
//! (an overlay-network address) while the TCP connections to port 3389 came from public addresses.
//! Use [`crate::aggregate::rdp_peers`] for the real source address; this one is informational.

use std::net::Ipv4Addr;

/// `AF_INET`.
pub const AF_INET: u32 = 2;

/// Decodes the address an RDP client reports for itself.
///
/// For `AF_INET` the IPv4 address sits in bytes **2..6** of the 20-byte `Address` array (bytes 0
/// and 1 are not part of it). This offset is a known trap; it was checked on a live RDP session
/// (the decoded value was the address the client itself reported, not the TCP peer).
///
/// IPv6 clients are **not** decoded: the layout of the array for `AF_INET6` has not been verified
/// against a real session, and a wrong address here would later make the Guardian protect the wrong
/// host. They are reported as `None` until verified.
pub fn client_address(family: u32, address: &[u8; 20]) -> Option<String> {
    if family != AF_INET {
        return None;
    }
    let ip = Ipv4Addr::new(address[2], address[3], address[4], address[5]);
    // A disconnected session reports no usable address (all zeros).
    (!ip.is_unspecified()).then(|| ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(bytes: &[(usize, u8)]) -> [u8; 20] {
        let mut array = [0u8; 20];
        for &(index, value) in bytes {
            array[index] = value;
        }
        array
    }

    #[test]
    fn ipv4_is_read_from_bytes_two_to_five() {
        let raw = address(&[(2, 203), (3, 0), (4, 113), (5, 9)]);
        assert_eq!(
            client_address(AF_INET, &raw).as_deref(),
            Some("203.0.113.9")
        );
    }

    #[test]
    fn bytes_zero_and_one_are_not_part_of_the_address() {
        let raw = address(&[(0, 0xFF), (1, 0xEE), (2, 10), (3, 1), (4, 2), (5, 3)]);
        assert_eq!(client_address(AF_INET, &raw).as_deref(), Some("10.1.2.3"));
    }

    #[test]
    fn an_all_zero_address_means_no_client() {
        assert_eq!(client_address(AF_INET, &[0u8; 20]), None);
    }

    #[test]
    fn other_families_are_not_decoded() {
        let raw = address(&[(2, 1), (3, 2), (4, 3), (5, 4)]);
        assert_eq!(client_address(23, &raw), None); // AF_INET6
        assert_eq!(client_address(0, &raw), None);
    }
}

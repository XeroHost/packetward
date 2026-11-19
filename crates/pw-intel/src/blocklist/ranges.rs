// SPDX-License-Identifier: GPL-3.0-or-later
//! CIDR aggregation and subtraction on inclusive `u128` address ranges.
//!
//! Each address family is handled on its own (IPv4 as `0..=u32::MAX`, IPv6 as `0..=u128::MAX`): inclusive ends avoid
//! overflow at `255.255.255.255` and `ffff:…:ffff`, and the families can never be confused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pw_core::Cidr;

/// Inclusive address range `(first, last)` in one family.
type Range = (u128, u128);

const V4_BITS: u32 = 32;
const V6_BITS: u32 = 128;

fn to_bits(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn cidr_range(block: &Cidr) -> (bool, Range) {
    let network = block.network();
    let is_v4 = network.is_ipv4();
    let width = if is_v4 { V4_BITS } else { V6_BITS };
    let host_bits = width - u32::from(block.prefix());
    let first = to_bits(network);
    let span = if host_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    (is_v4, (first, first | span))
}

/// Sort and merge overlapping or adjacent ranges.
fn merge(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_unstable();
    let mut merged: Vec<Range> = Vec::with_capacity(ranges.len());
    for (first, last) in ranges {
        match merged.last_mut() {
            // Overlapping, or directly adjacent (`last + 1 == first`, written without overflow).
            Some(prev) if first <= prev.1 || first - prev.1 == 1 => {
                if last > prev.1 {
                    prev.1 = last;
                }
            }
            _ => merged.push((first, last)),
        }
    }
    merged
}

/// `a` minus `b`; both must be sorted and merged.
fn subtract(a: &[Range], b: &[Range]) -> Vec<Range> {
    let mut out = Vec::with_capacity(a.len());
    let mut j = 0;
    for &(first, last) in a {
        let mut start = first;
        let mut exhausted = false;
        // Skip removals entirely below the current range.
        while j < b.len() && b[j].1 < start {
            j += 1;
        }
        let mut k = j;
        while k < b.len() && b[k].0 <= last {
            let (rfirst, rlast) = b[k];
            if rfirst > start {
                out.push((start, rfirst - 1));
            }
            if rlast >= last {
                exhausted = true;
                break;
            }
            start = rlast + 1; // rlast < last <= MAX, no overflow
            k += 1;
        }
        if !exhausted {
            out.push((start, last));
        }
    }
    out
}

fn make_addr(is_v4: bool, bits: u128) -> IpAddr {
    if is_v4 {
        // Callers keep IPv4 ranges inside 0..=u32::MAX, so the truncation never loses bits.
        IpAddr::V4(Ipv4Addr::from(bits as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(bits))
    }
}

/// Minimal list of CIDR blocks covering exactly `first..=last`.
fn range_to_cidrs(is_v4: bool, first: u128, last: u128, out: &mut Vec<Cidr>) {
    let width = if is_v4 { V4_BITS } else { V6_BITS };
    let mut start = first;
    loop {
        // Largest block that is aligned at `start` ...
        let align = start.trailing_zeros().min(width);
        // ... and does not run past `last`.
        let span = last - start;
        let fit = if span == u128::MAX {
            128
        } else {
            127 - (span + 1).leading_zeros()
        };
        let host_bits = align.min(fit);
        let prefix = (width - host_bits) as u8;
        if let Ok(block) = Cidr::new(make_addr(is_v4, start), prefix) {
            out.push(block);
        }
        let block_last = if host_bits >= 128 {
            u128::MAX
        } else {
            start | ((1u128 << host_bits) - 1)
        };
        if block_last >= last {
            break;
        }
        start = block_last + 1;
    }
}

fn split_families(blocks: impl IntoIterator<Item = Cidr>) -> (Vec<Range>, Vec<Range>) {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for block in blocks {
        let (is_v4, range) = cidr_range(&block);
        if is_v4 {
            v4.push(range);
        } else {
            v6.push(range);
        }
    }
    (merge(v4), merge(v6))
}

fn join_families(v4: &[Range], v6: &[Range]) -> Vec<Cidr> {
    let mut out = Vec::new();
    for &(first, last) in v4 {
        range_to_cidrs(true, first, last, &mut out);
    }
    for &(first, last) in v6 {
        range_to_cidrs(false, first, last, &mut out);
    }
    out
}

/// De-duplicate and aggregate `blocks` into the minimal set of CIDRs covering exactly the same addresses
/// (IPv4 first, each family in address order).
pub fn aggregate(blocks: impl IntoIterator<Item = Cidr>) -> Vec<Cidr> {
    let (v4, v6) = split_families(blocks);
    join_families(&v4, &v6)
}

/// Aggregate `blocks`, then remove every address covered by any of `exclusions`. The result is again minimal.
/// A block that only partially overlaps an exclusion is split, so no excluded address can remain.
pub fn aggregate_excluding(
    blocks: impl IntoIterator<Item = Cidr>,
    exclusions: impl IntoIterator<Item = Cidr>,
) -> Vec<Cidr> {
    let (a4, a6) = split_families(blocks);
    let (e4, e6) = split_families(exclusions);
    join_families(&subtract(&a4, &e4), &subtract(&a6, &e6))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn c(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    fn strings(blocks: &[Cidr]) -> Vec<String> {
        blocks.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn adjacent_blocks_merge_and_duplicates_vanish() {
        let out = aggregate([
            c("10.0.0.0/25"),
            c("10.0.0.128/25"),
            c("10.0.0.0/24"),
            c("10.0.1.0/24"),
        ]);
        assert_eq!(strings(&out), ["10.0.0.0/23"]);
    }

    #[test]
    fn an_unaligned_run_splits_into_the_minimal_blocks() {
        // 10.0.0.1 .. 10.0.0.6 is not one block.
        let out = aggregate([
            c("10.0.0.1/32"),
            c("10.0.0.2/31"),
            c("10.0.0.4/31"),
            c("10.0.0.6/32"),
        ]);
        assert_eq!(
            strings(&out),
            ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]
        );
    }

    #[test]
    fn whole_address_space_and_the_top_of_each_family() {
        assert_eq!(
            strings(&aggregate([c("0.0.0.0/1"), c("128.0.0.0/1")])),
            ["0.0.0.0/0"]
        );
        assert_eq!(strings(&aggregate([c("::/1"), c("8000::/1")])), ["::/0"]);
        assert_eq!(
            strings(&aggregate([
                c("255.255.255.255/32"),
                c("255.255.255.254/32")
            ])),
            ["255.255.255.254/31"]
        );
        assert_eq!(
            strings(&aggregate([c(
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
            )])),
            ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"]
        );
    }

    #[test]
    fn families_never_mix() {
        let out = aggregate([c("1.2.3.0/24"), c("2001:db8::/32"), c("1.2.4.0/24")]);
        assert_eq!(strings(&out), ["1.2.3.0/24", "1.2.4.0/24", "2001:db8::/32"]);
    }

    #[test]
    fn a_partially_overlapping_exclusion_splits_the_block() {
        // Excluding 10.0.0.64/26 from 10.0.0.0/24 leaves 0..63 and 128..255.
        let out = aggregate_excluding([c("10.0.0.0/24")], [c("10.0.0.64/26")]);
        assert_eq!(strings(&out), ["10.0.0.0/26", "10.0.0.128/25"]);
        // Excluding one host out of a /24.
        let out = aggregate_excluding([c("192.0.2.0/24")], [c("192.0.2.77/32")]);
        assert_eq!(out.len(), 8);
        assert!(!out
            .iter()
            .any(|b| b.contains("192.0.2.77".parse().unwrap())));
        assert!(out
            .iter()
            .any(|b| b.contains("192.0.2.76".parse().unwrap())));
        assert!(out
            .iter()
            .any(|b| b.contains("192.0.2.78".parse().unwrap())));
    }

    #[test]
    fn exclusions_that_cover_or_miss_everything() {
        assert!(aggregate_excluding([c("10.0.0.0/24")], [c("10.0.0.0/8")]).is_empty());
        assert!(aggregate_excluding([c("10.0.0.0/24")], [c("0.0.0.0/0")]).is_empty());
        assert_eq!(
            strings(&aggregate_excluding([c("10.0.0.0/24")], [c("11.0.0.0/8")])),
            ["10.0.0.0/24"]
        );
        // An IPv6 exclusion never touches IPv4 blocks and vice versa.
        assert_eq!(
            strings(&aggregate_excluding([c("10.0.0.0/24")], [c("::/0")])),
            ["10.0.0.0/24"]
        );
        assert_eq!(
            strings(&aggregate_excluding([c("2001:db8::/32")], [c("0.0.0.0/0")])),
            ["2001:db8::/32"]
        );
    }

    #[test]
    fn an_ipv6_partial_overlap_splits_too() {
        let out = aggregate_excluding([c("2001:db8::/32")], [c("2001:db8:8000::/33")]);
        assert_eq!(strings(&out), ["2001:db8::/33"]);
        let out = aggregate_excluding([c("2001:db8::/32")], [c("2001:db8::1/128")]);
        assert!(!out
            .iter()
            .any(|b| b.contains("2001:db8::1".parse().unwrap())));
        assert!(out
            .iter()
            .any(|b| b.contains("2001:db8::2".parse().unwrap())));
        assert!(out
            .iter()
            .any(|b| b.contains("2001:db8::".parse().unwrap())));
    }

    /// Tiny deterministic generator so the property tests need no extra dependency.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Random blocks inside one /22 (1024 addresses) so membership can be enumerated exhaustively.
    fn random_blocks(rng: &mut Rng, count: usize, prefix_min: u8) -> Vec<Cidr> {
        (0..count)
            .map(|_| {
                let host = rng.below(1024) as u32;
                let prefix = prefix_min + rng.below(u64::from(33 - prefix_min)) as u8;
                let addr = Ipv4Addr::from(u32::from(Ipv4Addr::new(203, 0, 112, 0)) + host);
                Cidr::new(IpAddr::V4(addr), prefix).unwrap()
            })
            .collect()
    }

    fn members(blocks: &[Cidr]) -> BTreeSet<u32> {
        (0..1024u32)
            .filter(|host| {
                let addr = Ipv4Addr::from(u32::from(Ipv4Addr::new(203, 0, 112, 0)) + host);
                blocks.iter().any(|b| b.contains(IpAddr::V4(addr)))
            })
            .collect()
    }

    #[test]
    fn property_aggregation_covers_exactly_the_same_addresses_and_is_minimal() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for round in 0..300 {
            let count = 1 + rng.below(40) as usize;
            let input = random_blocks(&mut rng, count, 22);
            let out = aggregate(input.clone());
            assert_eq!(members(&input), members(&out), "round {round}");
            // Disjoint and non-adjacent-mergeable: re-aggregating changes nothing, and no two blocks overlap.
            assert_eq!(aggregate(out.clone()), out, "round {round}");
            for (i, a) in out.iter().enumerate() {
                for b in &out[i + 1..] {
                    assert!(
                        !a.contains(b.network()) && !b.contains(a.network()),
                        "round {round}"
                    );
                }
            }
        }
    }

    #[test]
    fn property_subtraction_never_leaves_an_excluded_address_and_keeps_the_rest() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
        for round in 0..300 {
            let (n_blocks, n_exclusions) = (1 + rng.below(30) as usize, 1 + rng.below(8) as usize);
            let blocks = random_blocks(&mut rng, n_blocks, 22);
            let exclusions = random_blocks(&mut rng, n_exclusions, 24);
            let out = aggregate_excluding(blocks.clone(), exclusions.clone());
            let wanted: BTreeSet<u32> = members(&blocks)
                .difference(&members(&exclusions))
                .copied()
                .collect();
            assert_eq!(members(&out), wanted, "round {round}");
            assert_eq!(
                aggregate(out.clone()),
                out,
                "result must already be minimal (round {round})"
            );
        }
    }
}

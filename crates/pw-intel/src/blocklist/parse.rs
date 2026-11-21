// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Blocklist text parsing and the sanitising pipeline (reserved space, too-broad entries, protected set).

use pw_core::{Cidr, CidrSet};
use serde::{Deserialize, Serialize};

use super::ranges::{aggregate, aggregate_excluding};
use crate::net::reserved_blocks;

/// Hard cap on the downloaded list size.
pub const MAX_LIST_BYTES: usize = 10 * 1024 * 1024;
/// Hard cap on accepted entries (after parsing, before aggregation).
pub const MAX_LIST_ENTRIES: usize = 500_000;
/// Shortest accepted IPv4 prefix. A list asking for `0.0.0.0/0` (or anything broader than a /8) is refusing to be
/// a blocklist; such entries are dropped and counted.
pub const MIN_PREFIX_V4: u8 = 8;
/// Shortest accepted IPv6 prefix.
pub const MIN_PREFIX_V6: u8 = 16;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ParseLimits {
    pub max_bytes: usize,
    pub max_entries: usize,
    /// The list is refused when more than this fraction of its data lines is garbage (e.g. an HTML error page).
    pub max_invalid_ratio: f64,
    /// A list without any usable entry is an error unless this is set (the signed XeroHost list may be empty).
    pub allow_empty: bool,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_LIST_BYTES,
            max_entries: MAX_LIST_ENTRIES,
            max_invalid_ratio: 0.05,
            allow_empty: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("the list is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error("the list has more than {limit} entries")]
    TooManyEntries { limit: usize },
    #[error("{invalid} of {total} data lines are not an IP address or CIDR; refusing the list")]
    TooManyInvalidLines { invalid: usize, total: usize },
    #[error("the list contains no usable entries")]
    Empty,
}

/// Counters describing what happened to the lines of a list. Garbage is counted, never silently dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseReport {
    /// All lines, including blank and comment lines.
    pub lines: usize,
    /// Lines with a valid IP address or CIDR.
    pub accepted: usize,
    /// Non-blank, non-comment lines that are not an address or CIDR.
    pub invalid: usize,
    /// Valid entries broader than [`MIN_PREFIX_V4`] / [`MIN_PREFIX_V6`], dropped.
    pub too_broad: usize,
    /// Valid entries entirely inside reserved space (private, loopback, multicast, …), dropped.
    pub reserved_dropped: usize,
    /// CIDRs after de-duplication and aggregation, before subtracting the protected set.
    pub aggregated: usize,
    /// CIDRs in the final output (after subtracting the protected set).
    pub effective: usize,
    /// `true` when the protected set removed at least part of the list.
    pub protected_carved: bool,
}

/// Parse one list. Format: one IP or CIDR per line (IPv4 or IPv6); `#` and `;` start a comment (whole line or inline);
/// CRLF and a UTF-8 BOM are tolerated. Returns the valid blocks (not yet aggregated) and the counters.
pub fn parse_list(
    data: &[u8],
    limits: &ParseLimits,
) -> Result<(Vec<Cidr>, ParseReport), ParseError> {
    if data.len() > limits.max_bytes {
        return Err(ParseError::TooLarge {
            limit: limits.max_bytes,
        });
    }
    // Lossy: a stray non-UTF-8 byte in a comment must not discard a whole list; it just fails to parse as an entry.
    let text = String::from_utf8_lossy(data);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);

    let mut report = ParseReport::default();
    let mut blocks = Vec::new();
    for raw_line in text.split('\n') {
        report.lines += 1;
        let line = match raw_line.find(['#', ';']) {
            Some(at) => &raw_line[..at],
            None => raw_line,
        }
        .trim(); // also removes the `\r` of CRLF
        if line.is_empty() {
            continue;
        }
        // A data line is exactly one token; "1.2.3.4 extra words" is garbage, not an entry.
        let parsed = if line.split_whitespace().nth(1).is_some() {
            None
        } else {
            line.parse::<Cidr>().ok()
        };
        let Some(block) = parsed else {
            report.invalid += 1;
            continue;
        };
        let min_prefix = if block.network().is_ipv4() {
            MIN_PREFIX_V4
        } else {
            MIN_PREFIX_V6
        };
        if block.prefix() < min_prefix {
            report.too_broad += 1;
            continue;
        }
        report.accepted += 1;
        if report.accepted > limits.max_entries {
            return Err(ParseError::TooManyEntries {
                limit: limits.max_entries,
            });
        }
        blocks.push(block);
    }
    // The trailing split piece after a final newline is an empty line, not a real one.
    if text.ends_with('\n') {
        report.lines -= 1;
    }

    let data_lines = report.accepted + report.invalid + report.too_broad;
    #[allow(clippy::cast_precision_loss)] // counts are far below 2^52
    let ratio = report.invalid as f64 / data_lines.max(1) as f64;
    if report.invalid > 0 && ratio > limits.max_invalid_ratio {
        return Err(ParseError::TooManyInvalidLines {
            invalid: report.invalid,
            total: data_lines,
        });
    }
    if report.accepted == 0 && !limits.allow_empty {
        return Err(ParseError::Empty);
    }
    Ok((blocks, report))
}

/// The result of [`build_list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltList {
    /// Aggregated, public blocks **before** the protected set is subtracted. Kept so the protected set can be
    /// re-applied later (a new trusted RDP client appears) without downloading again.
    pub public_blocks: Vec<Cidr>,
    /// `public_blocks` minus the protected set: what may be applied to the firewall.
    pub effective_blocks: Vec<Cidr>,
    pub report: ParseReport,
}

/// Remove reserved space from `blocks` and aggregate. Entries that only partially overlap reserved space are split.
fn sanitise(blocks: Vec<Cidr>, report: &mut ParseReport) -> Vec<Cidr> {
    let reserved = reserved_blocks();
    let (inside, kept): (Vec<Cidr>, Vec<Cidr>) = blocks.into_iter().partition(|block| {
        reserved
            .iter()
            .any(|r| r.contains(block.network()) && r.prefix() <= block.prefix())
    });
    report.reserved_dropped += inside.len();
    aggregate_excluding(kept, reserved.iter().copied())
}

/// Full pipeline: parse, drop too-broad and reserved entries, de-duplicate and aggregate to minimal CIDRs, then
/// subtract `protected`. No address of `protected` can appear in `effective_blocks`.
pub fn build_list(
    data: &[u8],
    limits: &ParseLimits,
    protected: &CidrSet,
) -> Result<BuiltList, ParseError> {
    let (blocks, mut report) = parse_list(data, limits)?;
    let public_blocks = sanitise(blocks, &mut report);
    report.aggregated = public_blocks.len();
    let effective_blocks = exclude_protected(&public_blocks, protected);
    report.effective = effective_blocks.len();
    report.protected_carved = effective_blocks != public_blocks;
    Ok(BuiltList {
        public_blocks,
        effective_blocks,
        report,
    })
}

/// `blocks` minus `protected`, aggregated. Use this to re-apply an updated protected set to a stored list.
pub fn exclude_protected(blocks: &[Cidr], protected: &CidrSet) -> Vec<Cidr> {
    if protected.is_empty() {
        return aggregate(blocks.iter().copied());
    }
    aggregate_excluding(blocks.iter().copied(), protected.iter().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn limits() -> ParseLimits {
        ParseLimits::default()
    }

    fn strings(blocks: &[Cidr]) -> Vec<String> {
        blocks.iter().map(ToString::to_string).collect()
    }

    fn set(blocks: &[&str]) -> CidrSet {
        let mut set = CidrSet::new();
        for b in blocks {
            set.insert_str(b).unwrap();
        }
        set
    }

    #[test]
    fn parses_comments_inline_comments_crlf_and_both_families() {
        let text = "\u{feff}# header\r\n; spamhaus style\r\n\r\n1.2.3.0/24 ; SBL12345\r\n5.6.7.8 # a host\r\n2001:4860::/32\r\n  9.9.9.0/24  \r\n";
        let (blocks, report) = parse_list(text.as_bytes(), &limits()).unwrap();
        assert_eq!(
            strings(&blocks),
            ["1.2.3.0/24", "5.6.7.8/32", "2001:4860::/32", "9.9.9.0/24"]
        );
        assert_eq!(report.accepted, 4);
        assert_eq!(report.invalid, 0);
        assert_eq!(report.lines, 7);
    }

    #[test]
    fn garbage_lines_are_counted_not_accepted() {
        let mut text = String::new();
        for i in 0..100 {
            text.push_str(&format!("45.{i}.0.0/16\n"));
        }
        text.push_str("not-an-ip\n1.2.3.4 extra\n999.1.1.1\n1.2.3.4/33\n");
        let (blocks, report) = parse_list(text.as_bytes(), &limits()).unwrap();
        assert_eq!(blocks.len(), 100);
        assert_eq!(report.invalid, 4);
        assert_eq!(report.accepted, 100);
    }

    #[test]
    fn a_mostly_garbage_file_is_refused() {
        let html = "<html>\n<body>\n<h1>503</h1>\nservice unavailable\n</body>\n</html>\n1.2.3.4\n";
        assert!(matches!(
            parse_list(html.as_bytes(), &limits()),
            Err(ParseError::TooManyInvalidLines { .. })
        ));
        assert_eq!(parse_list(b"", &limits()).unwrap_err(), ParseError::Empty);
        assert_eq!(
            parse_list(b"# only comments\n", &limits()).unwrap_err(),
            ParseError::Empty
        );
        let allow = ParseLimits {
            allow_empty: true,
            ..limits()
        };
        assert!(parse_list(b"# only comments\n", &allow)
            .unwrap()
            .0
            .is_empty());
    }

    #[test]
    fn too_broad_entries_are_dropped_and_counted() {
        let (blocks, report) = parse_list(
            b"0.0.0.0/0\n1.0.0.0/7\n2.0.0.0/8\n::/0\n2000::/15\n2400::/16\n",
            &limits(),
        )
        .unwrap();
        assert_eq!(strings(&blocks), ["2.0.0.0/8", "2400::/16"]);
        assert_eq!(report.too_broad, 4);
    }

    #[test]
    fn the_size_cap_is_enforced() {
        let small = ParseLimits {
            max_bytes: 16,
            ..limits()
        };
        assert_eq!(
            parse_list(b"1.2.3.4\n5.6.7.8\n9.9.9.9\n", &small).unwrap_err(),
            ParseError::TooLarge { limit: 16 }
        );
        let default_over = vec![b'#'; MAX_LIST_BYTES + 1];
        assert!(matches!(
            parse_list(&default_over, &limits()),
            Err(ParseError::TooLarge { .. })
        ));
        let at_cap = vec![b'#'; MAX_LIST_BYTES];
        let allow = ParseLimits {
            allow_empty: true,
            ..limits()
        };
        assert!(parse_list(&at_cap, &allow).is_ok());
    }

    #[test]
    fn the_entry_cap_is_enforced() {
        let small = ParseLimits {
            max_entries: 3,
            ..limits()
        };
        assert!(parse_list(b"1.1.1.1\n2.2.2.2\n3.3.3.3\n", &small).is_ok());
        assert_eq!(
            parse_list(b"1.1.1.1\n2.2.2.2\n3.3.3.3\n4.4.4.4\n", &small).unwrap_err(),
            ParseError::TooManyEntries { limit: 3 }
        );
    }

    #[test]
    fn the_default_entry_cap_is_five_hundred_thousand() {
        // 500 001 distinct /32 hosts.
        let mut text = String::with_capacity(8 * 1024 * 1024);
        for n in 0..=MAX_LIST_ENTRIES as u32 {
            let a = 16 + (n >> 16);
            text.push_str(&format!("{}.{}.{}.1\n", a, (n >> 8) & 0xff, n & 0xff));
        }
        assert!(text.len() < MAX_LIST_BYTES);
        assert_eq!(
            parse_list(text.as_bytes(), &limits()).unwrap_err(),
            ParseError::TooManyEntries {
                limit: MAX_LIST_ENTRIES
            }
        );
    }

    #[test]
    fn reserved_space_never_survives() {
        // FireHOL-level-1 style bogons, plus one real range and one that straddles private space.
        let text = "0.0.0.0/8\n10.0.0.0/8\n127.0.0.0/8\n169.254.0.0/16\n172.16.0.0/12\n192.168.0.0/16\n224.0.0.0/4\n240.0.0.0/4\n\
                    198.51.100.0/24\n45.33.32.0/24\n172.0.0.0/8\nfc00::/7\nfe80::/10\n2001:db8::/32\n";
        let built = build_list(text.as_bytes(), &limits(), &CidrSet::new()).unwrap();
        for private in [
            "10.1.1.1",
            "192.168.0.1",
            "172.16.5.5",
            "172.31.9.9",
            "127.0.0.1",
            "224.1.1.1",
            "169.254.1.1",
            "fe80::1",
            "fd00::1",
        ] {
            let addr: IpAddr = private.parse().unwrap();
            assert!(
                !built.effective_blocks.iter().any(|b| b.contains(addr)),
                "{private}"
            );
        }
        // The straddling /8 keeps its public parts only.
        let kept = |text: &str| {
            let addr: IpAddr = text.parse().unwrap();
            built.effective_blocks.iter().any(|b| b.contains(addr))
        };
        assert!(kept("172.0.0.1"));
        assert!(kept("172.15.255.255"));
        assert!(!kept("172.16.0.0"));
        assert!(kept("172.32.0.0"));
        assert!(kept("45.33.32.7"));
        assert_eq!(built.report.reserved_dropped, 8);
        assert_eq!(built.report.too_broad, 4); // 224/4, 240/4, fc00::/7, fe80::/10 are broader than the minimum
    }

    #[test]
    fn protected_addresses_never_end_up_in_the_output() {
        // The protected sub-ranges only partially overlap list entries.
        let text = "203.1.0.0/16\n198.1.2.0/24\n45.0.0.0/8\n2a00::/16\n";
        let protected = set(&[
            "203.1.77.0/24", // inside a /16
            "198.1.2.9",     // one host of a /24 (an RDP client)
            "45.0.0.0/9",    // half of a /8
            "2a00:1::/32",   // inside an IPv6 /16
            "100.1.1.1",     // not in the list at all
        ]);
        let built = build_list(text.as_bytes(), &limits(), &protected).unwrap();
        for protected_addr in [
            "203.1.77.0",
            "203.1.77.255",
            "198.1.2.9",
            "45.0.0.1",
            "45.127.255.255",
            "2a00:1::5",
        ] {
            let addr: IpAddr = protected_addr.parse().unwrap();
            assert!(
                !built.effective_blocks.iter().any(|b| b.contains(addr)),
                "{protected_addr} leaked"
            );
        }
        // Everything around the carve-outs is still listed.
        for blocked in [
            "203.1.76.255",
            "203.1.78.0",
            "198.1.2.8",
            "198.1.2.10",
            "45.128.0.0",
            "2a00:2::1",
        ] {
            let addr: IpAddr = blocked.parse().unwrap();
            assert!(
                built.effective_blocks.iter().any(|b| b.contains(addr)),
                "{blocked} lost"
            );
        }
        // The pre-protection set is kept for later re-application.
        assert!(built
            .public_blocks
            .iter()
            .any(|b| b.contains("198.1.2.9".parse().unwrap())));
        assert!(built.report.protected_carved);
        assert!(built.report.effective > built.report.aggregated);
    }

    #[test]
    fn the_protected_set_can_be_reapplied_to_a_stored_list() {
        let built = build_list(b"203.1.0.0/16\n", &limits(), &CidrSet::new()).unwrap();
        assert_eq!(strings(&built.effective_blocks), ["203.1.0.0/16"]);
        let later = exclude_protected(&built.public_blocks, &set(&["203.1.5.5"]));
        assert!(!later
            .iter()
            .any(|b| b.contains("203.1.5.5".parse().unwrap())));
        assert!(later
            .iter()
            .any(|b| b.contains("203.1.5.6".parse().unwrap())));
    }

    #[test]
    fn duplicates_and_overlaps_collapse() {
        let text = "1.2.3.0/25\n1.2.3.128/25\n1.2.3.0/24\n1.2.3.4\n1.2.3.4\n";
        let built = build_list(text.as_bytes(), &limits(), &CidrSet::new()).unwrap();
        assert_eq!(strings(&built.effective_blocks), ["1.2.3.0/24"]);
        assert_eq!(built.report.accepted, 5);
        assert_eq!(built.report.aggregated, 1);
    }
}

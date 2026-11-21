// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Test-only MaxMind DB writer: builds tiny `.mmdb` fixtures programmatically, so no real database (and no
//! MaxMind or DB-IP data) is ever committed. IPv6 search tree (IPv4 lives under `::/96`), 24-bit records.

use std::net::IpAddr;

use pw_core::Cidr;

pub enum V {
    Str(String),
    U16(u16),
    U32(u32),
    U64(u64),
    Map(Vec<(&'static str, V)>),
    Arr(Vec<V>),
}

fn s(text: &str) -> V {
    V::Str(text.to_owned())
}

fn header(type_id: u8, size: usize, out: &mut Vec<u8>) {
    assert!(size < 29 + 256, "test fixture value too large");
    let (size_bits, extra) = if size < 29 {
        (size as u8, None)
    } else {
        (29u8, Some((size - 29) as u8))
    };
    if type_id <= 7 {
        out.push((type_id << 5) | size_bits);
    } else {
        out.push(size_bits);
        out.push(type_id - 7);
    }
    if let Some(extra) = extra {
        out.push(extra);
    }
}

fn uint(type_id: u8, value: u64, out: &mut Vec<u8>) {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    header(type_id, 8 - skip, out);
    out.extend_from_slice(&bytes[skip..]);
}

pub fn encode(value: &V, out: &mut Vec<u8>) {
    match value {
        V::Str(text) => {
            header(2, text.len(), out);
            out.extend_from_slice(text.as_bytes());
        }
        V::U16(n) => uint(5, u64::from(*n), out),
        V::U32(n) => uint(6, u64::from(*n), out),
        V::U64(n) => uint(9, *n, out),
        V::Map(entries) => {
            header(7, entries.len(), out);
            for (key, value) in entries {
                encode(&V::Str((*key).to_owned()), out);
                encode(value, out);
            }
        }
        V::Arr(items) => {
            header(11, items.len(), out);
            for item in items {
                encode(item, out);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Child {
    Empty,
    Node(usize),
    Data(usize),
}

fn bits_of(addr: IpAddr) -> (u128, u32) {
    match addr {
        // IPv4 sits at ::a.b.c.d inside the IPv6 tree.
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 96),
        IpAddr::V6(v6) => (u128::from(v6), 0),
    }
}

/// Build a database from `(cidr, record)` pairs. `build_epoch` goes into the metadata.
pub fn build_mmdb(entries: &[(&str, V)], build_epoch: u64, database_type: &str) -> Vec<u8> {
    let mut data = Vec::new();
    let mut nodes: Vec<[Child; 2]> = vec![[Child::Empty; 2]];
    for (cidr, record) in entries {
        let cidr: Cidr = cidr.parse().expect("fixture CIDR");
        let (addr_bits, offset) = bits_of(cidr.network());
        let depth = offset + u32::from(cidr.prefix());
        let data_offset = data.len();
        encode(record, &mut data);
        let mut node = 0usize;
        for level in 0..depth {
            let bit = ((addr_bits >> (127 - level)) & 1) as usize;
            let last = level + 1 == depth;
            if last {
                nodes[node][bit] = Child::Data(data_offset);
            } else {
                node = match nodes[node][bit] {
                    Child::Node(next) => next,
                    _ => {
                        nodes.push([Child::Empty; 2]);
                        let next = nodes.len() - 1;
                        nodes[node][bit] = Child::Node(next);
                        next
                    }
                };
            }
        }
    }

    let node_count = nodes.len();
    let record = |child: Child| -> u32 {
        match child {
            Child::Empty => node_count as u32,
            Child::Node(n) => n as u32,
            Child::Data(offset) => (node_count + 16 + offset) as u32,
        }
    };
    let mut out = Vec::new();
    for [left, right] in &nodes {
        for value in [record(*left), record(*right)] {
            out.extend_from_slice(&value.to_be_bytes()[1..]);
        }
    }
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&data);
    out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
    let metadata = V::Map(vec![
        ("binary_format_major_version", V::U16(2)),
        ("binary_format_minor_version", V::U16(0)),
        ("build_epoch", V::U64(build_epoch)),
        ("database_type", s(database_type)),
        ("description", V::Map(vec![("en", s("test fixture"))])),
        ("ip_version", V::U16(6)),
        ("languages", V::Arr(vec![s("en")])),
        ("node_count", V::U32(node_count as u32)),
        ("record_size", V::U16(24)),
    ]);
    encode(&metadata, &mut out);
    out
}

/// A DB-IP Lite style country record.
pub fn country_record(iso: &str, name: &str, continent: &str) -> V {
    V::Map(vec![
        (
            "continent",
            V::Map(vec![
                ("code", s(continent)),
                ("names", V::Map(vec![("en", s(continent))])),
            ]),
        ),
        (
            "country",
            V::Map(vec![
                ("iso_code", s(iso)),
                ("names", V::Map(vec![("en", s(name))])),
            ]),
        ),
    ])
}

/// A DB-IP Lite style ASN record.
pub fn asn_record(number: u32, organization: &str) -> V {
    V::Map(vec![
        ("autonomous_system_number", V::U32(number)),
        ("autonomous_system_organization", s(organization)),
    ])
}

/// Country fixture: 8.8.8.0/24 and 2001:4860::/32 → US, 203.1.0.0/16 → BR (not reserved space).
pub fn country_fixture(build_epoch: u64) -> Vec<u8> {
    build_mmdb(
        &[
            ("8.8.8.0/24", country_record("US", "United States", "NA")),
            (
                "2001:4860::/32",
                country_record("US", "United States", "NA"),
            ),
            ("203.1.0.0/16", country_record("BR", "Brazil", "SA")),
        ],
        build_epoch,
        "DBIP-Country-Lite",
    )
}

/// ASN fixture: 8.8.8.0/24 → AS15169, 2001:4860::/32 → AS15169, 203.1.0.0/16 → AS64500.
pub fn asn_fixture(build_epoch: u64) -> Vec<u8> {
    build_mmdb(
        &[
            ("8.8.8.0/24", asn_record(15169, "Google LLC")),
            ("2001:4860::/32", asn_record(15169, "Google LLC")),
            ("203.1.0.0/16", asn_record(64500, "Example Transit")),
        ],
        build_epoch,
        "DBIP-ASN-Lite (compat=GeoLite2-ASN)",
    )
}

/// Minimal self-cleaning temp directory (no extra dependency).
pub struct TempDir(std::path::PathBuf);

impl TempDir {
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "pw-intel-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

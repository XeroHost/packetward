// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! ASN + country per hop. The data comes from a *local* database behind [`HopEnricher`] (the
//! engine adapts `pw-intel`'s GeoIP reader); nothing is ever sent over the network for a hop, and
//! private / reserved addresses are not even handed to the enricher.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Most addresses remembered by an [`EnrichCache`]; the oldest is evicted first.
pub const ENRICH_CACHE_CAPACITY: usize = 1024;

/// What is known about the network an address belongs to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HopInfo {
    /// Autonomous system number (`13335`), when known.
    pub asn: Option<u32>,
    /// Name of the autonomous system's organisation.
    pub as_org: Option<String>,
    /// ISO 3166-1 alpha-2 country code (`US`).
    pub country_code: Option<String>,
}

impl HopInfo {
    /// `true` when nothing is known.
    pub fn is_empty(&self) -> bool {
        *self == HopInfo::default()
    }
}

/// A local ASN / country lookup. Implementations must not touch the network: this is called for
/// every distinct public hop address, from the diagnostic's own task.
pub trait HopEnricher: Send + Sync {
    /// ASN and country of `ip`; `None` when there is no data.
    fn lookup(&self, ip: IpAddr) -> Option<HopInfo>;
}

impl<E: HopEnricher + ?Sized> HopEnricher for Arc<E> {
    fn lookup(&self, ip: IpAddr) -> Option<HopInfo> {
        (**self).lookup(ip)
    }
}

/// An enricher that knows nothing (enrichment disabled).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoEnrich;

impl HopEnricher for NoEnrich {
    fn lookup(&self, _ip: IpAddr) -> Option<HopInfo> {
        None
    }
}

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<IpAddr, Option<HopInfo>>,
    order: VecDeque<IpAddr>,
}

/// Bounded per-address cache in front of a [`HopEnricher`], shared by consecutive runs. Misses
/// ("no data") are cached too. Private, loopback, link-local, shared (CGNAT), documentation and
/// other reserved addresses are answered `None` without calling the enricher.
#[derive(Debug)]
pub struct EnrichCache<E> {
    enricher: E,
    inner: Mutex<Inner>,
}

impl<E: HopEnricher> EnrichCache<E> {
    /// Cache in front of `enricher`.
    pub fn new(enricher: E) -> Self {
        Self {
            enricher,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn guard(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// ASN / country of `ip`, from the cache or, once per address, from the enricher.
    pub fn info(&self, ip: IpAddr) -> Option<HopInfo> {
        let ip = ip.to_canonical();
        if !is_public_ip(ip) {
            return None;
        }
        if let Some(hit) = self.guard().map.get(&ip) {
            return hit.clone();
        }
        // Looked up outside the lock so a slow database never blocks other readers.
        let found = self.enricher.lookup(ip).filter(|i| !i.is_empty());
        let mut inner = self.guard();
        if !inner.map.contains_key(&ip) {
            while inner.map.len() >= ENRICH_CACHE_CAPACITY {
                let Some(oldest) = inner.order.pop_front() else {
                    break;
                };
                inner.map.remove(&oldest);
            }
            inner.order.push_back(ip);
            inner.map.insert(ip, found.clone());
        }
        found
    }

    /// Number of cached addresses.
    pub fn len(&self) -> usize {
        self.guard().map.len()
    }

    /// `true` when nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

struct V4Block(u32, u8);
struct V6Block(u128, u8);

const RESERVED_V4: &[V4Block] = &[
    V4Block(0x0000_0000, 8),  // "this network"
    V4Block(0x0A00_0000, 8),  // private
    V4Block(0x6440_0000, 10), // shared address space (CGNAT)
    V4Block(0x7F00_0000, 8),  // loopback
    V4Block(0xA9FE_0000, 16), // link-local
    V4Block(0xAC10_0000, 12), // private
    V4Block(0xC000_0000, 24), // IETF protocol assignments
    V4Block(0xC000_0200, 24), // TEST-NET-1
    V4Block(0xC058_6300, 24), // 6to4 relay anycast (deprecated)
    V4Block(0xC0A8_0000, 16), // private
    V4Block(0xC612_0000, 15), // benchmarking
    V4Block(0xC633_6400, 24), // TEST-NET-2
    V4Block(0xCB00_7100, 24), // TEST-NET-3
    V4Block(0xE000_0000, 4),  // multicast
    V4Block(0xF000_0000, 4),  // reserved + broadcast
];

const RESERVED_V6: &[V6Block] = &[
    V6Block(0, 128),                                        // ::
    V6Block(1, 128),                                        // ::1
    V6Block(0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96), // 64:ff9b::/96 NAT64
    V6Block(0x0100_0000_0000_0000_0000_0000_0000_0000, 64), // 100::/64 discard
    V6Block(0x2001_0000_0000_0000_0000_0000_0000_0000, 23), // IETF assignments, Teredo, ORCHID
    V6Block(0x2001_0db8_0000_0000_0000_0000_0000_0000, 32), // documentation
    V6Block(0x2002_0000_0000_0000_0000_0000_0000_0000, 16), // 6to4
    V6Block(0x3fff_0000_0000_0000_0000_0000_0000_0000, 20), // documentation
    V6Block(0xfc00_0000_0000_0000_0000_0000_0000_0000, 7),  // unique local
    V6Block(0xfe80_0000_0000_0000_0000_0000_0000_0000, 10), // link-local
    V6Block(0xfec0_0000_0000_0000_0000_0000_0000_0000, 10), // site-local (deprecated)
    V6Block(0xff00_0000_0000_0000_0000_0000_0000_0000, 8),  // multicast
];

fn in_v4(addr: Ipv4Addr, block: &V4Block) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(block.1)).unwrap_or(0);
    u32::from(addr) & mask == block.0 & mask
}

fn in_v6(addr: Ipv6Addr, block: &V6Block) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(block.1)).unwrap_or(0);
    u128::from(addr) & mask == block.0 & mask
}

/// `true` for an address in globally routable space. IPv4-mapped IPv6 addresses are judged as the
/// IPv4 address they wrap. This is the gate in front of every enrichment lookup.
pub fn is_public_ip(addr: IpAddr) -> bool {
    match addr.to_canonical() {
        IpAddr::V4(v4) => !RESERVED_V4.iter().any(|b| in_v4(v4, b)),
        IpAddr::V6(v6) => !RESERVED_V6.iter().any(|b| in_v6(v6, b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn reserved_space_is_not_public() {
        for s in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:10.0.0.1",
            "fe80::1",
            "fd00::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
            "2002::1",
            "64:ff9b::1",
        ] {
            assert!(!is_public_ip(ip(s)), "{s} must not be public");
        }
    }

    #[test]
    fn global_space_is_public() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "9.9.9.9",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.0.1.1",
            "198.17.255.255",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2a00:1450::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public_ip(ip(s)), "{s} must be public");
        }
    }

    struct Counting {
        calls: AtomicUsize,
        seen: Mutex<Vec<IpAddr>>,
    }

    impl Counting {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                seen: Mutex::new(Vec::new()),
            })
        }
    }

    impl HopEnricher for Counting {
        fn lookup(&self, ip: IpAddr) -> Option<HopInfo> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(ip);
            (ip == "1.1.1.1".parse::<IpAddr>().unwrap()).then(|| HopInfo {
                asn: Some(13335),
                as_org: Some("Cloudflare, Inc.".to_owned()),
                country_code: Some("US".to_owned()),
            })
        }
    }

    #[test]
    fn caches_hits_and_misses_per_address() {
        let e = Counting::new();
        let cache = EnrichCache::new(Arc::clone(&e));
        for _ in 0..3 {
            assert_eq!(cache.info(ip("1.1.1.1")).unwrap().asn, Some(13335));
            assert_eq!(cache.info(ip("8.8.8.8")), None);
        }
        assert_eq!(e.calls.load(Ordering::SeqCst), 2, "one lookup per address");
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn private_and_reserved_addresses_never_reach_the_enricher() {
        let e = Counting::new();
        let cache = EnrichCache::new(Arc::clone(&e));
        for s in [
            "10.0.0.1",
            "192.168.0.1",
            "127.0.0.1",
            "fe80::1",
            "203.0.113.9",
        ] {
            assert_eq!(cache.info(ip(s)), None);
        }
        assert_eq!(e.calls.load(Ordering::SeqCst), 0);
        assert!(cache.is_empty(), "skipped addresses are not cached either");
        // A mapped address is judged by the address it wraps.
        assert!(cache.info(ip("::ffff:1.1.1.1")).is_some());
        assert_eq!(e.seen.lock().unwrap().as_slice(), [ip("1.1.1.1")]);
    }

    #[test]
    fn empty_answers_count_as_no_data() {
        struct Empty;
        impl HopEnricher for Empty {
            fn lookup(&self, _ip: IpAddr) -> Option<HopInfo> {
                Some(HopInfo::default())
            }
        }
        assert_eq!(EnrichCache::new(Empty).info(ip("1.1.1.1")), None);
        assert_eq!(EnrichCache::new(NoEnrich).info(ip("1.1.1.1")), None);
    }

    #[test]
    fn cache_is_bounded() {
        let cache = EnrichCache::new(NoEnrich);
        for i in 0..(ENRICH_CACHE_CAPACITY + 40) {
            let hi = u8::try_from(i / 250).unwrap();
            let lo = u8::try_from(i % 250).unwrap();
            cache.info(ip(&format!("8.8.{hi}.{lo}")));
        }
        assert_eq!(cache.len(), ENRICH_CACHE_CAPACITY);
    }
}

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Proves the hot-path claim: decoding, filtering and aggregating a packet allocates nothing (counted with
//! the test-only allocator in `sys::alloc_probe`).

#[cfg(test)]
mod tests {
    use crate::decode::{decode_ethernet, decode_ip, LocalAddrs};
    use crate::fake::{SyntheticConfig, SyntheticSource};
    use crate::filter::Filter;
    use crate::stats::{StatsAggregator, StatsConfig};
    use crate::sys::alloc_probe::allocations_in;
    use crate::{LinkType, PacketSource, SourceEvent};
    use etherparse::PacketBuilder;
    use pw_core::PacketMeta;

    fn corpus() -> Vec<Vec<u8>> {
        let v6 = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let mut syn = Vec::new();
        PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([203, 0, 113, 9], [10, 0, 0, 5], 64)
            .tcp(50000, 3389, 1, 8192)
            .syn()
            .write(&mut syn, &[])
            .unwrap();
        let mut udp = Vec::new();
        PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([198, 51, 100, 1], [10, 0, 0, 5], 64)
            .udp(1, 53)
            .write(&mut udp, &[7; 100])
            .unwrap();
        let mut tcp6 = Vec::new();
        PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv6(v6, [0; 16], 64)
            .tcp(1, 2, 3, 4)
            .write(&mut tcp6, &[])
            .unwrap();
        vec![syn, udp, tcp6]
    }

    #[test]
    fn the_probe_really_counts() {
        let allocs = allocations_in(|| {
            let v = std::hint::black_box(Vec::<u8>::with_capacity(64));
            drop(v);
        });
        assert_eq!(allocs, 1);
    }

    #[test]
    fn decoding_allocates_nothing() {
        let frames = corpus();
        let local = LocalAddrs::new(&["10.0.0.5".parse().unwrap()]);
        let mut decoded = 0u32;
        let allocs = allocations_in(|| {
            for _ in 0..2_000 {
                for frame in &frames {
                    if decode_ethernet(frame, 1, &local).is_ok() {
                        decoded += 1;
                    }
                    // Truncated and IP-level entry points too.
                    if decode_ethernet(&frame[..frame.len().min(60)], 1, &local).is_ok() {
                        decoded += 1;
                    }
                    if decode_ip(&frame[14..], 1, &local).is_ok() {
                        decoded += 1;
                    }
                }
                // Garbage.
                let _ = decode_ethernet(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3], 1, &local);
                let _ = decode_ip(&[0x45; 30], 1, &local);
            }
        });
        assert!(decoded > 10_000);
        assert_eq!(allocs, 0, "the decoder must not allocate per packet");
    }

    #[test]
    fn filtering_and_aggregating_allocate_nothing_once_built() {
        let mut src = SyntheticSource::new(SyntheticConfig {
            total_packets: Some(5_000),
            distinct_sources: 3_000,
            ..SyntheticConfig::default()
        });
        let local = LocalAddrs::new(src.local_addrs());
        let mut metas: Vec<PacketMeta> = Vec::new();
        while let Ok(SourceEvent::Frame(f)) = src.next() {
            metas.push(
                crate::decode::decode_frame(LinkType::RawIp, f.data, f.timestamp_ns, &local)
                    .unwrap(),
            );
        }
        let filter =
            Filter::parse("udp and (dst port 53 or host 10.0.0.0/8) and not icmp").unwrap();
        let mut agg = StatsAggregator::new(
            StatsConfig {
                top_n: 10,
                max_tracked_ips: 4_000,
            },
            0,
        );
        let mut passed = 0u32;
        let allocs = allocations_in(|| {
            for m in &metas {
                if filter.matches(m) {
                    passed += 1;
                }
                agg.observe(m);
            }
        });
        assert_eq!(passed as usize, metas.len());
        assert_eq!(
            allocs, 0,
            "filtering and aggregating must not allocate per packet"
        );
        assert!(agg.tracked_sources() <= 4_000);
    }

    #[test]
    fn the_synthetic_source_allocates_nothing() {
        let mut src = SyntheticSource::new(SyntheticConfig {
            total_packets: Some(10_000),
            ..SyntheticConfig::default()
        });
        let mut n = 0;
        let allocs = allocations_in(|| {
            while let Ok(SourceEvent::Frame(_)) = src.next() {
                n += 1;
            }
        });
        assert_eq!(n, 10_000);
        assert_eq!(allocs, 0);
    }
}

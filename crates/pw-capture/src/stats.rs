// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Live statistics: per-protocol rates, inbound/outbound totals and top talkers, closed into a
//! [`StatsSnapshot`] by [`StatsAggregator::tick`].
//!
//! The aggregator is pure and deterministic: it never reads a clock. The caller passes `now_ns` to
//! [`StatsAggregator::tick`] (normally once per second) and rates are computed over exactly the time since
//! the previous tick.
//!
//! # Top talkers and the memory bound
//! A talker is the **source IP of inbound packets** (who is sending to this machine). Per interval the
//! aggregator keeps at most [`StatsConfig::max_tracked_ips`] sources in a hash table allocated up front, so
//! memory is bounded no matter how many distinct (spoofed) sources a flood uses and nothing is allocated
//! per packet. Eviction policy:
//!
//! * A source that arrives while the table is full is **not tracked**; its packets and bytes are added to
//!   `untracked_packets` / `untracked_bytes` in the snapshot, so the UI can say "plus N packets from many
//!   other sources" instead of hiding them. Nothing already tracked is evicted within an interval.
//! * At every tick the table is cleared, except that the sources of the previous interval's top N keep their
//!   slot (with zeroed counters). A persistent heavy hitter is therefore tracked from the first packet of
//!   the next interval even when a spoofed flood fills the table immediately.
//!
//! Limitation: a heavy hitter that *starts* after the table filled stays untracked until the next tick has
//! room for it (it is still counted in the protocol and direction totals).

use std::collections::HashMap;
use std::net::IpAddr;

use pw_core::{Direction, PacketMeta, Protocol};
use serde::{Deserialize, Serialize};

pub const DEFAULT_TOP_N: usize = 10;
pub const DEFAULT_MAX_TRACKED_IPS: usize = 50_000;

#[derive(Debug, Clone, Copy)]
pub struct StatsConfig {
    /// How many talkers a snapshot lists.
    pub top_n: usize,
    /// Upper bound on distinct inbound sources tracked per interval.
    pub max_tracked_ips: usize,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            top_n: DEFAULT_TOP_N,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
        }
    }
}

/// Counters of one protocol class over one interval, split by direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoStats {
    pub in_packets: u64,
    pub in_bytes: u64,
    pub out_packets: u64,
    pub out_bytes: u64,
    /// Packets per second, both directions.
    pub pps: u64,
    /// Bits per second, both directions.
    pub bps: u64,
}

/// One direction over one interval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectionStats {
    pub packets: u64,
    pub bytes: u64,
    pub pps: u64,
    /// Bits per second.
    pub bps: u64,
}

/// An inbound source over one interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Talker {
    pub ip: IpAddr,
    pub packets: u64,
    pub bytes: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub other_packets: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsSnapshot {
    /// The `now_ns` given to the tick that produced this snapshot.
    pub timestamp_ns: u64,
    /// Length of the interval the numbers cover.
    pub interval_ns: u64,
    pub inbound: DirectionStats,
    pub outbound: DirectionStats,
    pub tcp: ProtoStats,
    pub udp: ProtoStats,
    pub icmp: ProtoStats,
    pub other: ProtoStats,
    /// Busiest inbound sources by packets (ties: bytes, then address), at most `top_n`.
    pub top_talkers: Vec<Talker>,
    /// Distinct inbound sources tracked in this interval (never above `max_tracked_ips`).
    pub tracked_sources: usize,
    /// Inbound packets and bytes from sources that did not fit in the table.
    pub untracked_packets: u64,
    pub untracked_bytes: u64,
    /// Cumulative since the aggregator was created.
    pub total_inbound_packets: u64,
    pub total_inbound_bytes: u64,
    pub total_outbound_packets: u64,
    pub total_outbound_bytes: u64,
    /// Packets lost before they were counted (pipeline queue plus kernel), cumulative. Set with
    /// [`StatsAggregator::set_dropped_total`]; losses are reported, never hidden.
    pub dropped_packets: u64,
    /// Part of `dropped_packets` that happened during this interval.
    pub dropped_in_interval: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct ProtoAcc {
    in_packets: u64,
    in_bytes: u64,
    out_packets: u64,
    out_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct TalkerAcc {
    packets: u64,
    bytes: u64,
    mix: [u64; 4],
}

fn proto_index(p: Protocol) -> usize {
    match p {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
        Protocol::Icmp => 2,
        Protocol::Other(_) => 3,
    }
}

/// `count` events over `interval_ns`, per second.
fn per_second(count: u64, interval_ns: u64) -> u64 {
    let rate = u128::from(count) * 1_000_000_000 / u128::from(interval_ns.max(1));
    u64::try_from(rate).unwrap_or(u64::MAX)
}

pub struct StatsAggregator {
    cfg: StatsConfig,
    last_tick_ns: u64,
    protos: [ProtoAcc; 4],
    talkers: HashMap<IpAddr, TalkerAcc>,
    untracked_packets: u64,
    untracked_bytes: u64,
    in_packets: u64,
    in_bytes: u64,
    out_packets: u64,
    out_bytes: u64,
    total_in_packets: u64,
    total_in_bytes: u64,
    total_out_packets: u64,
    total_out_bytes: u64,
    dropped_total: u64,
    dropped_at_last_tick: u64,
}

impl StatsAggregator {
    /// `start_ns` is the time the first interval begins (the caller's clock).
    pub fn new(cfg: StatsConfig, start_ns: u64) -> Self {
        let cfg = StatsConfig {
            top_n: cfg.top_n.max(1),
            max_tracked_ips: cfg.max_tracked_ips.max(1),
        };
        Self {
            // Allocated once; the table never grows past `max_tracked_ips`, so it never reallocates.
            talkers: HashMap::with_capacity(cfg.max_tracked_ips),
            cfg,
            last_tick_ns: start_ns,
            protos: [ProtoAcc::default(); 4],
            untracked_packets: 0,
            untracked_bytes: 0,
            in_packets: 0,
            in_bytes: 0,
            out_packets: 0,
            out_bytes: 0,
            total_in_packets: 0,
            total_in_bytes: 0,
            total_out_packets: 0,
            total_out_bytes: 0,
            dropped_total: 0,
            dropped_at_last_tick: 0,
        }
    }

    /// Sources currently tracked (for tests and memory assertions).
    pub fn tracked_sources(&self) -> usize {
        self.talkers.len()
    }

    /// Records the cumulative number of dropped packets (pipeline queue plus kernel) to report.
    pub fn set_dropped_total(&mut self, dropped: u64) {
        self.dropped_total = dropped;
    }

    pub fn observe_batch(&mut self, batch: &[PacketMeta]) {
        for meta in batch {
            self.observe(meta);
        }
    }

    pub fn observe(&mut self, meta: &PacketMeta) {
        let bytes = u64::from(meta.len);
        let idx = proto_index(meta.proto);
        match meta.direction {
            Direction::Outbound => {
                self.out_packets += 1;
                self.out_bytes += bytes;
                self.protos[idx].out_packets += 1;
                self.protos[idx].out_bytes += bytes;
            }
            Direction::Inbound => {
                self.in_packets += 1;
                self.in_bytes += bytes;
                self.protos[idx].in_packets += 1;
                self.protos[idx].in_bytes += bytes;
                self.observe_source(meta.src, idx, bytes);
            }
        }
    }

    fn observe_source(&mut self, src: IpAddr, proto_idx: usize, bytes: u64) {
        let full = self.talkers.len() >= self.cfg.max_tracked_ips;
        let acc = match self.talkers.get_mut(&src) {
            Some(acc) => acc,
            None if full => {
                self.untracked_packets += 1;
                self.untracked_bytes += bytes;
                return;
            }
            None => self.talkers.entry(src).or_default(),
        };
        acc.packets += 1;
        acc.bytes += bytes;
        acc.mix[proto_idx] += 1;
    }

    /// Closes the current interval at `now_ns` and starts the next one. A `now_ns` that is not after the
    /// previous tick yields a 1 ns interval instead of dividing by zero.
    pub fn tick(&mut self, now_ns: u64) -> StatsSnapshot {
        let interval_ns = now_ns.saturating_sub(self.last_tick_ns).max(1);
        self.last_tick_ns = now_ns.max(self.last_tick_ns);

        let proto_stats = |acc: &ProtoAcc| ProtoStats {
            in_packets: acc.in_packets,
            in_bytes: acc.in_bytes,
            out_packets: acc.out_packets,
            out_bytes: acc.out_bytes,
            pps: per_second(acc.in_packets + acc.out_packets, interval_ns),
            bps: per_second(
                (acc.in_bytes + acc.out_bytes).saturating_mul(8),
                interval_ns,
            ),
        };
        let dir_stats = |packets: u64, bytes: u64| DirectionStats {
            packets,
            bytes,
            pps: per_second(packets, interval_ns),
            bps: per_second(bytes.saturating_mul(8), interval_ns),
        };

        // Rank the sources: select the best `top_n` in O(n), then sort only those.
        let mut ranked: Vec<(IpAddr, TalkerAcc)> = self
            .talkers
            .iter()
            .filter(|(_, acc)| acc.packets > 0)
            .map(|(ip, acc)| (*ip, *acc))
            .collect();
        let order = |a: &(IpAddr, TalkerAcc), b: &(IpAddr, TalkerAcc)| {
            b.1.packets
                .cmp(&a.1.packets)
                .then(b.1.bytes.cmp(&a.1.bytes))
                .then(a.0.cmp(&b.0))
        };
        if ranked.len() > self.cfg.top_n {
            ranked.select_nth_unstable_by(self.cfg.top_n, order);
            ranked.truncate(self.cfg.top_n);
        }
        ranked.sort_unstable_by(order);
        let top_talkers: Vec<Talker> = ranked
            .iter()
            .map(|(ip, acc)| Talker {
                ip: *ip,
                packets: acc.packets,
                bytes: acc.bytes,
                tcp_packets: acc.mix[0],
                udp_packets: acc.mix[1],
                icmp_packets: acc.mix[2],
                other_packets: acc.mix[3],
            })
            .collect();

        self.total_in_packets += self.in_packets;
        self.total_in_bytes += self.in_bytes;
        self.total_out_packets += self.out_packets;
        self.total_out_bytes += self.out_bytes;

        let snapshot = StatsSnapshot {
            timestamp_ns: now_ns,
            interval_ns,
            inbound: dir_stats(self.in_packets, self.in_bytes),
            outbound: dir_stats(self.out_packets, self.out_bytes),
            tcp: proto_stats(&self.protos[0]),
            udp: proto_stats(&self.protos[1]),
            icmp: proto_stats(&self.protos[2]),
            other: proto_stats(&self.protos[3]),
            top_talkers,
            tracked_sources: self.talkers.len(),
            untracked_packets: self.untracked_packets,
            untracked_bytes: self.untracked_bytes,
            total_inbound_packets: self.total_in_packets,
            total_inbound_bytes: self.total_in_bytes,
            total_outbound_packets: self.total_out_packets,
            total_outbound_bytes: self.total_out_bytes,
            dropped_packets: self.dropped_total,
            dropped_in_interval: self.dropped_total.saturating_sub(self.dropped_at_last_tick),
        };

        // Next interval: zero the counters; known heavy hitters keep a slot.
        self.dropped_at_last_tick = self.dropped_total;
        self.protos = [ProtoAcc::default(); 4];
        self.in_packets = 0;
        self.in_bytes = 0;
        self.out_packets = 0;
        self.out_bytes = 0;
        self.untracked_packets = 0;
        self.untracked_bytes = 0;
        self.talkers.clear();
        for (ip, _) in &ranked {
            self.talkers.insert(*ip, TalkerAcc::default());
        }

        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pw_core::TCP_SYN;

    const SEC: u64 = 1_000_000_000;

    fn pkt(src: &str, proto: Protocol, len: u32, dir: Direction) -> PacketMeta {
        PacketMeta {
            timestamp_ns: 0,
            src: src.parse().unwrap(),
            dst: "10.0.0.5".parse().unwrap(),
            src_port: 1000,
            dst_port: 80,
            proto,
            tcp_flags: if proto == Protocol::Tcp { TCP_SYN } else { 0 },
            len,
            direction: dir,
        }
    }

    fn ip(n: u32) -> IpAddr {
        IpAddr::from(n.to_be_bytes())
    }

    #[test]
    fn rates_and_totals_over_a_one_second_tick() {
        let mut agg = StatsAggregator::new(StatsConfig::default(), 0);
        for _ in 0..100 {
            agg.observe(&pkt("1.1.1.1", Protocol::Tcp, 60, Direction::Inbound));
        }
        for _ in 0..50 {
            agg.observe(&pkt("1.1.1.1", Protocol::Udp, 200, Direction::Inbound));
        }
        for _ in 0..10 {
            agg.observe(&pkt("10.0.0.5", Protocol::Icmp, 84, Direction::Outbound));
        }
        agg.observe(&pkt(
            "1.1.1.1",
            Protocol::Other(47),
            100,
            Direction::Inbound,
        ));
        let s = agg.tick(SEC);
        assert_eq!(s.interval_ns, SEC);
        assert_eq!(s.inbound.packets, 151);
        assert_eq!(s.inbound.bytes, 100 * 60 + 50 * 200 + 100);
        assert_eq!(s.inbound.pps, 151);
        assert_eq!(s.inbound.bps, (100 * 60 + 50 * 200 + 100) * 8);
        assert_eq!(s.outbound.packets, 10);
        assert_eq!(s.outbound.bytes, 840);
        assert_eq!(
            (s.tcp.in_packets, s.tcp.pps, s.tcp.bps),
            (100, 100, 100 * 60 * 8)
        );
        assert_eq!((s.udp.in_packets, s.udp.pps), (50, 50));
        assert_eq!(
            (s.icmp.out_packets, s.icmp.out_bytes, s.icmp.in_packets),
            (10, 840, 0)
        );
        assert_eq!(s.other.in_packets, 1);
        assert_eq!(s.total_inbound_packets, 151);
        // The next interval starts empty but totals accumulate.
        let s2 = agg.tick(2 * SEC);
        assert_eq!(s2.inbound.packets, 0);
        assert_eq!(s2.total_inbound_packets, 151);
        assert_eq!(s2.top_talkers.len(), 0);
    }

    #[test]
    fn rates_scale_with_the_actual_interval() {
        let mut agg = StatsAggregator::new(StatsConfig::default(), 5 * SEC);
        for _ in 0..1000 {
            agg.observe(&pkt("1.1.1.1", Protocol::Tcp, 100, Direction::Inbound));
        }
        let s = agg.tick(5 * SEC + SEC / 2);
        assert_eq!(s.interval_ns, SEC / 2);
        assert_eq!(s.inbound.pps, 2000);
        assert_eq!(s.inbound.bps, 1000 * 100 * 8 * 2);
    }

    #[test]
    fn a_tick_that_does_not_advance_cannot_divide_by_zero() {
        let mut agg = StatsAggregator::new(StatsConfig::default(), 10);
        agg.observe(&pkt("1.1.1.1", Protocol::Tcp, 100, Direction::Inbound));
        let s = agg.tick(10);
        assert_eq!(s.interval_ns, 1);
        assert!(s.inbound.pps >= 1);
        // Going backwards is treated the same way.
        let s = agg.tick(5);
        assert_eq!(s.interval_ns, 1);
    }

    #[test]
    fn top_talkers_are_ranked_and_only_count_inbound() {
        let cfg = StatsConfig {
            top_n: 3,
            ..StatsConfig::default()
        };
        let mut agg = StatsAggregator::new(cfg, 0);
        let feed = |agg: &mut StatsAggregator, src: &str, n: u32, len: u32| {
            for _ in 0..n {
                agg.observe(&pkt(src, Protocol::Tcp, len, Direction::Inbound));
            }
        };
        feed(&mut agg, "9.9.9.9", 5, 100);
        feed(&mut agg, "8.8.8.8", 50, 100);
        feed(&mut agg, "7.7.7.7", 50, 200); // same packets as 8.8.8.8, more bytes
        feed(&mut agg, "6.6.6.6", 20, 100);
        feed(&mut agg, "5.5.5.5", 1, 100);
        agg.observe(&pkt("7.7.7.7", Protocol::Udp, 100, Direction::Inbound));
        // Outbound traffic from a local address never becomes a talker.
        for _ in 0..500 {
            agg.observe(&pkt("10.0.0.5", Protocol::Tcp, 100, Direction::Outbound));
        }
        let s = agg.tick(SEC);
        let ips: Vec<String> = s.top_talkers.iter().map(|t| t.ip.to_string()).collect();
        assert_eq!(ips, ["7.7.7.7", "8.8.8.8", "6.6.6.6"]);
        let top = &s.top_talkers[0];
        assert_eq!((top.packets, top.bytes), (51, 50 * 200 + 100));
        assert_eq!(
            (
                top.tcp_packets,
                top.udp_packets,
                top.icmp_packets,
                top.other_packets
            ),
            (50, 1, 0, 0)
        );
        assert_eq!(s.tracked_sources, 5);
    }

    #[test]
    fn equal_talkers_are_ordered_by_address() {
        let mut agg = StatsAggregator::new(StatsConfig::default(), 0);
        for src in ["2.2.2.2", "1.1.1.1", "3.3.3.3"] {
            agg.observe(&pkt(src, Protocol::Tcp, 100, Direction::Inbound));
        }
        let s = agg.tick(SEC);
        let ips: Vec<String> = s.top_talkers.iter().map(|t| t.ip.to_string()).collect();
        assert_eq!(ips, ["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
    }

    #[test]
    fn tracked_sources_are_capped_and_the_rest_is_counted() {
        let cfg = StatsConfig {
            top_n: 5,
            max_tracked_ips: 100,
        };
        let mut agg = StatsAggregator::new(cfg, 0);
        for n in 0..10_000u32 {
            agg.observe(&PacketMeta {
                src: ip(n),
                ..pkt("1.1.1.1", Protocol::Udp, 100, Direction::Inbound)
            });
            assert!(agg.tracked_sources() <= 100);
        }
        let s = agg.tick(SEC);
        assert_eq!(s.tracked_sources, 100);
        assert_eq!(s.untracked_packets, 9_900);
        assert_eq!(s.untracked_bytes, 9_900 * 100);
        // Direction and protocol totals still include every packet.
        assert_eq!(s.inbound.packets, 10_000);
        assert_eq!(s.udp.in_packets, 10_000);
        assert_eq!(s.top_talkers.len(), 5);
    }

    #[test]
    fn heavy_hitters_keep_their_slot_across_ticks() {
        let cfg = StatsConfig {
            top_n: 1,
            max_tracked_ips: 10,
        };
        let mut agg = StatsAggregator::new(cfg, 0);
        for _ in 0..100 {
            agg.observe(&pkt("203.0.113.9", Protocol::Udp, 100, Direction::Inbound));
        }
        let s = agg.tick(SEC);
        assert_eq!(
            s.top_talkers[0].ip,
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // A spoofed flood fills the table first in the next interval...
        for n in 0..1000u32 {
            agg.observe(&PacketMeta {
                src: ip(n + 1),
                ..pkt("1.1.1.1", Protocol::Udp, 100, Direction::Inbound)
            });
        }
        // ...but the known heavy hitter is still tracked.
        for _ in 0..20 {
            agg.observe(&pkt("203.0.113.9", Protocol::Udp, 100, Direction::Inbound));
        }
        let s = agg.tick(2 * SEC);
        assert_eq!(
            s.top_talkers[0].ip,
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(s.top_talkers[0].packets, 20);
        assert!(s.tracked_sources <= 10);
        // Carried-over slots with no traffic are not listed.
        let s = agg.tick(3 * SEC);
        assert!(s.top_talkers.is_empty());
    }

    #[test]
    fn dropped_packets_are_reported_cumulatively_and_per_interval() {
        let mut agg = StatsAggregator::new(StatsConfig::default(), 0);
        agg.set_dropped_total(7);
        let s = agg.tick(SEC);
        assert_eq!((s.dropped_packets, s.dropped_in_interval), (7, 7));
        agg.set_dropped_total(10);
        let s = agg.tick(2 * SEC);
        assert_eq!((s.dropped_packets, s.dropped_in_interval), (10, 3));
        let s = agg.tick(3 * SEC);
        assert_eq!((s.dropped_packets, s.dropped_in_interval), (10, 0));
    }

    #[test]
    fn identical_input_gives_identical_snapshots() {
        let run = || {
            let mut agg = StatsAggregator::new(StatsConfig::default(), 0);
            for n in 0..5000u32 {
                agg.observe(&PacketMeta {
                    src: ip(n % 37),
                    ..pkt("1.1.1.1", Protocol::Tcp, 60 + n % 7, Direction::Inbound)
                });
            }
            agg.tick(SEC)
        };
        assert_eq!(run(), run());
    }
}

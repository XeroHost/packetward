// SPDX-License-Identifier: GPL-3.0-or-later
//! Deterministic synthetic traffic for tests of this crate and of its users (Guardian, engine).
//!
//! Available to this crate's own tests and, for other crates, behind the `testgen` feature. Every
//! generator is a pure function of its arguments (a seeded SplitMix64 where randomness is needed), so
//! two runs produce identical packets. Addresses come from the documentation ranges: the server is
//! `198.51.100.10`, attackers are `203.0.113.x`, legitimate infrastructure is `192.0.2.x`, ordinary
//! clients are `100.64.0.0 + n`.
//!
//! All timestamps are nanoseconds since the Unix epoch. Use [`T0`] (a realistic epoch) for the main
//! scenarios; start at `0` only in tests of the zero edge case.

use std::net::{IpAddr, Ipv4Addr};

use pw_core::{Direction, PacketMeta, Protocol, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};

use crate::{Alert, Engine, NS_PER_SEC};

/// One second in nanoseconds.
pub const SECOND: u64 = NS_PER_SEC;
/// A realistic start time (2027-01-15), far from the zero edge case.
pub const T0: u64 = 1_800_000_000 * SECOND;

/// The protected machine.
pub const SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
pub const ATTACKER_SYN: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
pub const ATTACKER_UDP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
pub const ATTACKER_ICMP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3));
pub const ATTACKER_SCAN: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));
pub const ATTACKER_RDP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
/// A legitimate RDP user (used by the "heavy but legitimate" traffic).
pub const RDP_USER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));

/// SplitMix64: tiny, fast, deterministic.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Uniform in `0..n` (`n > 0`; 0 yields 0).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

pub fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// The `n`-th ordinary client (`100.64.0.0 + n`).
pub fn client_ip(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(0x6440_0000u32.wrapping_add(n)))
}

/// A failed RDP logon (what `Security 4625` parsing would yield).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonFailure {
    pub ip: IpAddr,
    pub at_ns: u64,
}

#[allow(clippy::too_many_arguments)]
fn packet(
    ts: u64,
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    proto: Protocol,
    tcp_flags: u8,
    len: u32,
    direction: Direction,
) -> PacketMeta {
    PacketMeta {
        timestamp_ns: ts,
        src,
        dst,
        src_port,
        dst_port,
        proto,
        tcp_flags,
        len,
        direction,
    }
}

/// One inbound TCP packet to [`SERVER`].
pub fn inbound_tcp(
    ts: u64,
    src: IpAddr,
    sport: u16,
    dport: u16,
    flags: u8,
    len: u32,
) -> PacketMeta {
    packet(
        ts,
        src,
        SERVER,
        sport,
        dport,
        Protocol::Tcp,
        flags,
        len,
        Direction::Inbound,
    )
}

/// One inbound UDP datagram to [`SERVER`].
pub fn inbound_udp(ts: u64, src: IpAddr, sport: u16, dport: u16, len: u32) -> PacketMeta {
    packet(
        ts,
        src,
        SERVER,
        sport,
        dport,
        Protocol::Udp,
        0,
        len,
        Direction::Inbound,
    )
}

/// One inbound ICMP packet to [`SERVER`].
pub fn inbound_icmp(ts: u64, src: IpAddr, len: u32) -> PacketMeta {
    packet(
        ts,
        src,
        SERVER,
        0,
        0,
        Protocol::Icmp,
        0,
        len,
        Direction::Inbound,
    )
}

fn outbound_tcp(ts: u64, dst: IpAddr, sport: u16, dport: u16, flags: u8, len: u32) -> PacketMeta {
    packet(
        ts,
        SERVER,
        dst,
        sport,
        dport,
        Protocol::Tcp,
        flags,
        len,
        Direction::Outbound,
    )
}

/// Merge streams into one slice ordered by timestamp (stable: equal timestamps keep input order).
pub fn merge(streams: Vec<Vec<PacketMeta>>) -> Vec<PacketMeta> {
    let mut all: Vec<PacketMeta> = streams.into_iter().flatten().collect();
    all.sort_by_key(|p| p.timestamp_ns);
    all
}

/// Evenly spaced timestamps: the `i`-th of a stream at `pps` packets per second.
fn at(start_ns: u64, i: u64, pps: u64) -> u64 {
    start_ns + i * SECOND / pps.max(1)
}

// ---- legitimate traffic ------------------------------------------------------------------------

/// A busy, healthy server for `secs` seconds: `clients` distinct clients each opening 1-3 complete
/// TCP connections to 80/443, five clients doing large downloads, a NAT with many completing
/// connections, DNS/NTP replies to random ephemeral ports (the server's own lookups), SYN-ACKs and
/// bulk data for the server's outbound connections, mDNS/SSDP/NetBIOS/DHCP broadcast and multicast,
/// a heavy legitimate RDP client over TCP and UDP 3389, and a monitoring ping. No detector may fire
/// on this. About 300 000 packets for 4000 clients and 20 s.
pub fn normal_web(seed: u64, start_ns: u64, secs: u32, clients: u32) -> Vec<PacketMeta> {
    let mut rng = Rng::new(seed);
    let span = u64::from(secs) * SECOND;
    let mut v = Vec::new();

    for c in 0..clients {
        let ip = client_ip(c);
        for _ in 0..1 + rng.below(3) {
            let t = start_ns + rng.below(span);
            let sport = 49_152 + rng.below(16_000) as u16;
            let dport = if rng.below(10) < 7 { 443 } else { 80 };
            v.push(inbound_tcp(t, ip, sport, dport, TCP_SYN, 52));
            v.push(outbound_tcp(
                t + 20_000_000,
                ip,
                dport,
                sport,
                TCP_SYN | TCP_ACK,
                52,
            ));
            v.push(inbound_tcp(t + 40_000_000, ip, sport, dport, TCP_ACK, 40));
            v.push(inbound_tcp(
                t + 45_000_000,
                ip,
                sport,
                dport,
                TCP_PSH | TCP_ACK,
                400,
            ));
            let rounds = 5 + rng.below(10);
            for i in 0..rounds {
                let tr = t + 60_000_000 + i * 10_000_000;
                v.push(outbound_tcp(tr, ip, dport, sport, TCP_PSH | TCP_ACK, 1500));
                v.push(inbound_tcp(tr + 5_000_000, ip, sport, dport, TCP_ACK, 40));
            }
            let tf = t + 60_000_000 + rounds * 10_000_000;
            v.push(inbound_tcp(tf, ip, sport, dport, TCP_FIN | TCP_ACK, 40));
            v.push(outbound_tcp(
                tf + 1_000_000,
                ip,
                dport,
                sport,
                TCP_FIN | TCP_ACK,
                40,
            ));
            v.push(inbound_tcp(tf + 2_000_000, ip, sport, dport, TCP_ACK, 40));
        }
    }

    // Large downloads: the client only sends ACKs back (400 pps each).
    for d in 0..5u32 {
        let ip = client_ip(1_000_000 + d);
        let sport = 50_000 + d as u16;
        v.push(inbound_tcp(start_ns, ip, sport, 443, TCP_SYN, 52));
        v.push(inbound_tcp(
            start_ns + 40_000_000,
            ip,
            sport,
            443,
            TCP_ACK,
            40,
        ));
        for i in 0..(u64::from(secs) * 400) {
            v.push(inbound_tcp(
                at(start_ns + 100_000_000, i, 400),
                ip,
                sport,
                443,
                TCP_ACK,
                40,
            ));
        }
    }

    // A NAT: 6 new, completing connections per second from one address.
    let nat = ip4(192, 0, 2, 77);
    for i in 0..(u64::from(secs) * 6) {
        let t = at(start_ns, i, 6);
        let sport = 20_000 + (i % 30_000) as u16;
        v.push(inbound_tcp(t, nat, sport, 443, TCP_SYN, 52));
        v.push(inbound_tcp(t + 30_000_000, nat, sport, 443, TCP_ACK, 40));
        v.push(inbound_tcp(
            t + 35_000_000,
            nat,
            sport,
            443,
            TCP_PSH | TCP_ACK,
            300,
        ));
    }

    // Replies to the server's own lookups: random ephemeral destination ports, well-known source.
    for (r, resolver) in [ip4(8, 8, 8, 8), ip4(1, 1, 1, 1)].into_iter().enumerate() {
        for i in 0..300u64 {
            let t = at(start_ns, i, 300 / u64::from(secs).max(1)).min(start_ns + span);
            let dport = 49_152 + rng.below(16_000) as u16;
            v.push(packet(
                t + r as u64,
                resolver,
                SERVER,
                53,
                dport,
                Protocol::Udp,
                0,
                120,
                Direction::Inbound,
            ));
        }
    }
    let ntp = ip4(192, 0, 2, 123);
    for i in 0..40u64 {
        let dport = 49_152 + rng.below(16_000) as u16;
        v.push(packet(
            start_ns + i * span / 40,
            ntp,
            SERVER,
            123,
            dport,
            Protocol::Udp,
            0,
            76,
            Direction::Inbound,
        ));
    }

    // SYN-ACKs for the server's outbound connections (random ephemeral destination ports).
    for s in 0..4u8 {
        let remote = ip4(192, 0, 2, 200 + s);
        for i in 0..60u64 {
            let dport = 49_152 + rng.below(16_000) as u16;
            v.push(inbound_tcp(
                start_ns + i * span / 60 + u64::from(s),
                remote,
                443,
                dport,
                TCP_SYN | TCP_ACK,
                52,
            ));
        }
    }
    // Bulk download into the server: 1000 pps of full-size data segments from one source.
    let origin = ip4(192, 0, 2, 201);
    for i in 0..(u64::from(secs) * 1000) {
        v.push(inbound_tcp(
            at(start_ns, i, 1000),
            origin,
            443,
            51_000,
            TCP_ACK,
            1400,
        ));
    }

    // mDNS / SSDP / NetBIOS / DHCP: multicast and broadcast destinations.
    for i in 0..20u64 {
        let t = start_ns + i * span / 20;
        v.push(packet(
            t,
            ip4(192, 0, 2, 50),
            ip4(224, 0, 0, 251),
            5353,
            5353,
            Protocol::Udp,
            0,
            90,
            Direction::Inbound,
        ));
        v.push(packet(
            t,
            ip4(192, 0, 2, 51),
            ip4(239, 255, 255, 250),
            1900,
            1900,
            Protocol::Udp,
            0,
            200,
            Direction::Inbound,
        ));
        v.push(packet(
            t,
            ip4(192, 0, 2, 52),
            ip4(198, 51, 100, 255),
            137,
            137,
            Protocol::Udp,
            0,
            78,
            Direction::Inbound,
        ));
        v.push(packet(
            t,
            ip4(192, 0, 2, 53),
            ip4(255, 255, 255, 255),
            68,
            67,
            Protocol::Udp,
            0,
            300,
            Direction::Inbound,
        ));
    }

    // A heavy legitimate RDP user: TCP 3389 and UDP 3389 at 1500 pps each.
    for i in 0..(u64::from(secs) * 1500) {
        let t = at(start_ns, i, 1500);
        v.push(inbound_tcp(
            t,
            RDP_USER,
            52_000,
            3389,
            TCP_PSH | TCP_ACK,
            600,
        ));
        v.push(packet(
            t,
            RDP_USER,
            SERVER,
            54_000,
            3389,
            Protocol::Udp,
            0,
            1200,
            Direction::Inbound,
        ));
    }

    // Monitoring: one ping per second.
    let monitor = ip4(192, 0, 2, 250);
    for i in 0..u64::from(secs) {
        v.push(packet(
            start_ns + i * SECOND,
            monitor,
            SERVER,
            0,
            0,
            Protocol::Icmp,
            0,
            84,
            Direction::Inbound,
        ));
    }

    v.sort_by_key(|p| p.timestamp_ns);
    v
}

// ---- attacks -----------------------------------------------------------------------------------

/// SYN flood from one address at `pps`; the handshake never completes.
pub fn syn_flood(attacker: IpAddr, start_ns: u64, secs: u32, pps: u64) -> Vec<PacketMeta> {
    (0..u64::from(secs) * pps)
        .map(|i| {
            inbound_tcp(
                at(start_ns, i, pps),
                attacker,
                1024 + (i % 60_000) as u16,
                443,
                TCP_SYN,
                60,
            )
        })
        .collect()
}

/// SYN flood with a different random source address for every packet.
pub fn spoofed_syn_flood(seed: u64, start_ns: u64, secs: u32, pps: u64) -> Vec<PacketMeta> {
    spoofed_syn_iter(seed, start_ns, pps, u64::from(secs) * pps).collect()
}

/// UDP flood from one address.
pub fn udp_flood(
    attacker: IpAddr,
    start_ns: u64,
    secs: u32,
    pps: u64,
    len: u32,
) -> Vec<PacketMeta> {
    (0..u64::from(secs) * pps)
        .map(|i| {
            packet(
                at(start_ns, i, pps),
                attacker,
                SERVER,
                40_000 + (i % 20_000) as u16,
                27_015,
                Protocol::Udp,
                0,
                len,
                Direction::Inbound,
            )
        })
        .collect()
}

/// ICMP echo flood from one address.
pub fn icmp_flood(attacker: IpAddr, start_ns: u64, secs: u32, pps: u64) -> Vec<PacketMeta> {
    (0..u64::from(secs) * pps)
        .map(|i| {
            packet(
                at(start_ns, i, pps),
                attacker,
                SERVER,
                0,
                0,
                Protocol::Icmp,
                0,
                84,
                Direction::Inbound,
            )
        })
        .collect()
}

/// A vertical scan: one SYN per port in `ports`, `interval_ns` apart (the server answers closed
/// ports with an outbound RST).
pub fn port_scan_vertical(
    attacker: IpAddr,
    start_ns: u64,
    ports: impl IntoIterator<Item = u16>,
    interval_ns: u64,
) -> Vec<PacketMeta> {
    let mut v = Vec::new();
    for (i, port) in ports.into_iter().enumerate() {
        let t = start_ns + i as u64 * interval_ns;
        v.push(inbound_tcp(t, attacker, 44_444, port, TCP_SYN, 44));
        v.push(outbound_tcp(
            t + 100_000,
            attacker,
            port,
            44_444,
            TCP_RST | TCP_ACK,
            40,
        ));
    }
    v
}

/// A stealth scan: TCP packets with no SYN/ACK/RST (`flags` = 0 NULL, `TCP_FIN` FIN scan, ...).
pub fn stealth_scan(
    attacker: IpAddr,
    start_ns: u64,
    ports: impl IntoIterator<Item = u16>,
    interval_ns: u64,
    flags: u8,
) -> Vec<PacketMeta> {
    ports
        .into_iter()
        .enumerate()
        .map(|(i, port)| {
            inbound_tcp(
                start_ns + i as u64 * interval_ns,
                attacker,
                44_445,
                port,
                flags,
                40,
            )
        })
        .collect()
}

/// A UDP port scan from a fixed high source port.
pub fn udp_port_scan(
    attacker: IpAddr,
    start_ns: u64,
    ports: impl IntoIterator<Item = u16>,
    interval_ns: u64,
) -> Vec<PacketMeta> {
    ports
        .into_iter()
        .enumerate()
        .map(|(i, port)| {
            packet(
                start_ns + i as u64 * interval_ns,
                attacker,
                SERVER,
                50_000,
                port,
                Protocol::Udp,
                0,
                28,
                Direction::Inbound,
            )
        })
        .collect()
}

/// A horizontal sweep: one SYN to `port` on every address in `targets`.
pub fn port_scan_horizontal(
    attacker: IpAddr,
    start_ns: u64,
    targets: &[IpAddr],
    port: u16,
    interval_ns: u64,
) -> Vec<PacketMeta> {
    targets
        .iter()
        .enumerate()
        .map(|(i, dst)| {
            packet(
                start_ns + i as u64 * interval_ns,
                attacker,
                *dst,
                44_446,
                port,
                Protocol::Tcp,
                TCP_SYN,
                44,
                Direction::Inbound,
            )
        })
        .collect()
}

/// A slow scan: one port every `interval_ns` (use 1 s or more to model "slow").
pub fn slow_scan(
    attacker: IpAddr,
    start_ns: u64,
    port_count: u16,
    interval_ns: u64,
) -> Vec<PacketMeta> {
    port_scan_vertical(attacker, start_ns, 1..=port_count, interval_ns)
}

/// A new, **completing** TCP connection every `1/cps` s from one address (a connection flood as seen
/// by capture): SYN, ACK, data.
pub fn conn_flood_capture(attacker: IpAddr, start_ns: u64, secs: u32, cps: u64) -> Vec<PacketMeta> {
    let mut v = Vec::new();
    for i in 0..u64::from(secs) * cps {
        let t = at(start_ns, i, cps);
        let sport = 1024 + (i % 60_000) as u16;
        v.push(inbound_tcp(t, attacker, sport, 443, TCP_SYN, 52));
        v.push(inbound_tcp(t + 100_000, attacker, sport, 443, TCP_ACK, 40));
        v.push(inbound_tcp(
            t + 200_000,
            attacker,
            sport,
            443,
            TCP_PSH | TCP_ACK,
            200,
        ));
    }
    v
}

/// `count` failed logons from `ip`, `interval_ns` apart.
pub fn rdp_failures(ip: IpAddr, start_ns: u64, count: u32, interval_ns: u64) -> Vec<LogonFailure> {
    (0..u64::from(count))
        .map(|i| LogonFailure {
            ip,
            at_ns: start_ns + i * interval_ns,
        })
        .collect()
}

/// Everything at once: healthy traffic plus a SYN flood (`ATTACKER_SYN`), a UDP flood
/// (`ATTACKER_UDP`), an ICMP flood (`ATTACKER_ICMP`) and a port scan (`ATTACKER_SCAN`), all starting
/// 5 s in and lasting 20 s, plus an RDP brute force (`ATTACKER_RDP`).
pub fn mixed(
    seed: u64,
    start_ns: u64,
    secs: u32,
    clients: u32,
) -> (Vec<PacketMeta>, Vec<LogonFailure>) {
    let attack = start_ns + 5 * SECOND;
    let packets = merge(vec![
        normal_web(seed, start_ns, secs, clients),
        syn_flood(ATTACKER_SYN, attack, 20, 100),
        udp_flood(ATTACKER_UDP, attack, 20, 20_000, 1000),
        icmp_flood(ATTACKER_ICMP, attack, 20, 500),
        port_scan_vertical(ATTACKER_SCAN, attack, 1..=1000, SECOND / 50),
    ]);
    (packets, rdp_failures(ATTACKER_RDP, attack, 40, SECOND / 2))
}

// ---- lazy streams for the memory/throughput tests ----------------------------------------------

/// `total` SYNs at `pps`, every one from a different random address; never materialised.
pub fn spoofed_syn_iter(
    seed: u64,
    start_ns: u64,
    pps: u64,
    total: u64,
) -> impl Iterator<Item = PacketMeta> {
    let mut rng = Rng::new(seed);
    (0..total).map(move |i| {
        let src = IpAddr::V4(Ipv4Addr::from(rng.next_u32() | 0x0100_0000));
        inbound_tcp(
            at(start_ns, i, pps),
            src,
            1024 + (i % 60_000) as u16,
            443,
            TCP_SYN,
            60,
        )
    })
}

/// `total` UDP packets at `pps`, every one from a different random address.
pub fn spoofed_udp_iter(
    seed: u64,
    start_ns: u64,
    pps: u64,
    total: u64,
) -> impl Iterator<Item = PacketMeta> {
    let mut rng = Rng::new(seed);
    (0..total).map(move |i| {
        let src = IpAddr::V4(Ipv4Addr::from(rng.next_u32() | 0x0100_0000));
        packet(
            at(start_ns, i, pps),
            src,
            SERVER,
            1024 + (i % 60_000) as u16,
            27_015,
            Protocol::Udp,
            0,
            100,
            Direction::Inbound,
        )
    })
}

/// `total` packets of ordinary client traffic at `pps` over a pool of 100 000 clients
/// (handshakes completing, data ACKs, the odd DNS reply); never materialised.
pub fn legit_iter(
    seed: u64,
    start_ns: u64,
    pps: u64,
    total: u64,
) -> impl Iterator<Item = PacketMeta> {
    let mut rng = Rng::new(seed);
    (0..total).map(move |i| {
        let ip = client_ip(rng.below(100_000) as u32);
        let t = at(start_ns, i, pps);
        let sport = 49_152 + rng.below(16_000) as u16;
        match rng.below(20) {
            0 => inbound_tcp(t, ip, sport, 443, TCP_SYN, 52),
            1..=3 => {
                // Replies from a pool of 1000 resolvers, each a modest rate.
                let resolver = client_ip(2_000_000 + rng.below(1_000) as u32);
                packet(
                    t,
                    resolver,
                    SERVER,
                    53,
                    sport,
                    Protocol::Udp,
                    0,
                    100,
                    Direction::Inbound,
                )
            }
            _ => inbound_tcp(t, ip, sport, 443, TCP_ACK, 40),
        }
    })
}

/// Interleave two timestamp-ordered streams, keeping the result ordered.
pub fn interleave(
    a: impl Iterator<Item = PacketMeta>,
    b: impl Iterator<Item = PacketMeta>,
) -> impl Iterator<Item = PacketMeta> {
    let mut a = a.peekable();
    let mut b = b.peekable();
    std::iter::from_fn(move || match (a.peek(), b.peek()) {
        (Some(x), Some(y)) => {
            if x.timestamp_ns <= y.timestamp_ns {
                a.next()
            } else {
                b.next()
            }
        }
        (Some(_), None) => a.next(),
        (None, Some(_)) => b.next(),
        (None, None) => None,
    })
}

// ---- driver ------------------------------------------------------------------------------------

/// Drive `engine` through `packets` (ordered by timestamp) and `logons` (ordered), calling `tick` at
/// every whole second from the first boundary after `start_ns` up to and including `end_ns`
/// (rounded up to a boundary), like the real once-per-second loop. `after_tick` sees the engine and
/// the alerts of each tick. Returns all alerts in emission order.
pub fn replay_with(
    engine: &mut Engine,
    packets: impl IntoIterator<Item = PacketMeta>,
    logons: &[LogonFailure],
    start_ns: u64,
    end_ns: u64,
    mut after_tick: impl FnMut(&Engine, &[Alert]),
) -> Vec<Alert> {
    let mut packets = packets.into_iter().peekable();
    let mut next_logon = 0usize;
    let mut alerts = Vec::new();
    let mut boundary = (start_ns / SECOND + 1) * SECOND;
    loop {
        while let Some(p) = packets.next_if(|p| p.timestamp_ns < boundary) {
            engine.ingest(&p);
        }
        while let Some(l) = logons.get(next_logon).filter(|l| l.at_ns < boundary) {
            engine.observe_logon_failure(l.ip, l.at_ns);
            next_logon += 1;
        }
        let tick = engine.tick(boundary);
        after_tick(engine, &tick);
        alerts.extend(tick);
        if boundary >= end_ns {
            break;
        }
        boundary += SECOND;
    }
    alerts
}

/// [`replay_with`] without a callback.
pub fn replay(
    engine: &mut Engine,
    packets: impl IntoIterator<Item = PacketMeta>,
    logons: &[LogonFailure],
    start_ns: u64,
    end_ns: u64,
) -> Vec<Alert> {
    replay_with(engine, packets, logons, start_ns, end_ns, |_, _| {})
}

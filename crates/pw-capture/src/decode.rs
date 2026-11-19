// SPDX-License-Identifier: GPL-3.0-or-later
//! Frame to [`PacketMeta`]. Nothing here allocates per packet: etherparse hands back borrowed slices and
//! the result is a `Copy` struct. Truncated captures (snaplen 128) decode as far as they go; garbage never
//! panics, it is reported as a [`DecodeError`] for the pipeline to count.
//!
//! Choices worth knowing:
//! * `len` is the length the IP header declares (IPv4 `total_length`, IPv6 `payload_length + 40`), not the
//!   captured length, so a 128-byte snaplen does not distort byte rates. When the header's length is
//!   unusable (zero or shorter than the header, as with large-send offload on outbound packets) the number
//!   of captured IP bytes is used instead.
//! * Packets that are IP fragments carry no reliable transport header, so their ports and TCP flags are 0;
//!   the protocol still comes from the IP header (the next header after any IPv6 extension headers).
//! * ICMP and ICMPv6 are both [`Protocol::Icmp`]; every other protocol is [`Protocol::Other`].
//! * IPv4-mapped IPv6 addresses are reported as plain IPv4.
//! * `direction` is `Outbound` when the source is one of this machine's addresses, otherwise `Inbound`.

use std::net::IpAddr;

use etherparse::{LaxNetSlice, LaxSlicedPacket};
use pw_core::{Direction, PacketMeta, Protocol};

use crate::backend::LinkType;

const IPV4_MIN: usize = 20;
const IPV6_HEADER: usize = 40;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;

/// Why a frame produced no [`PacketMeta`]. `Copy` so counting it costs nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodeError {
    /// Too short to hold the headers it claims.
    Truncated,
    /// A well-formed frame that is not IP (ARP, LLDP, ...).
    NotIp,
    /// Looks like IP but the headers are inconsistent.
    Malformed,
}

/// This machine's addresses, to label packets inbound or outbound. A handful of entries: a linear scan.
#[derive(Debug, Clone, Default)]
pub struct LocalAddrs(Box<[IpAddr]>);

impl LocalAddrs {
    pub fn new(addrs: &[IpAddr]) -> Self {
        Self(addrs.iter().map(|a| a.to_canonical()).collect())
    }

    pub fn is_local(&self, addr: IpAddr) -> bool {
        self.0.contains(&addr)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Decodes one frame according to its link type.
pub fn decode_frame(
    link: LinkType,
    data: &[u8],
    timestamp_ns: u64,
    local: &LocalAddrs,
) -> Result<PacketMeta, DecodeError> {
    match link {
        LinkType::Ethernet => decode_ethernet(data, timestamp_ns, local),
        LinkType::RawIp => decode_ip(data, timestamp_ns, local),
        LinkType::Null => match data.get(4..) {
            Some(ip) => decode_ip(ip, timestamp_ns, local),
            None => Err(DecodeError::Truncated),
        },
    }
}

/// Decodes an Ethernet II frame (VLAN tags are skipped).
pub fn decode_ethernet(
    data: &[u8],
    timestamp_ns: u64,
    local: &LocalAddrs,
) -> Result<PacketMeta, DecodeError> {
    let packet = LaxSlicedPacket::from_ethernet(data).map_err(|_| DecodeError::Truncated)?;
    from_sliced(&packet, timestamp_ns, local)
}

/// Decodes a bare IP packet, as delivered by raw sockets (no link header).
pub fn decode_ip(
    data: &[u8],
    timestamp_ns: u64,
    local: &LocalAddrs,
) -> Result<PacketMeta, DecodeError> {
    let Some(first) = data.first() else {
        return Err(DecodeError::Truncated);
    };
    match first >> 4 {
        4 if data.len() < IPV4_MIN => return Err(DecodeError::Truncated),
        6 if data.len() < IPV6_HEADER => return Err(DecodeError::Truncated),
        4 | 6 => {}
        _ => return Err(DecodeError::Malformed),
    }
    let packet = LaxSlicedPacket::from_ip(data).map_err(|_| DecodeError::Malformed)?;
    from_sliced(&packet, timestamp_ns, local)
}

fn from_sliced(
    packet: &LaxSlicedPacket<'_>,
    timestamp_ns: u64,
    local: &LocalAddrs,
) -> Result<PacketMeta, DecodeError> {
    let (src, dst, ip_number, fragmented, payload, declared_len, header_len) = match &packet.net {
        Some(LaxNetSlice::Ipv4(ip)) => {
            let header = ip.header();
            let p = ip.payload();
            (
                IpAddr::V4(header.source_addr()),
                IpAddr::V4(header.destination_addr()),
                p.ip_number.0,
                p.fragmented,
                p.payload,
                u32::from(header.total_len()),
                header.slice().len(),
            )
        }
        Some(LaxNetSlice::Ipv6(ip)) => {
            let header = ip.header();
            let p = ip.payload();
            let declared = match header.payload_length() {
                0 => 0,
                n => u32::from(n) + IPV6_HEADER as u32,
            };
            (
                IpAddr::V6(header.source_addr()),
                IpAddr::V6(header.destination_addr()),
                p.ip_number.0,
                p.fragmented,
                p.payload,
                declared,
                IPV6_HEADER,
            )
        }
        Some(LaxNetSlice::Arp(_)) => return Err(DecodeError::NotIp),
        None => {
            return Err(if packet.stop_err.is_some() {
                DecodeError::Malformed
            } else {
                DecodeError::NotIp
            })
        }
    };

    // Bytes of IP packet actually present: everything from the IP header on. Approximated from the
    // payload slice and the header lengths (extension headers make this a lower bound).
    let captured_ip_len = (header_len + payload.len()) as u32;
    let len = if declared_len as usize >= header_len {
        declared_len
    } else {
        captured_ip_len
    };

    let src = src.to_canonical();
    let dst = dst.to_canonical();

    let (proto, src_port, dst_port, tcp_flags) = match ip_number {
        PROTO_TCP => {
            let (s, d, flags) = if fragmented {
                (0, 0, 0)
            } else {
                tcp_fields(payload)
            };
            (Protocol::Tcp, s, d, flags)
        }
        PROTO_UDP => {
            let (s, d) = if fragmented { (0, 0) } else { ports(payload) };
            (Protocol::Udp, s, d, 0)
        }
        PROTO_ICMP | PROTO_ICMPV6 => (Protocol::Icmp, 0, 0, 0),
        other => (Protocol::Other(other), 0, 0, 0),
    };

    let direction = if local.is_local(src) {
        Direction::Outbound
    } else {
        Direction::Inbound
    };

    Ok(PacketMeta {
        timestamp_ns,
        src,
        dst,
        src_port,
        dst_port,
        proto,
        tcp_flags,
        len,
        direction,
    })
}

fn ports(transport: &[u8]) -> (u16, u16) {
    match transport {
        [a, b, c, d, ..] => (u16::from_be_bytes([*a, *b]), u16::from_be_bytes([*c, *d])),
        _ => (0, 0),
    }
}

fn tcp_fields(transport: &[u8]) -> (u16, u16, u8) {
    let (src, dst) = ports(transport);
    // The flag byte is at offset 13 of the TCP header.
    let flags = transport.get(13).copied().unwrap_or(0);
    (src, dst, flags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use pw_core::{TCP_ACK, TCP_SYN};

    fn local() -> LocalAddrs {
        LocalAddrs::new(&["10.0.0.5".parse().unwrap(), "2001:db8::5".parse().unwrap()])
    }

    fn eth_tcp_syn() -> Vec<u8> {
        let b = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
            .ipv4([203, 0, 113, 9], [10, 0, 0, 5], 64)
            .tcp(50000, 3389, 1000, 8192)
            .syn();
        let mut out = Vec::new();
        b.write(&mut out, &[0u8; 20]).unwrap();
        out
    }

    fn ip_udp(src: [u8; 4], dst: [u8; 4], payload: usize) -> Vec<u8> {
        let b = PacketBuilder::ipv4(src, dst, 64).udp(5353, 53);
        let mut out = Vec::new();
        b.write(&mut out, &vec![7u8; payload]).unwrap();
        out
    }

    #[test]
    fn decodes_ethernet_ipv4_tcp_syn() {
        let frame = eth_tcp_syn();
        let m = decode_ethernet(&frame, 42, &local()).unwrap();
        assert_eq!(m.timestamp_ns, 42);
        assert_eq!(m.src, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert_eq!(m.dst, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!((m.src_port, m.dst_port), (50000, 3389));
        assert_eq!(m.proto, Protocol::Tcp);
        assert!(m.is_syn_only());
        assert_eq!(m.tcp_flags & (TCP_SYN | TCP_ACK), TCP_SYN);
        assert_eq!(m.len, 20 + 20 + 20); // IP + TCP + payload, no Ethernet header
        assert_eq!(m.direction, Direction::Inbound);
    }

    #[test]
    fn direction_follows_the_source_address() {
        let out = ip_udp([10, 0, 0, 5], [8, 8, 8, 8], 10);
        assert_eq!(
            decode_ip(&out, 0, &local()).unwrap().direction,
            Direction::Outbound
        );
        let inb = ip_udp([8, 8, 8, 8], [10, 0, 0, 5], 10);
        assert_eq!(
            decode_ip(&inb, 0, &local()).unwrap().direction,
            Direction::Inbound
        );
        // Unknown local addresses: everything counts as inbound.
        assert_eq!(
            decode_ip(&out, 0, &LocalAddrs::default())
                .unwrap()
                .direction,
            Direction::Inbound
        );
    }

    #[test]
    fn decodes_raw_ipv4_udp() {
        let pkt = ip_udp([198, 51, 100, 7], [10, 0, 0, 5], 100);
        let m = decode_ip(&pkt, 1, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Udp);
        assert_eq!((m.src_port, m.dst_port), (5353, 53));
        assert_eq!(m.len, 20 + 8 + 100);
        assert_eq!(m.tcp_flags, 0);
    }

    #[test]
    fn len_comes_from_the_ip_header_not_from_the_snaplen() {
        let pkt = ip_udp([198, 51, 100, 7], [10, 0, 0, 5], 1000);
        let m = decode_ip(&pkt[..128], 1, &local()).unwrap();
        assert_eq!(m.len, 20 + 8 + 1000);
        assert_eq!((m.src_port, m.dst_port), (5353, 53));
    }

    #[test]
    fn zero_total_length_falls_back_to_captured_length() {
        let mut pkt = ip_udp([198, 51, 100, 7], [10, 0, 0, 5], 100);
        pkt[2] = 0;
        pkt[3] = 0; // large-send offload leaves total_length at 0
        let m = decode_ip(&pkt, 1, &local()).unwrap();
        assert_eq!(m.len, pkt.len() as u32);
        assert_eq!((m.src_port, m.dst_port), (5353, 53));
    }

    #[test]
    fn decodes_icmp_v4_and_v6() {
        let b = PacketBuilder::ipv4([1, 1, 1, 1], [10, 0, 0, 5], 64).icmpv4_echo_request(1, 1);
        let mut pkt = Vec::new();
        b.write(&mut pkt, &[0u8; 8]).unwrap();
        let m = decode_ip(&pkt, 0, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Icmp);
        assert_eq!((m.src_port, m.dst_port), (0, 0));

        let b = PacketBuilder::ipv6(
            [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
            [0; 16],
            64,
        )
        .icmpv6_echo_request(1, 1);
        let mut pkt = Vec::new();
        b.write(&mut pkt, &[0u8; 8]).unwrap();
        let m = decode_ip(&pkt, 0, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Icmp);
        assert_eq!(m.len, 40 + 8 + 8);
    }

    #[test]
    fn decodes_ipv6_tcp() {
        let src = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let dst = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv6(src, dst, 64)
            .tcp(40000, 443, 1, 100)
            .syn()
            .ack(5);
        let mut frame = Vec::new();
        b.write(&mut frame, &[]).unwrap();
        let m = decode_ethernet(&frame, 0, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Tcp);
        assert_eq!((m.src_port, m.dst_port), (40000, 443));
        assert!(m.is_syn_ack());
        assert_eq!(m.direction, Direction::Inbound);
        assert_eq!(m.len, 40 + 20);
        assert_eq!(m.dst, "2001:db8::5".parse::<IpAddr>().unwrap());
    }

    fn ipv6_with_ext_headers(next_after_ext: u8, transport: &[u8]) -> Vec<u8> {
        // IPv6 | hop-by-hop (8 bytes) | destination options (8 bytes) | transport
        let mut p = vec![0x60, 0, 0, 0];
        let payload_len = (16 + transport.len()) as u16;
        p.extend_from_slice(&payload_len.to_be_bytes());
        p.push(0); // next header: hop-by-hop
        p.push(64);
        p.extend_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        p.extend_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
        p.extend_from_slice(&[60, 0, 1, 4, 0, 0, 0, 0]); // hop-by-hop, next = destination options (60)
        p.extend_from_slice(&[next_after_ext, 0, 1, 4, 0, 0, 0, 0]); // destination options
        p.extend_from_slice(transport);
        p
    }

    #[test]
    fn walks_ipv6_extension_headers() {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = TCP_SYN;
        let pkt = ipv6_with_ext_headers(6, &tcp);
        let m = decode_ip(&pkt, 0, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Tcp);
        assert_eq!((m.src_port, m.dst_port), (1234, 80));
        assert!(m.is_syn_only());
        assert_eq!(m.len, 40 + 16 + 20);
    }

    #[test]
    fn ipv4_fragments_have_no_ports_but_keep_the_protocol() {
        let mut pkt = ip_udp([198, 51, 100, 7], [10, 0, 0, 5], 100);
        // Fragment offset 100 (in 8-byte units), no more-fragments flag.
        pkt[6] = 0;
        pkt[7] = 100;
        // Header checksum is not validated.
        let m = decode_ip(&pkt, 0, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Udp);
        assert_eq!((m.src_port, m.dst_port), (0, 0));
        assert_eq!(m.len, 20 + 8 + 100);

        // More-fragments set at offset 0: first fragment, also reported without ports.
        let mut first = ip_udp([198, 51, 100, 7], [10, 0, 0, 5], 100);
        first[6] = 0x20;
        let m = decode_ip(&first, 0, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Udp);
        assert_eq!((m.src_port, m.dst_port), (0, 0));
    }

    #[test]
    fn ipv6_fragment_header_keeps_the_inner_protocol() {
        // IPv6 | fragment header (next = UDP, offset 1) | 8 bytes
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&16u16.to_be_bytes());
        p.push(44);
        p.push(64);
        p.extend_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        p.extend_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
        p.extend_from_slice(&[17, 0, 0, 8, 0, 0, 0, 1]);
        p.extend_from_slice(&[9u8; 8]);
        let m = decode_ip(&p, 0, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Udp);
        assert_eq!((m.src_port, m.dst_port), (0, 0));
    }

    #[test]
    fn other_protocols_and_vlan_tags() {
        // IPv4 header (protocol 47, GRE) followed by 8 bytes.
        let mut gre = vec![
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 47, 0, 0, 10, 9, 9, 9, 10, 0, 0, 5,
        ];
        gre.extend_from_slice(&[0u8; 8]);
        let m = decode_ip(&gre, 0, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Other(47));

        // Ethernet with an 802.1Q tag in front of IPv4/UDP.
        let ip = ip_udp([198, 51, 100, 7], [10, 0, 0, 5], 10);
        let mut frame = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x81, 0x00, 0x00, 0x2a, 0x08, 0x00,
        ];
        frame.extend_from_slice(&ip);
        let m = decode_ethernet(&frame, 0, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Udp);
        assert_eq!((m.src_port, m.dst_port), (5353, 53));
    }

    #[test]
    fn non_ip_frames_are_reported() {
        // ARP request.
        let mut arp = vec![0xff; 6];
        arp.extend_from_slice(&[1, 2, 3, 4, 5, 6, 0x08, 0x06]);
        arp.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        arp.extend_from_slice(&[1, 2, 3, 4, 5, 6, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2]);
        assert_eq!(decode_ethernet(&arp, 0, &local()), Err(DecodeError::NotIp));
        // LLDP ether type.
        let mut lldp = vec![0x01, 0x80, 0xc2, 0, 0, 0xe, 1, 2, 3, 4, 5, 6, 0x88, 0xcc];
        lldp.extend_from_slice(&[0u8; 30]);
        assert_eq!(decode_ethernet(&lldp, 0, &local()), Err(DecodeError::NotIp));
    }

    #[test]
    fn null_link_skips_the_family_word() {
        let ip = ip_udp([198, 51, 100, 7], [10, 0, 0, 5], 10);
        let mut frame = vec![2, 0, 0, 0];
        frame.extend_from_slice(&ip);
        let m = decode_frame(LinkType::Null, &frame, 0, &local()).unwrap();
        assert_eq!(m.proto, Protocol::Udp);
        assert_eq!(
            decode_frame(LinkType::Null, &[2, 0], 0, &local()),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn every_truncation_of_valid_packets_is_handled() {
        let frames = [eth_tcp_syn(), {
            let b = PacketBuilder::ethernet2([1; 6], [2; 6])
                .ipv6(
                    [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
                    [0; 16],
                    64,
                )
                .udp(1, 2);
            let mut v = Vec::new();
            b.write(&mut v, &[1u8; 30]).unwrap();
            v
        }];
        for frame in &frames {
            for cut in 0..=frame.len() {
                let eth = decode_ethernet(&frame[..cut], 0, &local());
                if cut < 14 {
                    assert!(eth.is_err(), "cut {cut}");
                }
                if let Ok(m) = eth {
                    // Anything that decodes must still have a sane length.
                    assert!(m.len >= 20, "cut {cut}: {m:?}");
                }
                let _ = decode_ip(&frame[14.min(cut)..cut.max(14.min(cut))], 0, &local());
            }
        }
    }

    /// Deterministic xorshift, enough to throw varied garbage at the decoder.
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn garbage_never_panics() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut buf = [0u8; 200];
        let mut decoded = 0usize;
        for round in 0..20_000 {
            let len = (xorshift(&mut state) % 200) as usize;
            for b in &mut buf[..len] {
                *b = xorshift(&mut state) as u8;
            }
            // Bias half of the rounds towards plausible IP headers so the parsers go deeper.
            if round % 2 == 0 && len > 0 {
                buf[0] = if round % 4 == 0 { 0x45 } else { 0x60 };
            }
            let data = &buf[..len];
            for link in [LinkType::Ethernet, LinkType::RawIp, LinkType::Null] {
                if decode_frame(link, data, 0, &local()).is_ok() {
                    decoded += 1;
                }
            }
        }
        // Some random bytes are valid IP packets; the point is only that nothing panicked.
        assert!(decoded > 0);
    }

    #[test]
    fn rejects_wrong_ip_versions_and_empty_input() {
        assert_eq!(decode_ip(&[], 0, &local()), Err(DecodeError::Truncated));
        assert_eq!(decode_ip(&[0x45], 0, &local()), Err(DecodeError::Truncated));
        assert_eq!(
            decode_ip(&[0x65; 10], 0, &local()),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            decode_ip(&[0x15; 64], 0, &local()),
            Err(DecodeError::Malformed)
        );
        assert_eq!(
            decode_ethernet(&[], 0, &local()),
            Err(DecodeError::Truncated)
        );
        // IPv4 header with an IHL below 5.
        let mut bad = ip_udp([1, 1, 1, 1], [10, 0, 0, 5], 10);
        bad[0] = 0x41;
        assert!(decode_ip(&bad, 0, &local()).is_err());
    }
}

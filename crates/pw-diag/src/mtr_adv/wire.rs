// SPDX-License-Identifier: GPL-3.0-or-later
//! Reading the answers to UDP and TCP-SYN probes from captured frames.
//!
//! Pure and platform independent: [`parse_frame`] takes the bytes of one frame (Ethernet, raw IP
//! or BSD loopback framing, see `pw_capture::LinkType`) and returns the few things MTR cares
//! about:
//!
//! * an ICMP / ICMPv6 *time exceeded* or *destination unreachable* message, together with the
//!   start of the probe it quotes (protocol, destination, ports) so it can be matched to the
//!   probe that caused it;
//! * a TCP segment that is a SYN-ACK or an RST.
//!
//! Everything else (including fragments, IPv6 extension headers and truncated headers) yields
//! `None`. The parser never panics on malformed input and never allocates.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pw_capture::LinkType;

/// Protocol of the probe an ICMP error quotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireProto {
    /// UDP.
    Udp,
    /// TCP.
    Tcp,
}

/// What an ICMP error says about the quoted probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpErrorKind {
    /// TTL / hop limit exceeded in transit: the sender is a router on the path.
    TimeExceeded,
    /// Port unreachable: the sender is the destination and nothing listens on the port.
    PortUnreachable,
    /// Any other destination-unreachable code (net, host, administratively prohibited, ...).
    OtherUnreachable,
}

/// The beginning of the probe quoted inside an ICMP error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotedProbe {
    /// Transport protocol.
    pub proto: WireProto,
    /// Destination address of the quoted probe.
    pub dst: IpAddr,
    /// Source port of the quoted probe (the local port that identifies it).
    pub src_port: u16,
    /// Destination port of the quoted probe.
    pub dst_port: u16,
}

/// Kind of a TCP answer from the probed host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpReplyKind {
    /// SYN-ACK: the port is open.
    SynAck,
    /// RST: the host is up, the port is closed.
    Rst,
}

/// One recognised frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireEvent {
    /// ICMP / ICMPv6 time-exceeded or unreachable.
    IcmpError {
        /// Who sent the ICMP message.
        from: IpAddr,
        /// What it says.
        kind: IcmpErrorKind,
        /// The probe it is about.
        quoted: QuotedProbe,
    },
    /// A SYN-ACK or RST.
    TcpReply {
        /// Source address of the segment.
        from: IpAddr,
        /// Source port of the segment (the probed port).
        src_port: u16,
        /// Destination port of the segment (our local port).
        dst_port: u16,
        /// SYN-ACK or RST.
        kind: TcpReplyKind,
    },
}

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

struct IpPacket<'a> {
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    payload: &'a [u8],
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Strip the link header; `None` for frames that do not carry IP.
fn ip_bytes(link: LinkType, data: &[u8]) -> Option<&[u8]> {
    match link {
        LinkType::RawIp => Some(data),
        LinkType::Null => data.get(4..),
        LinkType::Ethernet => {
            let mut at = 12;
            let mut ethertype = be16(data, at)?;
            // One or two VLAN tags (802.1Q / 802.1ad).
            for _ in 0..2 {
                if ethertype == 0x8100 || ethertype == 0x88a8 {
                    at += 4;
                    ethertype = be16(data, at)?;
                }
            }
            if ethertype == 0x0800 || ethertype == 0x86dd {
                data.get(at + 2..)
            } else {
                None
            }
        }
    }
}

/// Parse an IPv4 / IPv6 header. The payload may be truncated (a quote inside an ICMP error always
/// is). Fragments other than the first, and IPv6 packets with extension headers, are refused.
fn parse_ip(b: &[u8]) -> Option<IpPacket<'_>> {
    match b.first()? >> 4 {
        4 => {
            let ihl = usize::from(b[0] & 0x0f) * 4;
            if ihl < 20 || b.len() < ihl {
                return None;
            }
            let frag_offset = be16(b, 6)? & 0x1fff;
            if frag_offset != 0 {
                return None;
            }
            let src: [u8; 4] = b.get(12..16)?.try_into().ok()?;
            let dst: [u8; 4] = b.get(16..20)?.try_into().ok()?;
            Some(IpPacket {
                src: IpAddr::V4(Ipv4Addr::from(src)),
                dst: IpAddr::V4(Ipv4Addr::from(dst)),
                proto: *b.get(9)?,
                payload: b.get(ihl..)?,
            })
        }
        6 => {
            let src: [u8; 16] = b.get(8..24)?.try_into().ok()?;
            let dst: [u8; 16] = b.get(24..40)?.try_into().ok()?;
            Some(IpPacket {
                src: IpAddr::V6(Ipv6Addr::from(src)),
                dst: IpAddr::V6(Ipv6Addr::from(dst)),
                proto: *b.get(6)?,
                payload: b.get(40..)?,
            })
        }
        _ => None,
    }
}

fn parse_quoted(b: &[u8]) -> Option<QuotedProbe> {
    let ip = parse_ip(b)?;
    let proto = match ip.proto {
        PROTO_UDP => WireProto::Udp,
        PROTO_TCP => WireProto::Tcp,
        _ => return None,
    };
    Some(QuotedProbe {
        proto,
        dst: ip.dst,
        src_port: be16(ip.payload, 0)?,
        dst_port: be16(ip.payload, 2)?,
    })
}

fn parse_icmp(ip: &IpPacket<'_>) -> Option<WireEvent> {
    let kind = match (ip.src, ip.proto) {
        (IpAddr::V4(_), PROTO_ICMP) => match (*ip.payload.first()?, *ip.payload.get(1)?) {
            (11, _) => IcmpErrorKind::TimeExceeded,
            (3, 3) => IcmpErrorKind::PortUnreachable,
            (3, _) => IcmpErrorKind::OtherUnreachable,
            _ => return None,
        },
        (IpAddr::V6(_), PROTO_ICMPV6) => match (*ip.payload.first()?, *ip.payload.get(1)?) {
            (3, _) => IcmpErrorKind::TimeExceeded,
            (1, 4) => IcmpErrorKind::PortUnreachable,
            (1, _) => IcmpErrorKind::OtherUnreachable,
            _ => return None,
        },
        _ => return None,
    };
    let quoted = parse_quoted(ip.payload.get(8..)?)?;
    Some(WireEvent::IcmpError {
        from: ip.src,
        kind,
        quoted,
    })
}

fn parse_tcp(ip: &IpPacket<'_>) -> Option<WireEvent> {
    let t = ip.payload;
    let flags = *t.get(13)?;
    let kind = if flags & 0x04 != 0 {
        TcpReplyKind::Rst
    } else if flags & 0x12 == 0x12 {
        TcpReplyKind::SynAck
    } else {
        return None;
    };
    Some(WireEvent::TcpReply {
        from: ip.src,
        src_port: be16(t, 0)?,
        dst_port: be16(t, 2)?,
        kind,
    })
}

/// Recognise one captured frame, see the module documentation.
pub fn parse_frame(link: LinkType, data: &[u8]) -> Option<WireEvent> {
    let ip = parse_ip(ip_bytes(link, data)?)?;
    match ip.proto {
        PROTO_ICMP | PROTO_ICMPV6 => parse_icmp(&ip),
        PROTO_TCP => parse_tcp(&ip),
        _ => None,
    }
}

/// Byte-level packet builders shared by the tests of this crate.
#[cfg(test)]
pub(crate) mod testpkt {
    use std::net::IpAddr;

    use super::{WireProto, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};

    fn ip_header(src: IpAddr, dst: IpAddr, proto: u8, payload_len: usize) -> Vec<u8> {
        let mut h = Vec::new();
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                h.extend([0x45, 0]);
                h.extend(u16::try_from(20 + payload_len).unwrap().to_be_bytes());
                h.extend([0, 0, 0, 0, 64, proto, 0, 0]);
                h.extend(s.octets());
                h.extend(d.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                h.extend([0x60, 0, 0, 0]);
                h.extend(u16::try_from(payload_len).unwrap().to_be_bytes());
                h.extend([proto, 64]);
                h.extend(s.octets());
                h.extend(d.octets());
            }
            _ => panic!("mixed address families"),
        }
        h
    }

    /// The probe as it leaves this machine, truncated like an ICMP quote (headers + 8 bytes).
    pub(crate) fn quoted_probe(
        local: IpAddr,
        target: IpAddr,
        proto: WireProto,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let (p, mut l4) = match proto {
            WireProto::Udp => (PROTO_UDP, Vec::new()),
            WireProto::Tcp => (PROTO_TCP, Vec::new()),
        };
        l4.extend(src_port.to_be_bytes());
        l4.extend(dst_port.to_be_bytes());
        l4.extend([0, 0, 0, 0]); // UDP length + checksum / TCP sequence number
        let mut pkt = ip_header(local, target, p, l4.len());
        pkt.extend(l4);
        pkt
    }

    /// An ICMP / ICMPv6 error from `from` to `local` quoting `quoted`.
    pub(crate) fn icmp_error(
        from: IpAddr,
        local: IpAddr,
        icmp_type: u8,
        code: u8,
        quoted: &[u8],
    ) -> Vec<u8> {
        let mut body = vec![icmp_type, code, 0, 0, 0, 0, 0, 0];
        body.extend(quoted);
        let proto = if from.is_ipv4() {
            PROTO_ICMP
        } else {
            PROTO_ICMPV6
        };
        let mut pkt = ip_header(from, local, proto, body.len());
        pkt.extend(body);
        pkt
    }

    /// A TCP segment (no payload) with the given flag byte.
    pub(crate) fn tcp_segment(
        from: IpAddr,
        to: IpAddr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut seg = Vec::new();
        seg.extend(src_port.to_be_bytes());
        seg.extend(dst_port.to_be_bytes());
        seg.extend([0; 8]); // seq + ack
        seg.extend([0x50, flags, 0, 0, 0, 0, 0, 0]);
        let mut pkt = ip_header(from, to, PROTO_TCP, seg.len());
        pkt.extend(seg);
        pkt
    }

    /// Put an IP packet into an Ethernet frame.
    pub(crate) fn ethernet(ip: &[u8], vlan: bool) -> Vec<u8> {
        let mut f = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let ethertype: [u8; 2] = if ip[0] >> 4 == 4 {
            [0x08, 0x00]
        } else {
            [0x86, 0xdd]
        };
        if vlan {
            f.extend([0x81, 0x00, 0x00, 0x05]);
        }
        f.extend(ethertype);
        f.extend(ip);
        f
    }
}

#[cfg(test)]
mod tests {
    use super::testpkt::*;
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const FLAG_SYN: u8 = 0x02;
    const FLAG_RST: u8 = 0x04;
    const FLAG_ACK: u8 = 0x10;

    #[test]
    fn time_exceeded_v4_quotes_the_udp_probe() {
        let local = ip("192.168.1.5");
        let target = ip("1.1.1.1");
        let q = quoted_probe(local, target, WireProto::Udp, 50_000, 33434);
        let pkt = icmp_error(ip("10.0.0.1"), local, 11, 0, &q);
        let want = WireEvent::IcmpError {
            from: ip("10.0.0.1"),
            kind: IcmpErrorKind::TimeExceeded,
            quoted: QuotedProbe {
                proto: WireProto::Udp,
                dst: target,
                src_port: 50_000,
                dst_port: 33434,
            },
        };
        assert_eq!(parse_frame(LinkType::RawIp, &pkt), Some(want));
        // The same packet in an Ethernet frame, with and without a VLAN tag, and BSD loopback.
        assert_eq!(
            parse_frame(LinkType::Ethernet, &ethernet(&pkt, false)),
            Some(want)
        );
        assert_eq!(
            parse_frame(LinkType::Ethernet, &ethernet(&pkt, true)),
            Some(want)
        );
        let mut null = vec![2, 0, 0, 0];
        null.extend(&pkt);
        assert_eq!(parse_frame(LinkType::Null, &null), Some(want));
    }

    #[test]
    fn port_unreachable_and_other_unreachable_codes() {
        let local = ip("192.168.1.5");
        let target = ip("1.1.1.1");
        let q = quoted_probe(local, target, WireProto::Udp, 50_001, 33434);
        for (code, kind) in [
            (3, IcmpErrorKind::PortUnreachable),
            (1, IcmpErrorKind::OtherUnreachable),
            (13, IcmpErrorKind::OtherUnreachable),
        ] {
            let pkt = icmp_error(target, local, 3, code, &q);
            match parse_frame(LinkType::RawIp, &pkt) {
                Some(WireEvent::IcmpError { from, kind: k, .. }) => {
                    assert_eq!((from, k), (target, kind), "code {code}");
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn ipv6_time_exceeded_and_port_unreachable() {
        let local = ip("2001:db8::5");
        let target = ip("2606:4700:4700::1111");
        let q = quoted_probe(local, target, WireProto::Tcp, 51_000, 443);
        let te = icmp_error(ip("2001:db8::1"), local, 3, 0, &q);
        assert_eq!(
            parse_frame(LinkType::RawIp, &te),
            Some(WireEvent::IcmpError {
                from: ip("2001:db8::1"),
                kind: IcmpErrorKind::TimeExceeded,
                quoted: QuotedProbe {
                    proto: WireProto::Tcp,
                    dst: target,
                    src_port: 51_000,
                    dst_port: 443
                },
            })
        );
        let pu = icmp_error(target, local, 1, 4, &q);
        assert!(matches!(
            parse_frame(LinkType::Ethernet, &ethernet(&pu, false)),
            Some(WireEvent::IcmpError {
                kind: IcmpErrorKind::PortUnreachable,
                ..
            })
        ));
        // ICMPv6 type 128 (echo request) is not an error message.
        let echo = icmp_error(target, local, 128, 0, &q);
        assert_eq!(parse_frame(LinkType::RawIp, &echo), None);
    }

    #[test]
    fn tcp_syn_ack_and_rst_are_recognised() {
        let local = ip("192.168.1.5");
        let target = ip("1.1.1.1");
        let synack = tcp_segment(target, local, 443, 50_002, FLAG_SYN | FLAG_ACK);
        assert_eq!(
            parse_frame(LinkType::RawIp, &synack),
            Some(WireEvent::TcpReply {
                from: target,
                src_port: 443,
                dst_port: 50_002,
                kind: TcpReplyKind::SynAck
            })
        );
        for flags in [FLAG_RST, FLAG_RST | FLAG_ACK] {
            let rst = tcp_segment(target, local, 443, 50_002, flags);
            assert!(matches!(
                parse_frame(LinkType::RawIp, &rst),
                Some(WireEvent::TcpReply {
                    kind: TcpReplyKind::Rst,
                    ..
                })
            ));
        }
        // Plain ACK, plain SYN and data-only segments are not answers to a SYN.
        for flags in [FLAG_ACK, FLAG_SYN, 0x18] {
            let seg = tcp_segment(target, local, 443, 50_002, flags);
            assert_eq!(parse_frame(LinkType::RawIp, &seg), None, "flags {flags:#x}");
        }
        let v6 = tcp_segment(
            ip("2606:4700:4700::1111"),
            ip("2001:db8::5"),
            80,
            50_003,
            FLAG_SYN | FLAG_ACK,
        );
        assert!(matches!(
            parse_frame(LinkType::RawIp, &v6),
            Some(WireEvent::TcpReply {
                kind: TcpReplyKind::SynAck,
                ..
            })
        ));
    }

    #[test]
    fn garbage_never_panics_or_matches() {
        assert_eq!(parse_frame(LinkType::RawIp, &[]), None);
        assert_eq!(parse_frame(LinkType::Ethernet, &[0; 13]), None);
        assert_eq!(parse_frame(LinkType::Null, &[2, 0, 0]), None);
        assert_eq!(parse_frame(LinkType::RawIp, &[0x45]), None);
        assert_eq!(parse_frame(LinkType::RawIp, &[0x15; 40]), None);
        // An ARP frame is not IP.
        let mut arp = vec![0; 12];
        arp.extend([0x08, 0x06]);
        arp.extend([0; 28]);
        assert_eq!(parse_frame(LinkType::Ethernet, &arp), None);
        // Every prefix of a valid packet is handled.
        let local = ip("192.168.1.5");
        let target = ip("1.1.1.1");
        let q = quoted_probe(local, target, WireProto::Udp, 50_000, 33434);
        let pkt = icmp_error(ip("10.0.0.1"), local, 11, 0, &q);
        for n in 0..pkt.len() {
            let _ = parse_frame(LinkType::RawIp, &pkt[..n]);
        }
        // Echo reply (type 0) and echo request are not errors.
        assert_eq!(
            parse_frame(LinkType::RawIp, &icmp_error(target, local, 0, 0, &q)),
            None
        );
    }

    #[test]
    fn fragments_are_ignored() {
        let local = ip("192.168.1.5");
        let target = ip("1.1.1.1");
        let mut seg = tcp_segment(target, local, 443, 50_002, FLAG_SYN | FLAG_ACK);
        seg[6] = 0x00;
        seg[7] = 0x08; // fragment offset 8
        assert_eq!(parse_frame(LinkType::RawIp, &seg), None);
    }
}

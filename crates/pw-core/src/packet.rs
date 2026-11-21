// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
use std::net::IpAddr;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    /// ICMP or ICMPv6.
    Icmp,
    Other(u8),
}

/// Relative to this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// What the decoder extracts from one packet and everything downstream (stats, detectors) consumes.
/// Small and `Copy` on purpose: the capture hot path must not allocate per packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    /// Nanoseconds since the Unix epoch (capture clock).
    pub timestamp_ns: u64,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// 0 for protocols without ports.
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: Protocol,
    /// TCP flag bits (`TCP_SYN`, ...); 0 for other protocols.
    pub tcp_flags: u8,
    /// Length of the IP packet in bytes.
    pub len: u32,
    pub direction: Direction,
}

impl PacketMeta {
    pub fn is_syn_only(&self) -> bool {
        self.proto == Protocol::Tcp && self.tcp_flags & (TCP_SYN | TCP_ACK) == TCP_SYN
    }

    pub fn is_syn_ack(&self) -> bool {
        self.proto == Protocol::Tcp && self.tcp_flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(flags: u8) -> PacketMeta {
        PacketMeta {
            timestamp_ns: 0,
            src: "203.0.113.9".parse().unwrap(),
            dst: "10.0.0.5".parse().unwrap(),
            src_port: 40000,
            dst_port: 443,
            proto: Protocol::Tcp,
            tcp_flags: flags,
            len: 60,
            direction: Direction::Inbound,
        }
    }

    #[test]
    fn syn_helpers_distinguish_syn_from_syn_ack() {
        assert!(tcp(TCP_SYN).is_syn_only());
        assert!(!tcp(TCP_SYN | TCP_ACK).is_syn_only());
        assert!(tcp(TCP_SYN | TCP_ACK).is_syn_ack());
        assert!(!tcp(TCP_ACK).is_syn_only());
    }
}

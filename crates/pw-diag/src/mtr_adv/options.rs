// SPDX-License-Identifier: GPL-3.0-or-later
//! Options of the advanced MTR and their clamps.

use std::net::IpAddr;
use std::time::Duration;

use super::{MtrError, ProbeMode};
use crate::echo::{clamp_timeout, DEFAULT_PAYLOAD, MAX_PAYLOAD};
use crate::error::DiagError;
use crate::mtr::{MtrOptions, MAX_CYCLES, MAX_HOPS_LIMIT, MAX_PARALLELISM};
use crate::ping::MIN_INTERVAL;

/// Destination port of UDP probes unless configured (the classic traceroute base port: nothing
/// legitimate listens there, so the destination answers port-unreachable).
pub const DEFAULT_UDP_PORT: u16 = 33434;
/// Port suggested for TCP-SYN probes (HTTPS: the port most firewalls let through).
pub const DEFAULT_TCP_PORT: u16 = 443;
/// Largest UDP / ICMP payload that fits one IPv6 Ethernet frame (1500 - 40 - 8).
pub const MAX_PAYLOAD_V6: u16 = 1452;
/// A TCP SYN carries no payload: `packet_size` is ignored (forced to this) in TCP-SYN mode.
pub const TCP_SYN_PAYLOAD: u16 = 0;

/// Parameters of [`crate::mtr_adv::mtr_with`]. Out-of-range values are clamped, see
/// [`AdvMtrOptions::normalized_for`]; only a zero port is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvMtrOptions {
    /// Probe kind (default ICMP).
    pub mode: ProbeMode,
    /// Number of cycles (default 10, at most [`MAX_CYCLES`]).
    pub cycles: u32,
    /// Highest TTL / hop limit probed (default 30, `1..=`[`MAX_HOPS_LIMIT`]).
    pub max_hops: u8,
    /// Per-probe timeout (default 1 s, `1 ms..=10 s`).
    pub timeout: Duration,
    /// Payload size in bytes (default 32; at most 1472, or 1452 for UDP / IPv6; ignored for
    /// TCP SYN).
    pub packet_size: u16,
    /// Time between the starts of two cycles (default 1 s, at least 200 ms).
    pub interval: Duration,
    /// TTLs probed at the same time (default 8, `1..=`[`MAX_PARALLELISM`]).
    pub parallelism: u8,
    /// Destination port of UDP probes (default [`DEFAULT_UDP_PORT`]; must not be 0).
    pub udp_port: u16,
    /// Look up host names of hops (default `true`); `false` never touches DNS.
    pub resolve_names: bool,
}

impl Default for AdvMtrOptions {
    fn default() -> Self {
        Self {
            mode: ProbeMode::Icmp,
            cycles: 10,
            max_hops: 30,
            timeout: Duration::from_secs(1),
            packet_size: DEFAULT_PAYLOAD,
            interval: Duration::from_secs(1),
            parallelism: 8,
            udp_port: DEFAULT_UDP_PORT,
            resolve_names: true,
        }
    }
}

impl From<&MtrOptions> for AdvMtrOptions {
    /// The ICMP options of the simple MTR as advanced options (mode ICMP, names resolved).
    fn from(o: &MtrOptions) -> Self {
        Self {
            cycles: o.cycles,
            max_hops: o.max_hops,
            timeout: o.timeout,
            packet_size: o.packet_size,
            interval: o.interval,
            parallelism: o.parallelism,
            ..Self::default()
        }
    }
}

impl AdvMtrOptions {
    /// The options with every numeric field forced into its supported range for a trace to
    /// `target`:
    ///
    /// * the common limits are the simple MTR's (`cycles <= 1000`, `max_hops <= 64`, timeout
    ///   1 ms..10 s, interval >= 200 ms, parallelism <= 16, payload <= 1472);
    /// * UDP towards an IPv6 target is further limited to [`MAX_PAYLOAD_V6`] so a probe never
    ///   fragments; TCP SYN uses [`TCP_SYN_PAYLOAD`].
    ///
    /// Zero ports are *not* silently fixed, see [`AdvMtrOptions::validate`].
    pub fn normalized_for(&self, target: IpAddr) -> AdvMtrOptions {
        let mut packet_size = self.packet_size.min(MAX_PAYLOAD);
        match self.mode {
            ProbeMode::Icmp => {}
            ProbeMode::Udp => {
                if target.is_ipv6() {
                    packet_size = packet_size.min(MAX_PAYLOAD_V6);
                }
            }
            ProbeMode::TcpSyn { .. } => packet_size = TCP_SYN_PAYLOAD,
        }
        AdvMtrOptions {
            mode: self.mode,
            cycles: self.cycles.clamp(1, MAX_CYCLES),
            max_hops: self.max_hops.clamp(1, MAX_HOPS_LIMIT),
            timeout: clamp_timeout(self.timeout),
            packet_size,
            interval: self.interval.max(MIN_INTERVAL),
            parallelism: self.parallelism.clamp(1, MAX_PARALLELISM),
            udp_port: self.udp_port,
            resolve_names: self.resolve_names,
        }
    }

    /// Refuse what must never be sent: destination port 0.
    pub fn validate(&self) -> Result<(), MtrError> {
        let port_zero = match self.mode {
            ProbeMode::Icmp => false,
            ProbeMode::Udp => self.udp_port == 0,
            ProbeMode::TcpSyn { port } => port == 0,
        };
        if port_zero {
            return Err(DiagError::InvalidInput("port 0 cannot be probed".to_owned()).into());
        }
        Ok(())
    }

    /// Destination port of the probes: the UDP / TCP port, or `0` for ICMP.
    pub fn probe_port(&self) -> u16 {
        match self.mode {
            ProbeMode::Icmp => 0,
            ProbeMode::Udp => self.udp_port,
            ProbeMode::TcpSyn { port } => port,
        }
    }
}

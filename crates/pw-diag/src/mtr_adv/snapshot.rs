// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The table of an advanced MTR: the simple [`MtrSnapshot`] plus mode, ASN / country and how the
//! destination answered. The simple types are left untouched so nothing downstream changes;
//! everything new is an `Option` / defaulted field here.

use std::net::IpAddr;

use super::{HopInfo, ProbeMode, ReachKind};
use crate::mtr::{HopSnapshot, MtrSnapshot};

/// One row of the table: the simple hop plus what is known about its network.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvHop {
    /// Addresses, loss and latency statistics (identical to the simple MTR's row).
    pub hop: HopSnapshot,
    /// ASN / country of `hop.addr`; `None` for silent hops, private / reserved addresses and
    /// addresses without data.
    pub info: Option<HopInfo>,
}

impl AdvHop {
    /// `AS13335`, when the ASN is known.
    pub fn asn_label(&self) -> Option<String> {
        self.info
            .as_ref()
            .and_then(|i| i.asn)
            .map(|n| format!("AS{n}"))
    }
}

/// The whole table after some number of cycles.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvMtrSnapshot {
    /// How the probes were sent.
    pub mode: ProbeMode,
    /// Destination port of the probes (`0` for ICMP).
    pub port: u16,
    /// The destination traced.
    pub target: IpAddr,
    /// Cycles completed so far.
    pub cycle: u32,
    /// Cycles requested.
    pub total_cycles: u32,
    /// One entry per hop, from TTL 1 up to the destination (or `max_hops` when it never answered).
    pub hops: Vec<AdvHop>,
    /// The destination itself answered (not just a router saying "unreachable").
    pub destination_reached: bool,
    /// How the destination answered in the latest cycle that reached it.
    pub reached_via: Option<ReachKind>,
    /// Only set on the value *returned* by the run: it was cancelled before finishing.
    pub cancelled: bool,
}

impl AdvMtrSnapshot {
    /// The simple table (without the extras), for code that only knows [`MtrSnapshot`].
    pub fn to_trace(&self) -> MtrSnapshot {
        MtrSnapshot {
            target: self.target,
            cycle: self.cycle,
            total_cycles: self.total_cycles,
            hops: self.hops.iter().map(|h| h.hop.clone()).collect(),
            destination_reached: self.destination_reached,
            cancelled: self.cancelled,
        }
    }

    /// `"UDP (port 33434)"`, `"TCP SYN (port 443)"` or `"ICMP"`.
    pub fn mode_description(&self) -> String {
        match self.mode {
            ProbeMode::Icmp => self.mode.label().to_owned(),
            _ => format!("{} (port {})", self.mode.label(), self.port),
        }
    }

    /// `"IPv4"` or `"IPv6"`.
    pub fn family_label(&self) -> &'static str {
        if self.target.is_ipv6() {
            "IPv6"
        } else {
            "IPv4"
        }
    }
}

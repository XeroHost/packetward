// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-core — Config model, IP/CIDR sets, allowlist, time windows, errors. No OS dependencies.

mod cidr;
mod packet;

pub use cidr::{Cidr, CidrError, CidrSet};
pub use packet::{Direction, PacketMeta, Protocol, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};

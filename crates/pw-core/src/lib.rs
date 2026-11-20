// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-core — Config model, IP/CIDR sets, allowlist, time windows, errors. No OS dependencies.

mod cidr;
mod packet;
mod proxy;

pub use cidr::{Cidr, CidrError, CidrSet};
pub use packet::{Direction, PacketMeta, Protocol, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
pub use proxy::{
    validate_proxy_password, validate_proxy_username, ProxyAuth, MAX_PROXY_PASSWORD_LEN,
    MAX_PROXY_USERNAME_LEN,
};

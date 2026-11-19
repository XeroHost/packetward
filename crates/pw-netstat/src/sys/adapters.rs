// SPDX-License-Identifier: GPL-3.0-or-later
//! Default gateways and DNS servers of the adapters that are up (`GetAdaptersAddresses`, read-only).
//! These addresses must never be blocked: cutting the gateway or the resolver cuts the server off.
#![allow(unsafe_code)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKET_ADDRESS};

use crate::NetworkContext;

const ERROR_BUFFER_OVERFLOW: u32 = 111;
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const ATTEMPTS: usize = 5;

fn sockaddr_to_ip(bytes: &[u8]) -> Option<IpAddr> {
    let family = u16::from_ne_bytes([*bytes.first()?, *bytes.get(1)?]);
    if family == AF_INET.0 {
        let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(octets)))
    } else if family == AF_INET6.0 {
        let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        None
    }
}

/// Decodes a `SOCKET_ADDRESS` that points into the adapter buffer.
///
/// # Safety
/// `address.lpSockaddr` must be null or point to `iSockaddrLength` readable bytes.
unsafe fn socket_address_ip(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
    let len = usize::try_from(address.iSockaddrLength).ok()?;
    if address.lpSockaddr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: guaranteed by the caller.
    let bytes = unsafe { std::slice::from_raw_parts(address.lpSockaddr.cast::<u8>(), len) };
    sockaddr_to_ip(bytes).map(|ip| ip.to_canonical())
}

pub fn network_context() -> io::Result<NetworkContext> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST;
    let mut size = 15_000u32;
    for _ in 0..ATTEMPTS {
        // u64 backing store: the structures need 8-byte alignment.
        let mut buf = vec![0u64; (size as usize).div_ceil(8) + 1];
        let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: `head` points to `buf`, at least `size` bytes and suitably aligned; `size` is a valid
        // out-parameter.
        let rc = unsafe {
            GetAdaptersAddresses(u32::from(AF_UNSPEC.0), flags, None, Some(head), &mut size)
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            size = size.saturating_add(4096);
            continue;
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let mut context = NetworkContext::default();
        let mut adapter = head.cast_const();
        while !adapter.is_null() {
            // SAFETY: on success the buffer holds a valid linked list of adapters inside `buf`, which
            // outlives this loop.
            let a = unsafe { &*adapter };
            if a.OperStatus == IfOperStatusUp && a.IfType != IF_TYPE_SOFTWARE_LOOPBACK {
                let mut gateway = a.FirstGatewayAddress.cast_const();
                while !gateway.is_null() {
                    // SAFETY: same list guarantee.
                    let g = unsafe { &*gateway };
                    // SAFETY: the socket address points into `buf`.
                    if let Some(ip) = unsafe { socket_address_ip(&g.Address) } {
                        context.gateways.push(ip);
                    }
                    gateway = g.Next.cast_const();
                }
                let mut dns = a.FirstDnsServerAddress.cast_const();
                while !dns.is_null() {
                    // SAFETY: same list guarantee.
                    let d = unsafe { &*dns };
                    // SAFETY: the socket address points into `buf`.
                    if let Some(ip) = unsafe { socket_address_ip(&d.Address) } {
                        context.dns_servers.push(ip);
                    }
                    dns = d.Next.cast_const();
                }
            }
            adapter = a.Next.cast_const();
        }
        context.gateways.sort();
        context.gateways.dedup();
        context.dns_servers.sort();
        context.dns_servers.dedup();
        return Ok(context);
    }
    Err(io::Error::other("the adapter list kept changing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_real_machine_reports_something_sane() {
        let context = network_context().expect("adapters can be listed");
        for ip in context.gateways.iter().chain(&context.dns_servers) {
            assert!(!ip.is_unspecified() && !ip.is_loopback(), "{ip}");
        }
    }
}

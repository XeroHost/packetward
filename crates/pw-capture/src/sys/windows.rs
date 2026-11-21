// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Win32 helpers: adapter listing (read-only), the elevation check and the `SIO_RCVALL` switch of the
//! raw-socket backend. Everything `unsafe` for those lives here.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::io::AsRawSocket;

use socket2::Socket;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    WSAIoctl, AF_INET, AF_INET6, AF_UNSPEC, RCVALL_IPLEVEL, SIO_RCVALL, SOCKET,
};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::backend::InterfaceId;
use crate::interfaces::InterfaceInfo;

const ERROR_BUFFER_OVERFLOW: u32 = 111;
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
/// The adapter list grows between the sizing call and the read; retry a few times.
const ADAPTER_ATTEMPTS: usize = 5;

// ---------------------------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------------------------

/// Reads a NUL-terminated UTF-16 string. `ptr` may be null.
///
/// # Safety
/// `ptr` must be null or point to a NUL-terminated UTF-16 string that stays valid for the call.
unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: the caller guarantees the string is NUL-terminated, so the scan stops inside it.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` elements were just read from the same allocation.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Reads a NUL-terminated ANSI string (adapter GUIDs are ASCII).
///
/// # Safety
/// `ptr` must be null or point to a NUL-terminated string that stays valid for the call.
unsafe fn ansi_to_string(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: NUL-terminated by the caller's guarantee.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` bytes were just read from the same allocation.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr, len) }).into_owned()
}

/// Decodes a `SOCKADDR_IN` / `SOCKADDR_IN6` from its raw bytes.
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

/// Lists the adapters of this machine with their unicast addresses (`GetAdaptersAddresses`, read-only).
pub(crate) fn list_adapters() -> io::Result<Vec<InterfaceInfo>> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 15_000u32;
    for _ in 0..ADAPTER_ATTEMPTS {
        // u64 backing store: the structures need 8-byte alignment.
        let mut buf = vec![0u64; (size as usize).div_ceil(8) + 1];
        let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: `head` points to `buf`, which is at least `size` bytes and suitably aligned; `size` is a
        // valid out-parameter.
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
        let mut out = Vec::new();
        let mut adapter = head.cast_const();
        while !adapter.is_null() {
            // SAFETY: on success the buffer holds a valid linked list of adapters; every pointer in it
            // points into `buf`, which outlives this loop.
            let a = unsafe { &*adapter };
            let mut addrs = Vec::new();
            let mut unicast = a.FirstUnicastAddress.cast_const();
            while !unicast.is_null() {
                // SAFETY: same list guarantee as above.
                let u = unsafe { &*unicast };
                let sock = u.Address.lpSockaddr;
                let len = usize::try_from(u.Address.iSockaddrLength).unwrap_or(0);
                if !sock.is_null() && len > 0 {
                    // SAFETY: lpSockaddr points to iSockaddrLength readable bytes inside `buf`.
                    let bytes = unsafe { std::slice::from_raw_parts(sock.cast::<u8>(), len) };
                    if let Some(ip) = sockaddr_to_ip(bytes) {
                        addrs.push(ip);
                    }
                }
                unicast = u.Next.cast_const();
            }
            // SAFETY: the string pointers are NUL-terminated strings inside `buf` or null.
            let (guid, name, description) = unsafe {
                (
                    ansi_to_string(a.AdapterName.0),
                    wide_to_string(a.FriendlyName.0),
                    wide_to_string(a.Description.0),
                )
            };
            out.push(InterfaceInfo {
                id: InterfaceId(guid),
                name,
                description,
                addrs,
                up: a.OperStatus == IfOperStatusUp,
                loopback: a.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
            });
            adapter = a.Next.cast_const();
        }
        return Ok(out);
    }
    Err(io::Error::other("the adapter list kept changing size"))
}

/// Milliseconds since boot from the system tick counter: a plain memory read with no hypervisor trap.
pub(crate) fn tick_ms() -> u64 {
    // SAFETY: GetTickCount64 takes no arguments and has no preconditions.
    unsafe { windows::Win32::System::SystemInformation::GetTickCount64() }
}

// ---------------------------------------------------------------------------------------------
// Elevation
// ---------------------------------------------------------------------------------------------

/// Is this process running elevated (an administrator token with the privileges active)?
pub(crate) fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing; `token` is a valid out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION and its size is passed; `token` was opened just above.
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast::<c_void>()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: `token` is the handle opened above and is closed exactly once.
    let _ = unsafe { CloseHandle(token) };
    queried.is_ok() && elevation.TokenIsElevated != 0
}

// ---------------------------------------------------------------------------------------------
// SIO_RCVALL
// ---------------------------------------------------------------------------------------------

/// Makes a raw socket bound to an interface address receive all IP packets that interface carries, in
/// both directions, **without** putting the adapter in promiscuous mode (`RCVALL_IPLEVEL`).
pub(crate) fn enable_rcvall(socket: &Socket) -> io::Result<()> {
    let mode = RCVALL_IPLEVEL.0 as u32;
    let mut returned = 0u32;
    // SAFETY: the socket handle is valid for the duration of the call (borrowed from `socket`); the input
    // buffer is a live u32 of the stated size and no output buffer or overlapped I/O is used.
    let rc = unsafe {
        WSAIoctl(
            SOCKET(socket.as_raw_socket() as usize),
            SIO_RCVALL,
            Some(std::ptr::from_ref(&mode).cast::<c_void>()),
            size_of::<u32>() as u32,
            None,
            0,
            &mut returned,
            None,
            None,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Win32 backend: IP Helper tables, interface counters, WTS sessions and process names.
//! Everything `unsafe` in `pw-netstat` lives here.
#![allow(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::c_void;
use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use pw_proto::{Connection, RdpSession, RdpSessionState};
use windows::core::w;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetExtendedTcpTable, GetExtendedUdpTable, GetIfTable2, GetIpForwardTable2,
    MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSClientAddress, WTSClientName, WTSClientProtocolType, WTSConnected,
    WTSDisconnected, WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW,
    WTSUserName, WTS_CLIENT_ADDRESS, WTS_INFO_CLASS, WTS_SESSION_INFOW,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::rdp::client_address;
use crate::tables::{parse_tcp4, parse_tcp6, parse_udp4, parse_udp6};
use crate::{ConnectionTable, Counters, InterfaceSample, NetStat, DEFAULT_RDP_PORT};

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// The tables grow between the sizing call and the read; retry a few times with growing slack.
const TABLE_ATTEMPTS: usize = 8;
const PROTOCOL_RDP: u16 = 2;
/// How long a cached process name is trusted before the creation time is checked again (PID reuse).
const NAME_REVALIDATE: Duration = Duration::from_secs(5);

fn win32_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

// ---------------------------------------------------------------------------------------------
// Connection tables
// ---------------------------------------------------------------------------------------------

/// Reads a variable-size IP Helper table, growing the buffer until it fits.
fn read_table(mut fetch: impl FnMut(Option<*mut c_void>, &mut u32) -> u32) -> io::Result<Vec<u8>> {
    let mut size = 0u32;
    // First call only asks how big the table is.
    let first = fetch(None, &mut size);
    if first != 0 && first != ERROR_INSUFFICIENT_BUFFER {
        return Err(win32_error(first));
    }
    for _ in 0..TABLE_ATTEMPTS {
        // A DWORD-backed buffer, so Windows can write 4-byte aligned data; 25 % slack because
        // connections appear between the two calls.
        let words = (size as usize + size as usize / 4).div_ceil(4) + 16;
        let mut buffer = vec![0u32; words];
        let mut capacity = u32::try_from(words * 4).unwrap_or(u32::MAX);
        let status = fetch(Some(buffer.as_mut_ptr().cast::<c_void>()), &mut capacity);
        match status {
            0 => {
                // SAFETY: `buffer` owns `words * 4` initialised bytes; the u8 view has weaker
                // alignment than the u32 backing it and the same length.
                let bytes =
                    unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), words * 4) };
                return Ok(bytes.to_vec());
            }
            ERROR_INSUFFICIENT_BUFFER => size = capacity,
            other => return Err(win32_error(other)),
        }
    }
    Err(io::Error::other(
        "the connection table kept growing while it was being read",
    ))
}

fn tcp_table(family: u32) -> io::Result<Vec<u8>> {
    read_table(|buffer, size| {
        // SAFETY: `buffer` is either None or points to `*size` writable bytes (see `read_table`).
        unsafe { GetExtendedTcpTable(buffer, size, false, family, TCP_TABLE_OWNER_PID_ALL, 0) }
    })
}

fn udp_table(family: u32) -> io::Result<Vec<u8>> {
    read_table(|buffer, size| {
        // SAFETY: as above.
        unsafe { GetExtendedUdpTable(buffer, size, false, family, UDP_TABLE_OWNER_PID, 0) }
    })
}

fn to_io(err: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(err)
}

// ---------------------------------------------------------------------------------------------
// Process names
// ---------------------------------------------------------------------------------------------

struct CachedName {
    creation: u64,
    name: Option<String>,
    checked: Instant,
}

#[derive(Default)]
struct ProcessNames {
    cache: HashMap<u32, CachedName>,
}

fn filetime(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

/// The creation time and image file name of a process, if it can be opened.
fn query_process(pid: u32) -> Option<(u64, String)> {
    // SAFETY: plain API call; the returned handle is closed below.
    let handle: HANDLE =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut created = FILETIME::default();
    let (mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: `handle` is valid and every out pointer refers to a live local.
    let times = unsafe { GetProcessTimes(handle, &mut created, &mut exit, &mut kernel, &mut user) };
    let mut buffer = vec![0u16; 1024];
    let mut size = buffer.len() as u32;
    // SAFETY: `buffer` has `size` writable u16s; the call writes at most that many.
    let queried = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    };
    // SAFETY: closing the handle opened above, once.
    unsafe {
        let _ = CloseHandle(handle);
    }
    times.ok()?;
    queried.ok()?;
    let path = String::from_utf16_lossy(&buffer[..size as usize]);
    let file = path.rsplit('\\').next().unwrap_or(&path).to_owned();
    Some((filetime(created), file))
}

impl ProcessNames {
    fn resolve(&mut self, pids: &HashSet<u32>) -> BTreeMap<u32, String> {
        let now = Instant::now();
        self.cache.retain(|pid, _| pids.contains(pid));
        let mut names = BTreeMap::new();
        for &pid in pids {
            let name = match pid {
                0 => Some("System Idle Process".to_owned()),
                4 => Some("System".to_owned()),
                _ => self.lookup(pid, now),
            };
            if let Some(name) = name {
                names.insert(pid, name);
            }
        }
        names
    }

    fn lookup(&mut self, pid: u32, now: Instant) -> Option<String> {
        if let Some(entry) = self.cache.get(&pid) {
            if now.duration_since(entry.checked) < NAME_REVALIDATE {
                return entry.name.clone();
            }
        }
        let fresh = query_process(pid);
        let cached = self.cache.get(&pid);
        let name = match (&fresh, cached) {
            // Same process as before: keep the cached name, just refresh the timestamp.
            (Some((creation, _)), Some(old)) if old.creation == *creation && old.name.is_some() => {
                old.name.clone()
            }
            (Some((_, name)), _) => Some(name.clone()),
            (None, _) => None,
        };
        self.cache.insert(
            pid,
            CachedName {
                creation: fresh.map_or(0, |(creation, _)| creation),
                name: name.clone(),
                checked: now,
            },
        );
        name
    }
}

// ---------------------------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------------------------

fn wide_to_string(text: &[u16]) -> String {
    let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
    String::from_utf16_lossy(&text[..end])
}

/// Interface indexes that carry a default route (`/0` prefix), IPv4 or IPv6.
fn default_route_interfaces() -> io::Result<HashSet<u32>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` is a valid out pointer; the table is freed below.
    let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if status != WIN32_ERROR(0) {
        return Err(win32_error(status.0));
    }
    // SAFETY: on success `table` points to NumEntries consecutive rows starting at `Table`.
    let rows: &[MIB_IPFORWARD_ROW2] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table).NumEntries as usize,
        )
    };
    let with_default = rows
        .iter()
        .filter(|row| row.DestinationPrefix.PrefixLength == 0)
        .map(|row| row.InterfaceIndex)
        .collect();
    // SAFETY: `table` was allocated by GetIpForwardTable2 and is freed once.
    unsafe { FreeMibTable(table.cast::<c_void>()) };
    Ok(with_default)
}

fn interface_rows() -> io::Result<Vec<InterfaceSample>> {
    let defaults = default_route_interfaces().unwrap_or_else(|err| {
        tracing::warn!(%err, "could not read the routing table; assuming no default gateways");
        HashSet::new()
    });
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` is a valid out pointer; the table is freed below.
    let status = unsafe { GetIfTable2(&mut table) };
    if status != WIN32_ERROR(0) {
        return Err(win32_error(status.0));
    }
    // SAFETY: on success `table` points to NumEntries consecutive rows starting at `Table`.
    let rows: &[MIB_IF_ROW2] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>(),
            (*table).NumEntries as usize,
        )
    };
    let samples = rows
        .iter()
        .map(|row| {
            // InterfaceAndOperStatusFlags: bit 0 Hardware, 1 Filter, 2 ConnectorPresent.
            let flags = row.InterfaceAndOperStatusFlags._bitfield;
            InterfaceSample {
                index: row.InterfaceIndex,
                name: wide_to_string(&row.Alias),
                description: wide_to_string(&row.Description),
                if_type: row.Type,
                oper_up: row.OperStatus.0 == 1, // IfOperStatusUp
                hardware: flags & 0b001 != 0,
                filter: flags & 0b010 != 0,
                connector_present: flags & 0b100 != 0,
                has_default_gateway: defaults.contains(&row.InterfaceIndex),
                link_speed_bps: row.ReceiveLinkSpeed.min(row.TransmitLinkSpeed),
                counters: Counters {
                    in_octets: row.InOctets,
                    out_octets: row.OutOctets,
                    in_packets: row.InUcastPkts.saturating_add(row.InNUcastPkts),
                    out_packets: row.OutUcastPkts.saturating_add(row.OutNUcastPkts),
                },
            }
        })
        .collect();
    // SAFETY: `table` was allocated by GetIfTable2 and is freed once.
    unsafe { FreeMibTable(table.cast::<c_void>()) };
    Ok(samples)
}

// ---------------------------------------------------------------------------------------------
// RDP sessions
// ---------------------------------------------------------------------------------------------

/// A buffer returned by `WTSQuerySessionInformationW`, freed on drop.
struct WtsBuffer {
    ptr: PWSTR,
    len: usize,
}

impl WtsBuffer {
    fn query(session: u32, class: WTS_INFO_CLASS) -> Option<Self> {
        let mut ptr = PWSTR::null();
        let mut len = 0u32;
        // SAFETY: valid out pointers; a null server handle means the local server.
        unsafe { WTSQuerySessionInformationW(None, session, class, &mut ptr, &mut len) }.ok()?;
        (!ptr.is_null()).then_some(Self {
            ptr,
            len: len as usize,
        })
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: the buffer holds `len` bytes until it is freed in Drop.
        unsafe { std::slice::from_raw_parts(self.ptr.0.cast::<u8>(), self.len) }
    }

    fn text(&self) -> String {
        // SAFETY: string-valued classes return a NUL-terminated UTF-16 string.
        unsafe { self.ptr.to_string() }.unwrap_or_default()
    }
}

impl Drop for WtsBuffer {
    fn drop(&mut self) {
        // SAFETY: the buffer was allocated by WTS and is freed exactly once.
        unsafe { WTSFreeMemory(self.ptr.0.cast::<c_void>()) };
    }
}

fn rdp_session_list() -> io::Result<Vec<RdpSession>> {
    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: valid out pointers; the list is freed below.
    unsafe { WTSEnumerateSessionsW(None, 0, 1, &mut info, &mut count) }.map_err(to_io)?;
    // SAFETY: on success `info` points to `count` consecutive WTS_SESSION_INFOW.
    let sessions = unsafe { std::slice::from_raw_parts(info, count as usize) };
    let mut result = Vec::new();
    for session in sessions {
        let id = session.SessionId;
        let state = if session.State == WTSActive {
            RdpSessionState::Active
        } else if session.State == WTSConnected {
            RdpSessionState::Connected
        } else if session.State == WTSDisconnected {
            RdpSessionState::Disconnected
        } else {
            continue; // listener, idle, shadow...: not a user session
        };
        let is_rdp = WtsBuffer::query(id, WTSClientProtocolType)
            .and_then(|buffer| <[u8; 2]>::try_from(buffer.bytes().get(..2)?).ok())
            .is_some_and(|bytes| u16::from_le_bytes(bytes) == PROTOCOL_RDP);
        if !is_rdp {
            continue;
        }
        let user = WtsBuffer::query(id, WTSUserName)
            .map(|b| b.text())
            .unwrap_or_default();
        let client_name = WtsBuffer::query(id, WTSClientName)
            .map(|b| b.text())
            .unwrap_or_default();
        let client_addr = WtsBuffer::query(id, WTSClientAddress).and_then(|buffer| {
            if buffer.bytes().len() < std::mem::size_of::<WTS_CLIENT_ADDRESS>() {
                return None;
            }
            // SAFETY: the buffer holds at least one WTS_CLIENT_ADDRESS; read it unaligned.
            let raw = unsafe {
                std::ptr::read_unaligned(buffer.bytes().as_ptr().cast::<WTS_CLIENT_ADDRESS>())
            };
            client_address(raw.AddressFamily, &raw.Address)
        });
        result.push(RdpSession {
            session_id: id,
            user,
            state,
            reported_addr: client_addr,
            client_name,
        });
    }
    // SAFETY: `info` was allocated by WTSEnumerateSessionsW and is freed once.
    unsafe { WTSFreeMemory(info.cast::<c_void>()) };
    Ok(result)
}

/// The RDP listener port from `HKLMSYSTEMCurrentControlSetControlTerminal
/// ServerWinStationsRDP-TcpPortNumber`, or 3389 when it cannot be read.
fn configured_rdp_port() -> u16 {
    let mut value = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: valid NUL-terminated names and a DWORD-sized out buffer.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"),
            w!("PortNumber"),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut value as *mut u32).cast::<c_void>()),
            Some(&mut size),
        )
    };
    match (status.0, u16::try_from(value)) {
        (0, Ok(port)) if port != 0 => port,
        _ => DEFAULT_RDP_PORT,
    }
}

// ---------------------------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------------------------

/// Network state read straight from the Windows APIs.
#[derive(Default)]
pub struct WindowsNetStat {
    names: Mutex<ProcessNames>,
    feed: Mutex<Option<crate::sys::eventlog::LogonFeed>>,
    failure_feed: Mutex<Option<crate::sys::eventlog::FailureFeed>>,
}

impl WindowsNetStat {
    pub fn new() -> Self {
        Self::default()
    }

    fn names(&self) -> MutexGuard<'_, ProcessNames> {
        self.names.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl NetStat for WindowsNetStat {
    fn logon_audit(&self) -> pw_proto::LogonAudit {
        crate::sys::eventlog::logon_audit()
    }

    fn start_logon_feed(&self, window_ms: u64, sink: crate::LogonSink) -> pw_proto::TrustFeed {
        let (state, feed) = crate::sys::eventlog::start_feed(window_ms, sink);
        *self.feed.lock().unwrap_or_else(PoisonError::into_inner) = feed;
        state
    }

    fn network_context(&self) -> crate::NetworkContext {
        crate::sys::adapters::network_context().unwrap_or_else(|err| {
            tracing::warn!(%err, "could not read gateways and DNS servers");
            crate::NetworkContext::default()
        })
    }

    fn start_failure_feed(&self, sink: crate::LogonSink) -> bool {
        let feed = crate::sys::eventlog::start_failure_feed(&sink);
        let started = feed.is_some();
        *self
            .failure_feed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = feed;
        started
    }

    fn rdp_port(&self) -> u16 {
        configured_rdp_port()
    }

    fn connections(&self) -> io::Result<ConnectionTable> {
        let mut rows: Vec<Connection> = Vec::new();
        rows.extend(parse_tcp4(&tcp_table(u32::from(AF_INET.0))?).map_err(to_io)?);
        rows.extend(parse_udp4(&udp_table(u32::from(AF_INET.0))?).map_err(to_io)?);
        // IPv6 can be switched off; its absence is not an error.
        match tcp_table(u32::from(AF_INET6.0)).map_err(|e| e.to_string()) {
            Ok(buf) => rows.extend(parse_tcp6(&buf).map_err(to_io)?),
            Err(err) => tracing::debug!(%err, "no IPv6 TCP table"),
        }
        match udp_table(u32::from(AF_INET6.0)).map_err(|e| e.to_string()) {
            Ok(buf) => rows.extend(parse_udp6(&buf).map_err(to_io)?),
            Err(err) => tracing::debug!(%err, "no IPv6 UDP table"),
        }
        let pids: HashSet<u32> = rows.iter().map(|row| row.pid).collect();
        let processes = self.names().resolve(&pids);
        Ok(ConnectionTable { rows, processes })
    }

    fn interfaces(&self) -> io::Result<Vec<InterfaceSample>> {
        interface_rows()
    }

    fn rdp_sessions(&self) -> io::Result<Vec<RdpSession>> {
        rdp_session_list()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{classify_kind, counts_toward_total};

    /// Reads the real machine (read-only). Prints what it found so a human can compare it with
    /// `netstat -ano`, `Get-NetAdapter` and `query user` (`cargo test -p pw-netstat -- --nocapture`).
    #[test]
    fn reads_the_real_machine() {
        let backend = WindowsNetStat::new();

        let table = backend.connections().unwrap();
        assert!(
            !table.rows.is_empty(),
            "every Windows machine has listeners"
        );
        assert!(
            table
                .rows
                .iter()
                .any(|r| r.state == Some(pw_proto::TcpState::Listen)),
            "expected at least one listening socket"
        );
        assert_eq!(table.processes.get(&4).map(String::as_str), Some("System"));
        println!(
            "connections: {} rows, {} named processes",
            table.rows.len(),
            table.processes.len()
        );

        let interfaces = backend.interfaces().unwrap();
        assert!(interfaces
            .iter()
            .any(|i| i.if_type == crate::if_type::LOOPBACK));
        for i in &interfaces {
            let kind = classify_kind(i);
            println!(
                "if {:>3} {:<28} type={:<3} up={} hw={} filter={} conn={} gw={} {:?} counted={} in={}B out={}B",
                i.index, i.name, i.if_type, i.oper_up, i.hardware, i.filter, i.connector_present,
                i.has_default_gateway, kind, counts_toward_total(i, kind),
                i.counters.in_octets, i.counters.out_octets
            );
        }

        for session in backend.rdp_sessions().unwrap() {
            println!("rdp session: {session:?}");
        }
    }

    #[test]
    fn reading_the_tables_twice_is_stable_and_cheap() {
        let backend = WindowsNetStat::new();
        let first = Instant::now();
        let a = backend.connections().unwrap();
        let cold = first.elapsed();
        let second = Instant::now();
        let b = backend.connections().unwrap();
        let warm = second.elapsed();
        println!(
            "cold {cold:?}, warm {warm:?}, rows {} -> {}",
            a.rows.len(),
            b.rows.len()
        );
        assert!(warm < Duration::from_secs(1));
    }
}

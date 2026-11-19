// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows implementation of [`RdpControl`]: registry, account policy, service control manager and
//! terminal services. Reads are safe anywhere; **every write is only meant to run on a test VPS**.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::iter::once;
use std::thread::sleep;
use std::time::{Duration, Instant};

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupGetMembers, NetUserModalsGet, NetUserModalsSet,
    LOCALGROUP_MEMBERS_INFO_3, USER_MODALS_INFO_3,
};
use windows::Win32::System::Registry::{
    RegGetValueW, RegSetKeyValueW, HKEY_LOCAL_MACHINE, REG_DWORD, RRF_RT_REG_DWORD,
};
use windows::Win32::System::RemoteDesktop::{WTSDisconnectSession, WTSLogoffSession};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, EnumDependentServicesW, OpenSCManagerW, OpenServiceW,
    QueryServiceStatus, StartServiceW, ENUM_SERVICE_STATUSW, SC_HANDLE, SC_MANAGER_CONNECT,
    SERVICE_ACTIVE, SERVICE_CONTROL_STOP, SERVICE_ENUMERATE_DEPENDENTS, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED,
};

use crate::rdp_control::{Lockout, RdpConfig, RdpControl, DEFAULT_PORT};

const TERMINAL_SERVER: PCWSTR = w!(r"SYSTEM\CurrentControlSet\Control\Terminal Server");
const RDP_TCP: PCWSTR = w!(r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
const NERR_SUCCESS: u32 = 0;
const NERR_GROUP_NOT_FOUND: u32 = 2220;
const MAX_PREFERRED_LENGTH: u32 = u32::MAX;
const ERROR_MORE_DATA: u32 = 234;
const SERVICE_WAIT: Duration = Duration::from_secs(40);

fn to_io(err: windows::core::Error) -> io::Error {
    io::Error::other(err)
}

fn read_dword(key: PCWSTR, name: PCWSTR) -> Option<u32> {
    let mut value = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: valid NUL-terminated names and a DWORD-sized out buffer.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key,
            name,
            RRF_RT_REG_DWORD,
            None,
            Some((&mut value as *mut u32).cast::<c_void>()),
            Some(&mut size),
        )
    };
    (status == ERROR_SUCCESS).then_some(value)
}

fn write_dword(key: PCWSTR, name: PCWSTR, value: u32) -> io::Result<()> {
    // SAFETY: valid NUL-terminated names; the data pointer refers to a live DWORD of the stated size.
    let status = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            key,
            name,
            REG_DWORD.0,
            Some((&value as *const u32).cast::<c_void>()),
            size_of::<u32>() as u32,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status.0 as i32))
    }
}

/// A service control manager handle that closes itself.
struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by this module and is closed exactly once.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn open_service(name: PCWSTR, access: u32) -> io::Result<(Handle, Handle)> {
    // SAFETY: plain calls with valid arguments; the handles are wrapped so they are closed.
    let manager = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT) }.map_err(to_io)?;
    let manager = Handle(manager);
    // SAFETY: `manager` is a valid handle and `name` a NUL-terminated string.
    let service = unsafe { OpenServiceW(manager.0, name, access) }.map_err(to_io)?;
    Ok((manager, Handle(service)))
}

fn wait_for(service: &Handle, wanted: u32) -> io::Result<()> {
    let deadline = Instant::now() + SERVICE_WAIT;
    loop {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: valid handle and out pointer.
        unsafe { QueryServiceStatus(service.0, &mut status) }.map_err(to_io)?;
        if status.dwCurrentState.0 == wanted {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(
                "the service did not reach the expected state in time",
            ));
        }
        sleep(Duration::from_millis(250));
    }
}

/// Names of the services that depend on `service` and are running (they must stop first).
fn running_dependents(service: &Handle) -> io::Result<Vec<Vec<u16>>> {
    let mut needed = 0u32;
    let mut count = 0u32;
    // SAFETY: sizing call with no buffer.
    let probe = unsafe {
        EnumDependentServicesW(service.0, SERVICE_ACTIVE, None, 0, &mut needed, &mut count)
    };
    if probe.is_ok() || needed == 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8) + 1];
    // SAFETY: the buffer is at least `needed` bytes and 8-byte aligned.
    unsafe {
        EnumDependentServicesW(
            service.0,
            SERVICE_ACTIVE,
            Some(buffer.as_mut_ptr().cast::<ENUM_SERVICE_STATUSW>()),
            needed,
            &mut needed,
            &mut count,
        )
    }
    .map_err(to_io)?;
    let entries = buffer.as_ptr().cast::<ENUM_SERVICE_STATUSW>();
    let mut names = Vec::new();
    for index in 0..count as usize {
        // SAFETY: on success the buffer holds `count` entries whose name pointers point into it.
        let entry = unsafe { &*entries.add(index) };
        let ptr = entry.lpServiceName.0;
        if ptr.is_null() {
            continue;
        }
        let mut len = 0usize;
        // SAFETY: the name is NUL-terminated inside the buffer.
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` elements were just read from the same allocation.
        let mut name = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        name.push(0);
        names.push(name);
    }
    Ok(names)
}

fn stop_service(name: PCWSTR) -> io::Result<()> {
    let (_manager, service) = open_service(name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
    let mut status = SERVICE_STATUS::default();
    // SAFETY: valid handle and out pointer.
    let _ = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
    wait_for(&service, SERVICE_STOPPED.0)
}

fn start_service(name: PCWSTR) -> io::Result<()> {
    let (_manager, service) = open_service(name, SERVICE_START | SERVICE_QUERY_STATUS)?;
    // SAFETY: valid handle, no arguments.
    unsafe { StartServiceW(service.0, None) }.map_err(to_io)?;
    wait_for(&service, SERVICE_RUNNING.0)
}

pub struct WindowsRdpControl;

impl RdpControl for WindowsRdpControl {
    fn read(&self) -> io::Result<RdpConfig> {
        let mut lockout = Lockout::default();
        let mut buffer: *mut u8 = std::ptr::null_mut();
        // SAFETY: valid out pointer; the buffer is freed below.
        let status = unsafe { NetUserModalsGet(PCWSTR::null(), 3, &mut buffer) };
        if status == NERR_SUCCESS && !buffer.is_null() {
            // SAFETY: on success the buffer holds one USER_MODALS_INFO_3.
            let info = unsafe { &*buffer.cast::<USER_MODALS_INFO_3>() };
            lockout = Lockout {
                threshold: info.usrmod3_lockout_threshold,
                window_mins: info.usrmod3_lockout_observation_window / 60,
                duration_mins: info.usrmod3_lockout_duration / 60,
            };
        }
        if !buffer.is_null() {
            // SAFETY: the buffer came from NetUserModalsGet and is freed once.
            unsafe {
                let _ = NetApiBufferFree(Some(buffer.cast::<c_void>()));
            }
        }
        Ok(RdpConfig {
            enabled: read_dword(TERMINAL_SERVER, w!("fDenyTSConnections")).unwrap_or(1) == 0,
            port: read_dword(RDP_TCP, w!("PortNumber"))
                .and_then(|p| u16::try_from(p).ok())
                .filter(|p| *p != 0)
                .unwrap_or(DEFAULT_PORT),
            nla_required: read_dword(RDP_TCP, w!("UserAuthentication")).unwrap_or(1) == 1,
            security_layer: read_dword(RDP_TCP, w!("SecurityLayer")).unwrap_or(1),
            lockout,
        })
    }

    fn set_port(&self, port: u16) -> io::Result<()> {
        write_dword(RDP_TCP, w!("PortNumber"), u32::from(port))
    }

    fn set_nla(&self, required: bool) -> io::Result<()> {
        write_dword(RDP_TCP, w!("UserAuthentication"), u32::from(required))
    }

    fn set_lockout(&self, lockout: Lockout) -> io::Result<()> {
        let mut buffer: *mut u8 = std::ptr::null_mut();
        // SAFETY: valid out pointer; freed below.
        let status = unsafe { NetUserModalsGet(PCWSTR::null(), 3, &mut buffer) };
        if status != NERR_SUCCESS || buffer.is_null() {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // SAFETY: on success the buffer holds one USER_MODALS_INFO_3 that this call owns.
        let info = unsafe { &mut *buffer.cast::<USER_MODALS_INFO_3>() };
        info.usrmod3_lockout_threshold = lockout.threshold;
        info.usrmod3_lockout_observation_window = lockout.window_mins.saturating_mul(60);
        info.usrmod3_lockout_duration = lockout.duration_mins.saturating_mul(60);
        let mut bad_parameter = 0u32;
        // SAFETY: `buffer` is a valid USER_MODALS_INFO_3; the out pointer is valid.
        let set = unsafe { NetUserModalsSet(PCWSTR::null(), 3, buffer, Some(&mut bad_parameter)) };
        // SAFETY: the buffer came from NetUserModalsGet and is freed once.
        unsafe {
            let _ = NetApiBufferFree(Some(buffer.cast::<c_void>()));
        }
        if set == NERR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(set as i32))
        }
    }

    fn restart_service(&self) -> io::Result<()> {
        let term = w!("TermService");
        let dependents = {
            let (_manager, service) = open_service(
                term,
                SERVICE_ENUMERATE_DEPENDENTS | SERVICE_QUERY_STATUS | SERVICE_STOP,
            )?;
            running_dependents(&service)?
        };
        for name in &dependents {
            stop_service(PCWSTR(name.as_ptr()))?;
        }
        stop_service(term)?;
        start_service(term)?;
        // Best effort: bring the dependents back; the service manager starts the automatic ones anyway.
        for name in &dependents {
            let _ = start_service(PCWSTR(name.as_ptr()));
        }
        Ok(())
    }

    fn remote_desktop_users(&self) -> io::Result<Vec<String>> {
        let group: Vec<u16> = "Remote Desktop Users"
            .encode_utf16()
            .chain(once(0))
            .collect();
        let mut buffer: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        // SAFETY: valid NUL-terminated name and out pointers; the buffer is freed below.
        let status = unsafe {
            NetLocalGroupGetMembers(
                PCWSTR::null(),
                PCWSTR(group.as_ptr()),
                3,
                &mut buffer,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                None,
            )
        };
        if status == NERR_GROUP_NOT_FOUND {
            return Ok(Vec::new());
        }
        if status != NERR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut names = Vec::new();
        if !buffer.is_null() {
            // SAFETY: on success the buffer holds `read` LOCALGROUP_MEMBERS_INFO_3 entries.
            let members = unsafe {
                std::slice::from_raw_parts(
                    buffer.cast::<LOCALGROUP_MEMBERS_INFO_3>(),
                    read as usize,
                )
            };
            for member in members {
                let ptr: PWSTR = member.lgrmi3_domainandname;
                if ptr.is_null() {
                    continue;
                }
                let mut len = 0usize;
                // SAFETY: NUL-terminated string inside the buffer.
                while unsafe { *ptr.0.add(len) } != 0 {
                    len += 1;
                }
                // SAFETY: `len` elements were just read from the same allocation.
                names.push(String::from_utf16_lossy(unsafe {
                    std::slice::from_raw_parts(ptr.0, len)
                }));
            }
            // SAFETY: the buffer came from NetLocalGroupGetMembers and is freed once.
            unsafe {
                let _ = NetApiBufferFree(Some(buffer.cast::<c_void>()));
            }
        }
        Ok(names)
    }

    fn end_session(&self, session_id: u32, logoff: bool) -> io::Result<()> {
        // SAFETY: plain calls on the local server (a null handle means "this machine").
        let result = unsafe {
            if logoff {
                WTSLogoffSession(None, session_id, false)
            } else {
                WTSDisconnectSession(None, session_id, false)
            }
        };
        result.map_err(to_io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only: the real machine answers and the values are sane.
    #[test]
    fn reads_the_real_configuration() {
        let config = WindowsRdpControl
            .read()
            .expect("the configuration can be read");
        println!("{config:?}");
        assert!(config.port >= 1);
        let users = WindowsRdpControl
            .remote_desktop_users()
            .expect("the group can be listed");
        println!("Remote Desktop Users: {users:?}");
    }
}

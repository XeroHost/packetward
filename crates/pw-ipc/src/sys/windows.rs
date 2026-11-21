// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Win32 plumbing for the named pipe: security descriptors, account/SID lookups and group
//! membership. Everything `unsafe` in `pw-ipc` lives here.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::iter::once;

use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::IntoRawHandle;

use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupAdd, NetLocalGroupAddMembers, NetLocalGroupDel,
    NetLocalGroupDelMember, NetLocalGroupGetMembers, LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_0,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    CheckTokenMembership, GetTokenInformation, LookupAccountNameW, TokenUser, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED,
    SERVICE_STOP_PENDING,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NONE_MAPPED: u32 = 1332;
const NERR_SUCCESS: u32 = 0;
const NERR_GROUP_NOT_FOUND: u32 = 2220;
const MAX_PREFERRED_LENGTH: u32 = u32::MAX;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(once(0)).collect()
}

/// Low 16 bits of an `HRESULT_FROM_WIN32` value, i.e. the original Win32 error code.
fn win32_code(err: &windows::core::Error) -> u32 {
    (err.code().0 as u32) & 0xFFFF
}

fn to_io(err: windows::core::Error) -> io::Error {
    io::Error::other(err)
}

/// A self-relative security descriptor allocated by Windows from an SDDL string.
pub struct SecurityDescriptor {
    raw: PSECURITY_DESCRIPTOR,
}

// SAFETY: the descriptor is never mutated after creation and is freed exactly once in `Drop`.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: see above; shared access is read-only.
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let text = wide(sddl);
        let mut raw = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `text` is NUL-terminated and outlives the call; `raw` is a valid out pointer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                SDDL_REVISION_1,
                &mut raw,
                None,
            )
        }
        .map_err(to_io)?;
        Ok(Self { raw })
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.raw.0,
            bInheritHandle: BOOL(0),
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: `raw` was allocated with LocalAlloc by the SDDL conversion and is freed once.
        unsafe {
            LocalFree(Some(HLOCAL(self.raw.0)));
        }
    }
}

/// Creates one server instance of the pipe with the given security descriptor.
///
/// `first` must be true for the very first instance: it makes creation fail when another process
/// already owns the name, so nobody can squat the pipe before the agent starts.
pub fn create_pipe_instance(
    name: &str,
    descriptor: &SecurityDescriptor,
    first: bool,
) -> io::Result<NamedPipeServer> {
    let mut attributes = descriptor.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES whose descriptor is owned by
    // `descriptor`, which outlives the call; CreateNamedPipe copies the descriptor.
    unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
}

const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

/// Opens the agent pipe as a client with exactly the rights the ACL grants operators (see
/// `pipe::CLIENT_ACCESS`). SECURITY_IDENTIFICATION stops a server that is not the agent from
/// impersonating the caller.
pub fn open_client(name: &str) -> io::Result<NamedPipeClient> {
    let file = std::fs::OpenOptions::new()
        .access_mode(crate::pipe::CLIENT_ACCESS)
        .custom_flags(FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
        .open(name)?;
    // SAFETY: `file` owns a valid handle opened with FILE_FLAG_OVERLAPPED; ownership moves to the
    // pipe object, which closes it.
    unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle()) }
}

/// Converts a SID to its `S-1-5-...` string form.
fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: `sid` points to a valid SID and `text` is a valid out pointer.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(to_io)?;
    // SAFETY: on success `text` is a NUL-terminated UTF-16 string allocated with LocalAlloc.
    let converted = unsafe { text.to_string() };
    // SAFETY: freeing the buffer the conversion allocated, once.
    unsafe {
        LocalFree(Some(HLOCAL(text.0.cast())));
    }
    converted.map_err(io::Error::other)
}

/// The SID string of a local account or group, or `None` when no such account exists.
pub fn account_sid_string(account: &str) -> io::Result<Option<String>> {
    let name = wide(account);
    let mut sid_len = 0u32;
    let mut domain_len = 0u32;
    let mut kind = SID_NAME_USE(0);
    // SAFETY: first call only asks for the required buffer sizes; all pointers are valid.
    let sizing = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            None,
            &mut sid_len,
            None,
            &mut domain_len,
            &mut kind,
        )
    };
    if let Err(err) = sizing {
        match win32_code(&err) {
            ERROR_INSUFFICIENT_BUFFER => {}
            ERROR_NONE_MAPPED => return Ok(None),
            _ => return Err(to_io(err)),
        }
    }
    let mut sid = vec![0u8; sid_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: the buffers are exactly as large as the sizes reported by the first call.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    }
    .map_err(to_io)?;
    sid_to_string(PSID(sid.as_mut_ptr().cast())).map(Some)
}

/// Whether the SID is enabled in the calling thread's effective token. A group that is only
/// "deny-only" in the token (an unelevated administrator's Administrators) does not count.
pub fn token_has_group(sid: &str) -> io::Result<bool> {
    let text = wide(sid);
    let mut psid = PSID::default();
    // SAFETY: `text` is NUL-terminated; `psid` is a valid out pointer.
    unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut psid) }.map_err(to_io)?;
    let mut member = BOOL(0);
    // SAFETY: `psid` is a valid SID from the conversion above. A null token makes the call use the
    // thread's impersonation token or a duplicate of the process token.
    let checked = unsafe { CheckTokenMembership(None, psid, &mut member) };
    // SAFETY: freeing the SID the conversion allocated, once.
    unsafe {
        LocalFree(Some(HLOCAL(psid.0)));
    }
    checked.map_err(to_io)?;
    Ok(member.as_bool())
}

/// The SID string of the user running this process.
pub fn current_user_sid_string() -> io::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo handle from GetCurrentProcess is always valid; `token` is a valid out ptr.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(to_io)?;
    let result = (|| {
        let mut needed = 0u32;
        // SAFETY: sizing call with no output buffer.
        let sizing = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
        if let Err(err) = sizing {
            if win32_code(&err) != ERROR_INSUFFICIENT_BUFFER {
                return Err(to_io(err));
            }
        }
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: `buffer` holds `needed` bytes, as the sizing call asked.
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }
        .map_err(to_io)?;
        // SAFETY: the buffer now starts with a TOKEN_USER; it is a byte vector, so read unaligned.
        let user = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
        sid_to_string(user.User.Sid)
    })();
    // SAFETY: `token` was opened above and is closed once.
    unsafe {
        let _ = CloseHandle(token);
    }
    result
}

/// Whether `sid` is a member of the local group, according to the account database (not the
/// current token). `None` when the group does not exist.
pub fn local_group_has_member(group: &str, sid: &str) -> io::Result<Option<bool>> {
    Ok(local_group_member_sids(group)?.map(|members| {
        members
            .iter()
            .any(|member| member.eq_ignore_ascii_case(sid))
    }))
}

/// SIDs of the members of the local group, according to the account database (not any token).
/// `None` when the group does not exist.
pub fn local_group_member_sids(group: &str) -> io::Result<Option<Vec<String>>> {
    let name = wide(group);
    let mut buffer: *mut u8 = std::ptr::null_mut();
    let mut read = 0u32;
    let mut total = 0u32;
    // SAFETY: valid NUL-terminated name and valid out pointers; the buffer is freed below.
    let status = unsafe {
        NetLocalGroupGetMembers(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            0,
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
            None,
        )
    };
    match status {
        NERR_SUCCESS => {}
        NERR_GROUP_NOT_FOUND => return Ok(None),
        other => return Err(io::Error::from_raw_os_error(other as i32)),
    }
    let mut sids = Vec::new();
    let mut failure = None;
    if !buffer.is_null() {
        // SAFETY: on success `buffer` holds `read` LOCALGROUP_MEMBERS_INFO_0 entries.
        let members = unsafe {
            std::slice::from_raw_parts(buffer.cast::<LOCALGROUP_MEMBERS_INFO_0>(), read as usize)
        };
        for member in members {
            match sid_to_string(member.lgrmi0_sid) {
                Ok(sid) => sids.push(sid),
                Err(err) => {
                    failure = Some(err);
                    break;
                }
            }
        }
        // SAFETY: `buffer` was allocated by NetLocalGroupGetMembers and is freed once.
        unsafe {
            NetApiBufferFree(Some(buffer.cast_const().cast()));
        }
    }
    match failure {
        Some(err) => Err(err),
        None => Ok(Some(sids)),
    }
}

const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;

/// Raw state of a service as reported by the service control manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawServiceState {
    Stopped,
    StartPending,
    Running,
    StopPending,
    Other,
}

/// State of a registered service, or `None` when no such service exists. Needs no privileges.
pub fn service_state(name: &str) -> io::Result<Option<RawServiceState>> {
    let text = wide(name);
    // SAFETY: null machine/database names mean "local, active database".
    let manager = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
        .map_err(to_io)?;
    // SAFETY: `manager` is valid and `text` is NUL-terminated.
    let opened = unsafe { OpenServiceW(manager, PCWSTR(text.as_ptr()), SERVICE_QUERY_STATUS) };
    let result = match opened {
        Ok(service) => {
            let mut status = SERVICE_STATUS::default();
            // SAFETY: `service` is valid and `status` is a valid out struct.
            let queried = unsafe { QueryServiceStatus(service, &mut status) };
            // SAFETY: closing the handle opened above, once.
            unsafe {
                let _ = CloseServiceHandle(service);
            }
            queried.map_err(to_io).map(|()| {
                Some(match status.dwCurrentState {
                    SERVICE_STOPPED => RawServiceState::Stopped,
                    SERVICE_START_PENDING => RawServiceState::StartPending,
                    SERVICE_RUNNING => RawServiceState::Running,
                    SERVICE_STOP_PENDING => RawServiceState::StopPending,
                    _ => RawServiceState::Other,
                })
            })
        }
        Err(err) if win32_code(&err) == ERROR_SERVICE_DOES_NOT_EXIST => Ok(None),
        Err(err) => Err(to_io(err)),
    };
    // SAFETY: closing the handle opened above, once.
    unsafe {
        let _ = CloseServiceHandle(manager);
    }
    result
}

const NERR_GROUP_EXISTS: u32 = 2223;
const ERROR_MEMBER_IN_ALIAS: u32 = 1378;
const ERROR_NO_SUCH_MEMBER: u32 = 1387;

fn net_status(status: u32) -> io::Result<()> {
    if status == NERR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

/// Creates a local group. Returns `false` when it already existed.
pub fn local_group_add(group: &str, comment: &str) -> io::Result<bool> {
    let mut name = wide(group);
    let mut text = wide(comment);
    let info = LOCALGROUP_INFO_1 {
        lgrpi1_name: PWSTR(name.as_mut_ptr()),
        lgrpi1_comment: PWSTR(text.as_mut_ptr()),
    };
    // SAFETY: `info` and the strings it points to are valid for the duration of the call.
    let status = unsafe {
        NetLocalGroupAdd(
            PCWSTR::null(),
            1,
            (&info as *const LOCALGROUP_INFO_1).cast::<u8>(),
            None,
        )
    };
    if status == NERR_GROUP_EXISTS {
        return Ok(false);
    }
    net_status(status).map(|()| true)
}

/// Adds a SID to a local group. Returns `false` when it already was a member.
pub fn local_group_add_member(group: &str, sid: &str) -> io::Result<bool> {
    let name = wide(group);
    let text = wide(sid);
    let mut psid = PSID::default();
    // SAFETY: NUL-terminated string and valid out pointer; the SID is freed below.
    unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut psid) }.map_err(to_io)?;
    let member = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: psid };
    // SAFETY: `member` is a valid one-element LOCALGROUP_MEMBERS_INFO_0 array.
    let status = unsafe {
        NetLocalGroupAddMembers(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            0,
            (&member as *const LOCALGROUP_MEMBERS_INFO_0).cast::<u8>(),
            1,
        )
    };
    // SAFETY: freeing the SID the conversion allocated, once.
    unsafe {
        LocalFree(Some(HLOCAL(psid.0)));
    }
    if status == ERROR_MEMBER_IN_ALIAS {
        return Ok(false);
    }
    net_status(status).map(|()| true)
}

/// Removes a SID from a local group. Returns `false` when it was not a member.
pub fn local_group_remove_member(group: &str, sid: &str) -> io::Result<bool> {
    let name = wide(group);
    let text = wide(sid);
    let mut psid = PSID::default();
    // SAFETY: NUL-terminated string and valid out pointer; the SID is freed below.
    unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut psid) }.map_err(to_io)?;
    // SAFETY: valid group name and SID.
    let status = unsafe { NetLocalGroupDelMember(PCWSTR::null(), PCWSTR(name.as_ptr()), psid) };
    // SAFETY: freeing the SID the conversion allocated, once.
    unsafe {
        LocalFree(Some(HLOCAL(psid.0)));
    }
    if status == ERROR_NO_SUCH_MEMBER {
        return Ok(false);
    }
    net_status(status).map(|()| true)
}

/// Deletes a local group. Returns `false` when it did not exist.
pub fn local_group_delete(group: &str) -> io::Result<bool> {
    let name = wide(group);
    // SAFETY: valid NUL-terminated group name.
    let status = unsafe { NetLocalGroupDel(PCWSTR::null(), PCWSTR(name.as_ptr())) };
    if status == NERR_GROUP_NOT_FOUND {
        return Ok(false);
    }
    net_status(status).map(|()| true)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Runs code on a thread whose effective token has Administrators as "deny-only", which is
    //! exactly what an unelevated administrator looks like under UAC.
    use windows::Win32::Security::{
        CreateRestrictedToken, DuplicateTokenEx, SecurityImpersonation, TokenImpersonation,
        CREATE_RESTRICTED_TOKEN_FLAGS, SID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK, TOKEN_ASSIGN_PRIMARY,
        TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    };
    use windows::Win32::System::Threading::SetThreadToken;

    use super::*;

    pub const BUILTIN_ADMINISTRATORS: &str = "S-1-5-32-544";

    pub fn run_without_administrators<T: Send + 'static>(
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        std::thread::spawn(move || {
            let mut process = HANDLE::default();
            // SAFETY: valid pseudo handle and out pointer; the token is closed below.
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                    &mut process,
                )
            }
            .expect("open process token");

            let text = wide(BUILTIN_ADMINISTRATORS);
            let mut admins = PSID::default();
            // SAFETY: NUL-terminated string and valid out pointer; freed below.
            unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut admins) }
                .expect("convert SID");
            let disable = [SID_AND_ATTRIBUTES {
                Sid: admins,
                Attributes: 0,
            }];

            let mut restricted = HANDLE::default();
            // SAFETY: `disable` and the handles are valid; only the SID is turned deny-only.
            unsafe {
                CreateRestrictedToken(
                    process,
                    CREATE_RESTRICTED_TOKEN_FLAGS(0),
                    Some(&disable),
                    None,
                    None,
                    &mut restricted,
                )
            }
            .expect("create restricted token");

            let mut impersonation = HANDLE::default();
            // SAFETY: `restricted` is a valid primary token; the result is an impersonation token.
            unsafe {
                DuplicateTokenEx(
                    restricted,
                    TOKEN_ACCESS_MASK(TOKEN_IMPERSONATE.0 | TOKEN_QUERY.0),
                    None,
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut impersonation,
                )
            }
            .expect("duplicate token");

            // SAFETY: applies the token to this thread only; reverted below.
            unsafe { SetThreadToken(None, Some(impersonation)) }.expect("set thread token");
            let result = work();
            // SAFETY: reverts to the process token, then releases everything created above once.
            unsafe {
                let _ = SetThreadToken(None, None);
                let _ = CloseHandle(impersonation);
                let _ = CloseHandle(restricted);
                let _ = CloseHandle(process);
                LocalFree(Some(HLOCAL(admins.0)));
            }
            result
        })
        .join()
        .expect("restricted-token thread panicked")
    }
}

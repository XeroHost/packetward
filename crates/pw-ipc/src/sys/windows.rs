// SPDX-License-Identifier: GPL-3.0-or-later
//! Win32 plumbing for the named pipe: security descriptors, account/SID lookups and group
//! membership. Everything `unsafe` in `pw-ipc` lives here.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::iter::once;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupGetMembers, LOCALGROUP_MEMBERS_INFO_0,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    CheckTokenMembership, GetTokenInformation, LookupAccountNameW, TokenUser, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
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
    let mut found = false;
    if !buffer.is_null() {
        // SAFETY: on success `buffer` holds `read` LOCALGROUP_MEMBERS_INFO_0 entries.
        let members = unsafe {
            std::slice::from_raw_parts(buffer.cast::<LOCALGROUP_MEMBERS_INFO_0>(), read as usize)
        };
        for member in members {
            if sid_to_string(member.lgrmi0_sid)?.eq_ignore_ascii_case(sid) {
                found = true;
                break;
            }
        }
        // SAFETY: `buffer` was allocated by NetLocalGroupGetMembers and is freed once.
        unsafe {
            NetApiBufferFree(Some(buffer.cast_const().cast()));
        }
    }
    Ok(Some(found))
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

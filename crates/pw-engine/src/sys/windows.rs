// SPDX-License-Identifier: GPL-3.0-or-later
//! Win32 helpers of the engine: protecting folders that hold sensitive data.
#![allow(unsafe_code)]

use std::io;
use std::iter::once;
use std::path::Path;

use windows::core::{BOOL, PCWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

/// SYSTEM and Administrators only, inherited by everything created inside, no inheritance from the parent.
const PRIVATE_DIR_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(once(0)).collect()
}

/// Free bytes available to this process on the disk holding `dir`, or `None` if Windows does not answer.
pub fn free_disk_bytes(dir: &Path) -> Option<u64> {
    let path = wide(&dir.to_string_lossy());
    let mut available = 0u64;
    // SAFETY: `path` is a NUL-terminated UTF-16 string that outlives the call, and `available` is a valid
    // out pointer for the whole call; the other two out parameters are optional and passed as None.
    unsafe { GetDiskFreeSpaceExW(PCWSTR(path.as_ptr()), Some(&mut available), None, None) }
        .ok()
        .map(|()| available)
}

/// Replaces the folder's access list with "SYSTEM and Administrators: full control" and stops it
/// inheriting from `%ProgramData%` (where every user can read).
pub fn protect_dir(dir: &Path) -> io::Result<()> {
    let sddl = wide(PRIVATE_DIR_SDDL);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is NUL-terminated and outlives the call; `descriptor` is a valid out pointer.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(io::Error::other)?;

    let mut present = BOOL(0);
    let mut defaulted = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `descriptor` is a valid self-relative descriptor from the conversion above and the three
    // out pointers are valid for writes. The returned ACL points into `descriptor`, which stays alive
    // until the `LocalFree` below.
    let dacl_result =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) };

    let result = match dacl_result {
        Ok(()) if present.as_bool() && !dacl.is_null() => {
            let path = wide(&dir.to_string_lossy());
            // SAFETY: `path` is NUL-terminated and outlives the call; `dacl` is valid (see above).
            let status = unsafe {
                SetNamedSecurityInfoW(
                    PCWSTR(path.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(dacl),
                    None,
                )
            };
            if status.0 == 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(status.0 as i32))
            }
        }
        Ok(()) => Err(io::Error::other("the access list was empty")),
        Err(err) => Err(io::Error::other(err)),
    };
    // SAFETY: `descriptor` was allocated with LocalAlloc by the SDDL conversion and is freed once.
    unsafe {
        LocalFree(Some(HLOCAL(descriptor.0)));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_folder_can_be_protected_and_still_used_by_its_owner() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("private");
        std::fs::create_dir(&target).unwrap();
        protect_dir(&target).expect("the test runs as an administrator");
        std::fs::write(target.join("a.txt"), b"x").unwrap();
        assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"x");
    }
}

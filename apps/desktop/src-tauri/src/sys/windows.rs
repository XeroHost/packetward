// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Launching the agent executable with administrator rights (UAC prompt).
#![allow(unsafe_code)]

use std::io;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

const ERROR_CANCELLED: i32 = 1223;
/// Upper bound for an elevated agent command (service start can take a few seconds).
const WAIT_MS: u32 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevated {
    Exited(u32),
    /// The user declined the UAC prompt.
    Cancelled,
}

/// Runs `exe args` elevated through the `runas` verb and waits for it to finish.
pub fn run_elevated_and_wait(exe: &Path, args: &str) -> io::Result<Elevated> {
    let file: Vec<u16> = exe.as_os_str().encode_wide().chain(once(0)).collect();
    let parameters: Vec<u16> = args.encode_utf16().chain(once(0)).collect();
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: `info` is fully initialised and the strings it points to outlive the call.
    if let Err(err) = unsafe { ShellExecuteExW(&mut info) } {
        let code = (err.code().0 as u32 & 0xFFFF) as i32;
        return if code == ERROR_CANCELLED {
            Ok(Elevated::Cancelled)
        } else {
            Err(io::Error::from_raw_os_error(code))
        };
    }
    let process = info.hProcess;
    if process.is_invalid() {
        return Err(io::Error::other(
            "the elevated process handle was not returned",
        ));
    }
    // SAFETY: `process` is a valid process handle returned with SEE_MASK_NOCLOSEPROCESS.
    let waited = unsafe { WaitForSingleObject(process, WAIT_MS) };
    let result = if waited == WAIT_OBJECT_0 {
        let mut code = 0u32;
        // SAFETY: valid process handle and out pointer.
        unsafe { GetExitCodeProcess(process, &mut code) }
            .map(|()| Elevated::Exited(code))
            .map_err(io::Error::other)
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the elevated command did not finish in time",
        ))
    };
    // SAFETY: closing the handle we own, once.
    unsafe {
        let _ = CloseHandle(process);
    }
    result
}

/// Whether Windows draws transparency effects (Settings > Personalization > Colors). Mica is only
/// worth asking for when it is on; a missing value means the Windows default, which is on.
pub fn transparency_enabled() -> bool {
    use std::ffi::c_void;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};

    let mut data = 1u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: `data` and `size` are valid for writes and `size` is the byte size of `data`; both key
    // names are NUL-terminated literals.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"),
            w!("EnableTransparency"),
            RRF_RT_REG_DWORD,
            None,
            Some(std::ptr::from_mut(&mut data).cast::<c_void>()),
            Some(&mut size),
        )
    };
    status.is_err() || data != 0
}

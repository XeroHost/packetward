// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Runtime binding to Npcap's `wpcap.dll`. Nothing links against Npcap: the DLL is loaded with
//! `LoadLibraryExW` from its absolute path when a capture is opened, so the executable starts (and the
//! rest of PacketWard works) without Npcap installed. Npcap is never bundled (CLAUDE.md, licensing).
//!
//! Only the dozen libpcap functions this crate needs are resolved. The safe wrappers at the bottom are the
//! only API the rest of the crate sees.
//!
//! Not exercised by automated tests (the dev VPS has no Npcap and must not get one); written against the
//! documented libpcap/Npcap ABI and reviewed by hand.
#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::Path;
use std::sync::Arc;

use libloading::os::windows::{
    Library, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use crate::backend::LinkType;
use crate::error::CaptureError;

const ERRBUF_LEN: usize = 256;
const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -5;
const PCAP_ERROR_PERM_DENIED: c_int = -8;
const PCAP_NETMASK_UNKNOWN: u32 = 0xffff_ffff;
/// Kernel buffer used when the caller does not ask for one.
const DEFAULT_BUFFER_BYTES: u32 = 8 * 1024 * 1024;

/// `struct timeval` as Npcap's Windows headers define it: two 32-bit `long`s.
#[repr(C)]
struct Timeval {
    tv_sec: i32,
    tv_usec: i32,
}

/// `struct pcap_pkthdr`.
#[repr(C)]
struct PktHdr {
    ts: Timeval,
    caplen: u32,
    len: u32,
}

/// `struct bpf_program`.
#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *mut c_void,
}

type PcapT = c_void;

/// The resolved entry points. Holds the library so the function pointers stay valid.
struct Api {
    create: unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT,
    set_snaplen: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    set_promisc: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    set_timeout: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    set_buffer_size: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    activate: unsafe extern "C" fn(*mut PcapT) -> c_int,
    datalink: unsafe extern "C" fn(*mut PcapT) -> c_int,
    compile: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, u32) -> c_int,
    setfilter: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int,
    freecode: unsafe extern "C" fn(*mut BpfProgram),
    next_ex: unsafe extern "C" fn(*mut PcapT, *mut *mut PktHdr, *mut *const u8) -> c_int,
    stats: unsafe extern "C" fn(*mut PcapT, *mut c_void) -> c_int,
    geterr: unsafe extern "C" fn(*mut PcapT) -> *const c_char,
    close: unsafe extern "C" fn(*mut PcapT),
    _lib: Library,
}

macro_rules! symbol {
    ($lib:expr, $name:literal) => {{
        // SAFETY: the declared signature matches libpcap's documented prototype for this function.
        let sym = unsafe { $lib.get($name.as_bytes()) }.map_err(|e| CaptureError::Unavailable {
            reason: format!(
                "wpcap.dll does not export {}: {e}",
                $name.trim_end_matches('\0')
            ),
        })?;
        // Copy the raw function pointer out of the `Symbol`; `Api::_lib` keeps the library loaded.
        *sym
    }};
}

/// A loaded `wpcap.dll`.
pub(crate) struct Pcap {
    api: Arc<Api>,
}

impl Pcap {
    /// Loads the DLL from an absolute path. Its own dependencies (Npcap's `Packet.dll`) are searched in the
    /// same directory and in System32 only, never in the current directory or `PATH`.
    pub(crate) fn load(path: &Path) -> Result<Self, CaptureError> {
        if !path.is_absolute() {
            return Err(CaptureError::Unavailable {
                reason: "refusing to load wpcap.dll from a relative path".into(),
            });
        }
        // SAFETY: loading a DLL runs its initialisation code. The path is Npcap's own installation
        // directory under %SystemRoot%\System32, which only administrators can write to.
        let lib = unsafe {
            Library::load_with_flags(
                path,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }
        .map_err(|e| CaptureError::Unavailable {
            reason: format!(
                "Npcap was found but {} could not be loaded: {e}",
                path.display()
            ),
        })?;

        let api = Api {
            create: symbol!(lib, "pcap_create\0"),
            set_snaplen: symbol!(lib, "pcap_set_snaplen\0"),
            set_promisc: symbol!(lib, "pcap_set_promisc\0"),
            set_timeout: symbol!(lib, "pcap_set_timeout\0"),
            set_buffer_size: symbol!(lib, "pcap_set_buffer_size\0"),
            activate: symbol!(lib, "pcap_activate\0"),
            datalink: symbol!(lib, "pcap_datalink\0"),
            compile: symbol!(lib, "pcap_compile\0"),
            setfilter: symbol!(lib, "pcap_setfilter\0"),
            freecode: symbol!(lib, "pcap_freecode\0"),
            next_ex: symbol!(lib, "pcap_next_ex\0"),
            stats: symbol!(lib, "pcap_stats\0"),
            geterr: symbol!(lib, "pcap_geterr\0"),
            close: symbol!(lib, "pcap_close\0"),
            _lib: lib,
        };
        Ok(Self { api: Arc::new(api) })
    }

    /// Opens `device` (`\Device\NPF_{GUID}`) for capture.
    pub(crate) fn open(
        &self,
        device: &str,
        snaplen: u32,
        promiscuous: bool,
        timeout_ms: u32,
        buffer_bytes: u32,
        bpf: Option<&str>,
    ) -> Result<Handle, CaptureError> {
        let device_c = CString::new(device)
            .map_err(|_| CaptureError::InterfaceNotFound(device.replace('\0', "")))?;
        let mut errbuf = [0 as c_char; ERRBUF_LEN];
        // SAFETY: `device_c` is NUL-terminated and `errbuf` is the documented PCAP_ERRBUF_SIZE (256) bytes.
        let raw = unsafe { (self.api.create)(device_c.as_ptr(), errbuf.as_mut_ptr()) };
        if raw.is_null() {
            return Err(CaptureError::Source(format!(
                "pcap_create failed: {}",
                c_buf_to_string(&errbuf)
            )));
        }
        // From here on the handle is closed by `Drop`, also on the error paths below.
        let mut handle = Handle {
            api: Arc::clone(&self.api),
            raw,
            link: LinkType::Ethernet,
        };

        let buffer = if buffer_bytes == 0 {
            DEFAULT_BUFFER_BYTES
        } else {
            buffer_bytes
        };
        // SAFETY (all four calls): `handle.raw` is a live, not yet activated pcap_t.
        let setup = [
            unsafe { (self.api.set_snaplen)(raw, c_int::try_from(snaplen).unwrap_or(c_int::MAX)) },
            unsafe { (self.api.set_promisc)(raw, c_int::from(promiscuous)) },
            unsafe {
                (self.api.set_timeout)(raw, c_int::try_from(timeout_ms).unwrap_or(c_int::MAX))
            },
            unsafe {
                (self.api.set_buffer_size)(raw, c_int::try_from(buffer).unwrap_or(c_int::MAX))
            },
        ];
        if let Some(code) = setup.into_iter().find(|c| *c != 0) {
            return Err(handle.error("configuring the capture", code));
        }

        // SAFETY: `raw` is live and fully configured.
        let code = unsafe { (self.api.activate)(raw) };
        if code < 0 {
            return Err(handle.error("activating the capture", code));
        }

        // SAFETY: `raw` is an activated handle.
        let dlt = unsafe { (self.api.datalink)(raw) };
        // Wi-Fi monitor mode, tunnels, ... are not decoded by this crate.
        handle.link = LinkType::from_dlt(dlt).ok_or(CaptureError::Unsupported(
            "the adapter delivers a link type PacketWard cannot decode",
        ))?;

        if let Some(expr) = bpf {
            handle.set_filter(expr)?;
        }
        Ok(handle)
    }
}

/// An open, activated capture handle. Closed on drop.
pub(crate) struct Handle {
    api: Arc<Api>,
    raw: *mut PcapT,
    link: LinkType,
}

// SAFETY: a pcap_t may be used from any one thread at a time. `Handle` is moved into the capture thread
// and every method takes `&mut self` or `&self` from that single thread; it is never shared.
unsafe impl Send for Handle {}

/// What `Handle::next` produced.
pub(crate) enum Next<'a> {
    Frame {
        timestamp_ns: u64,
        data: &'a [u8],
        original_len: u32,
    },
    Timeout,
    Eof,
}

impl Handle {
    pub(crate) fn link_type(&self) -> LinkType {
        self.link
    }

    fn last_error(&self) -> String {
        // SAFETY: `raw` is live; pcap_geterr returns a NUL-terminated string owned by the handle.
        let ptr = unsafe { (self.api.geterr)(self.raw) };
        if ptr.is_null() {
            return String::new();
        }
        // SAFETY: non-null and NUL-terminated per the libpcap contract; copied out immediately.
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }

    fn error(&self, what: &str, code: c_int) -> CaptureError {
        match code {
            PCAP_ERROR_PERM_DENIED => CaptureError::AccessDenied,
            PCAP_ERROR_NO_SUCH_DEVICE => CaptureError::InterfaceNotFound(self.last_error()),
            _ => CaptureError::Source(format!("{what} failed ({code}): {}", self.last_error())),
        }
    }

    /// Compiles `expr` and installs it as the kernel filter.
    fn set_filter(&mut self, expr: &str) -> Result<(), CaptureError> {
        let expr_c = CString::new(expr)
            .map_err(|_| CaptureError::InvalidSettings("the filter contains a NUL byte".into()))?;
        let mut program = BpfProgram {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };
        // SAFETY: `raw` is live; `program` is a valid out-structure; `expr_c` is NUL-terminated.
        let code = unsafe {
            (self.api.compile)(
                self.raw,
                &mut program,
                expr_c.as_ptr(),
                1,
                PCAP_NETMASK_UNKNOWN,
            )
        };
        if code != 0 {
            return Err(CaptureError::InvalidSettings(format!(
                "Npcap rejected the filter {expr:?}: {}",
                self.last_error()
            )));
        }
        // SAFETY: `program` was filled in by a successful pcap_compile on this handle.
        let code = unsafe { (self.api.setfilter)(self.raw, &mut program) };
        let result = if code == 0 {
            Ok(())
        } else {
            Err(self.error("installing the filter", code))
        };
        // SAFETY: `program` came from pcap_compile and is freed exactly once; the kernel filter keeps its own copy.
        unsafe { (self.api.freecode)(&mut program) };
        result
    }

    /// Waits up to the configured read timeout for one packet.
    pub(crate) fn next(&mut self) -> Result<Next<'_>, CaptureError> {
        let mut header: *mut PktHdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        // SAFETY: `raw` is live; both out-pointers are valid locals.
        let code = unsafe { (self.api.next_ex)(self.raw, &mut header, &mut data) };
        match code {
            1 => {
                if header.is_null() || data.is_null() {
                    return Err(CaptureError::Source(
                        "pcap_next_ex returned a null packet".into(),
                    ));
                }
                // SAFETY: on success both pointers are valid until the next call on this handle; the
                // returned borrow is tied to `&mut self`, which prevents another call meanwhile.
                let (hdr, bytes) = unsafe {
                    let hdr = &*header;
                    (hdr, std::slice::from_raw_parts(data, hdr.caplen as usize))
                };
                let secs = u64::from(hdr.ts.tv_sec as u32);
                let micros = u64::from(hdr.ts.tv_usec as u32);
                Ok(Next::Frame {
                    timestamp_ns: secs
                        .saturating_mul(1_000_000_000)
                        .saturating_add(micros.saturating_mul(1_000)),
                    data: bytes,
                    original_len: hdr.len.max(hdr.caplen),
                })
            }
            0 => Ok(Next::Timeout),
            -2 => Ok(Next::Eof),
            other => Err(self.error("reading a packet", other)),
        }
    }

    /// Packets dropped by the kernel or the adapter since the capture started.
    pub(crate) fn drops(&self) -> u64 {
        // `struct pcap_stat` is three u32 on Windows (more in some builds); a generous zeroed buffer
        // makes the call safe either way.
        let mut stat = [0u32; 16];
        // SAFETY: `raw` is live and `stat` is larger than any pcap_stat definition.
        let code = unsafe { (self.api.stats)(self.raw, stat.as_mut_ptr().cast::<c_void>()) };
        if code == 0 {
            u64::from(stat[1]) + u64::from(stat[2])
        } else {
            0
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `raw` was returned by pcap_create, is closed exactly once, and not used afterwards.
        unsafe { (self.api.close)(self.raw) };
    }
}

fn c_buf_to_string(buf: &[c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

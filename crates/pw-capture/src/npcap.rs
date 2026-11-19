// SPDX-License-Identifier: GPL-3.0-or-later
//! The Npcap backend: best fidelity (Ethernet frames, BPF filters in the kernel, both directions).
//!
//! Npcap is **never bundled** (its free license forbids redistribution) and is not needed to start: this
//! module only *looks for* `%SystemRoot%\System32\Npcap\wpcap.dll`, and the DLL is loaded when a capture
//! is opened ([`crate::sys`], `libloading`). When it is absent the backend reports
//! [`Availability::Unavailable`](crate::Availability) with the download link, and
//! [`crate::select_backend`] falls back to the raw-socket backend.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::backend::{
    BackendCaps, BackendKind, CaptureBackend, CaptureOpts, InterfaceId, PacketSource,
};
use crate::error::CaptureError;
use crate::interfaces::{InterfaceProvider, SystemInterfaces};

#[cfg(windows)]
use crate::{
    backend::{Frame, LinkType, SourceEvent},
    interfaces::resolve_interface,
    sys::npcap::{Handle, Next, Pcap},
};

/// Where the installer of Npcap is published.
pub const NPCAP_URL: &str = "https://npcap.com";

/// Npcap's DLL under the given `SystemRoot` (`C:\Windows` when unknown).
pub fn npcap_dll_path(system_root: Option<&OsStr>) -> PathBuf {
    let root = system_root
        .filter(|r| !r.is_empty())
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    root.join("System32").join("Npcap").join("wpcap.dll")
}

/// The DLL of an installed Npcap, if present. Always `None` off Windows.
pub fn detect_npcap() -> Option<PathBuf> {
    if !cfg!(windows) {
        return None;
    }
    let path = npcap_dll_path(std::env::var_os("SystemRoot").as_deref());
    path.is_file().then_some(path)
}

pub struct NpcapBackend {
    dll: PathBuf,
    provider: Arc<dyn InterfaceProvider>,
}

impl NpcapBackend {
    /// A backend that will load `dll` (an absolute path to `wpcap.dll`) when a capture is opened.
    pub fn new(dll: PathBuf) -> Self {
        Self::with_interfaces(dll, Arc::new(SystemInterfaces))
    }

    pub fn with_interfaces(dll: PathBuf, provider: Arc<dyn InterfaceProvider>) -> Self {
        Self { dll, provider }
    }

    pub(crate) fn static_caps() -> BackendCaps {
        BackendCaps {
            kind: BackendKind::Npcap,
            link_layer: true,
            bpf: true,
            sees_outbound: true,
            ipv6: true,
            needs_admin: false,
        }
    }
}

impl CaptureBackend for NpcapBackend {
    fn caps(&self) -> BackendCaps {
        Self::static_caps()
    }

    #[cfg(not(windows))]
    fn open(
        &self,
        interface: &InterfaceId,
        opts: &CaptureOpts,
    ) -> Result<Box<dyn PacketSource>, CaptureError> {
        let _ = (interface, opts, &self.dll, &self.provider);
        Err(CaptureError::Unavailable {
            reason: "Npcap only exists on Windows".into(),
        })
    }

    #[cfg(windows)]
    fn open(
        &self,
        interface: &InterfaceId,
        opts: &CaptureOpts,
    ) -> Result<Box<dyn PacketSource>, CaptureError> {
        opts.validate()?;
        if !self.dll.is_file() {
            return Err(CaptureError::Unavailable {
                reason: format!("Npcap is not installed (get it from {NPCAP_URL})"),
            });
        }
        let info = resolve_interface(interface, self.provider.as_ref())?;
        let pcap = Pcap::load(&self.dll)?;
        // Only a filter that translates exactly is pushed to the kernel; the pipeline filters again.
        let bpf = opts.filter.as_ref().and_then(|f| f.to_bpf());
        let timeout_ms = u32::try_from(opts.read_timeout.as_millis()).unwrap_or(u32::MAX);
        let handle = pcap.open(
            &info.npcap_device(),
            opts.snaplen,
            opts.promiscuous,
            timeout_ms,
            opts.buffer_bytes,
            bpf.as_deref(),
        )?;
        Ok(Box::new(NpcapSource {
            handle,
            local: info.addrs,
        }))
    }
}

#[cfg(windows)]
struct NpcapSource {
    handle: Handle,
    local: Vec<std::net::IpAddr>,
}

#[cfg(windows)]
impl PacketSource for NpcapSource {
    fn link_type(&self) -> LinkType {
        self.handle.link_type()
    }

    fn local_addrs(&self) -> &[std::net::IpAddr] {
        &self.local
    }

    fn next(&mut self) -> Result<SourceEvent<'_>, CaptureError> {
        Ok(match self.handle.next()? {
            Next::Frame {
                timestamp_ns,
                data,
                original_len,
            } => SourceEvent::Frame(Frame {
                timestamp_ns,
                data,
                original_len,
            }),
            Next::Timeout => SourceEvent::Timeout,
            Next::Eof => SourceEvent::Eof,
        })
    }

    fn kernel_drops(&self) -> u64 {
        self.handle.drops()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dll_path_follows_system_root() {
        assert_eq!(
            npcap_dll_path(Some(OsStr::new(r"D:\WinNT"))),
            PathBuf::from(r"D:\WinNT")
                .join("System32")
                .join("Npcap")
                .join("wpcap.dll")
        );
        assert_eq!(
            npcap_dll_path(None),
            PathBuf::from(r"C:\Windows")
                .join("System32")
                .join("Npcap")
                .join("wpcap.dll")
        );
        assert_eq!(npcap_dll_path(Some(OsStr::new(""))), npcap_dll_path(None));
    }

    #[test]
    fn opening_without_the_dll_is_an_unavailable_error_not_a_crash() {
        let backend = NpcapBackend::new(PathBuf::from(r"Z:\definitely\missing\wpcap.dll"));
        let err = backend
            .open(&InterfaceId::new("eth0"), &CaptureOpts::default())
            .err()
            .unwrap();
        assert!(matches!(err, CaptureError::Unavailable { .. }), "{err}");
        let caps = backend.caps();
        assert!(caps.bpf && caps.link_layer && !caps.needs_admin);
    }
}

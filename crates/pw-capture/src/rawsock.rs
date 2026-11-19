// SPDX-License-Identifier: GPL-3.0-or-later
//! The built-in fallback backend: a Windows raw socket bound to the interface's IPv4 address with
//! `SIO_RCVALL` (`RCVALL_IPLEVEL`, so the adapter is not put in promiscuous mode).
//!
//! Properties, all visible in [`RawSocketBackend::caps`]: needs administrator rights (the agent has them);
//! IP level only (no Ethernet header, so frames are [`LinkType::RawIp`]); no kernel filter, the pipeline
//! filters in Rust; IPv4 only. Packets are delivered whole; truncation to the snap length happens where
//! they are stored. The kernel receive buffer is enlarged to ride out short stalls; what it still cannot
//! hold is lost silently by Windows, which a raw socket cannot report (`kernel_drops` stays 0).
//!
//! **Known limitation, measured on the dev VPS** (Windows Server 2025, Red Hat VirtIO adapter, Windows
//! Firewall on): with RDP and HTTPS traffic flowing, the socket delivered only *outbound* packets, none
//! inbound, with `RCVALL_IPLEVEL` and with `RCVALL_ON`, bound to the adapter's address. Inbound visibility
//! must be checked on every target machine (the live test prints the in/out split) before relying on this
//! backend to see attacks; Npcap does not have this problem.

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
    stamp::Stamper,
};

/// Receive buffer requested from the kernel.
#[cfg(windows)]
const RECV_BUFFER_BYTES: usize = 4 * 1024 * 1024;
/// Largest IP packet (65 535 bytes) fits.
#[cfg(windows)]
const READ_BUFFER_BYTES: usize = 65_536;

pub struct RawSocketBackend {
    provider: Arc<dyn InterfaceProvider>,
}

impl Default for RawSocketBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl RawSocketBackend {
    pub fn new() -> Self {
        Self::with_interfaces(Arc::new(SystemInterfaces))
    }

    pub fn with_interfaces(provider: Arc<dyn InterfaceProvider>) -> Self {
        Self { provider }
    }

    pub(crate) fn static_caps() -> BackendCaps {
        BackendCaps {
            kind: BackendKind::RawSocket,
            link_layer: false,
            bpf: false,
            sees_outbound: true,
            ipv6: false,
            needs_admin: true,
        }
    }
}

impl CaptureBackend for RawSocketBackend {
    fn caps(&self) -> BackendCaps {
        Self::static_caps()
    }

    #[cfg(not(windows))]
    fn open(
        &self,
        interface: &InterfaceId,
        opts: &CaptureOpts,
    ) -> Result<Box<dyn PacketSource>, CaptureError> {
        let _ = (interface, opts, &self.provider);
        Err(CaptureError::Unavailable {
            reason: "the raw-socket backend only exists on Windows".into(),
        })
    }

    #[cfg(windows)]
    fn open(
        &self,
        interface: &InterfaceId,
        opts: &CaptureOpts,
    ) -> Result<Box<dyn PacketSource>, CaptureError> {
        use std::net::{IpAddr, SocketAddr};

        use socket2::{Domain, Protocol, SockAddr, Socket, Type};

        opts.validate()?;
        let info = resolve_interface(interface, self.provider.as_ref())?;
        let address = info.ipv4_addrs().next().ok_or(CaptureError::Unsupported(
            "the raw-socket backend needs an IPv4 address on the interface",
        ))?;

        let denied = |e: std::io::Error| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                CaptureError::AccessDenied
            } else {
                CaptureError::Os(e)
            }
        };
        // IPPROTO_IP (0): every IP protocol, which is what SIO_RCVALL then delivers.
        let socket =
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(0))).map_err(denied)?;
        socket
            .bind(&SockAddr::from(SocketAddr::new(IpAddr::V4(address), 0)))
            .map_err(denied)?;
        crate::sys::windows::enable_rcvall(&socket).map_err(denied)?;
        if let Err(e) = socket.set_recv_buffer_size(RECV_BUFFER_BYTES) {
            tracing::debug!(error = %e, "could not enlarge the raw-socket receive buffer");
        }
        socket.set_read_timeout(Some(opts.read_timeout))?;

        Ok(Box::new(RawSocketSource {
            socket,
            buf: vec![0u8; READ_BUFFER_BYTES].into_boxed_slice(),
            local: info.addrs,
            stamper: Stamper::default(),
        }))
    }
}

#[cfg(windows)]
struct RawSocketSource {
    socket: socket2::Socket,
    buf: Box<[u8]>,
    local: Vec<std::net::IpAddr>,
    stamper: Stamper,
}

#[cfg(windows)]
impl PacketSource for RawSocketSource {
    fn link_type(&self) -> LinkType {
        LinkType::RawIp
    }

    fn local_addrs(&self) -> &[std::net::IpAddr] {
        &self.local
    }

    fn next(&mut self) -> Result<SourceEvent<'_>, CaptureError> {
        use std::io::{ErrorKind, Read};
        use std::time::{SystemTime, UNIX_EPOCH};

        match (&self.socket).read(&mut self.buf) {
            Ok(0) => Ok(SourceEvent::Timeout),
            Ok(n) => {
                // The tick counter is a plain memory read; the precise clock is only read once per tick.
                let timestamp_ns = self.stamper.stamp(crate::sys::windows::tick_ms(), || {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
                });
                Ok(SourceEvent::Frame(Frame {
                    timestamp_ns,
                    data: &self.buf[..n],
                    original_len: n as u32,
                }))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                ) =>
            {
                Ok(SourceEvent::Timeout)
            }
            Err(e) => Err(CaptureError::Source(format!("raw socket read failed: {e}"))),
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn is_unavailable_off_windows_and_never_panics() {
        let backend = RawSocketBackend::new();
        let err = backend
            .open(&InterfaceId::new("anything"), &CaptureOpts::default())
            .err()
            .unwrap();
        assert!(matches!(err, CaptureError::Unavailable { .. }));
        assert!(!backend.caps().bpf);
        assert!(backend.caps().needs_admin);
    }
}

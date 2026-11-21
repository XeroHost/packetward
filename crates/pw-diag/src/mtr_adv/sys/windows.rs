// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Windows sockets for UDP / TCP-SYN probes: ordinary (non-raw) sockets whose TTL / hop limit is
//! set before the first packet. Replies are *not* read here (Windows delivers neither ICMP
//! time-exceeded nor a SYN's fate to the socket); the capture side reads them. The only `unsafe`
//! is the `setsockopt` call.
#![allow(unsafe_code)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::windows::io::{AsRawSocket, RawSocket};

use tokio::net::TcpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use windows::Win32::Networking::WinSock::{
    setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_HOPS, IP_TTL, SOCKET,
    SOCKET_ERROR,
};

use crate::error::DiagError;
use crate::mtr_adv::capture::{BoundProbe, ProbeSender, SentProbe};
use crate::mtr_adv::{ModeUnavailable, ProbeMode, ProbeRequest, ReachKind};

/// [`ProbeSender`] using Winsock sockets.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsSender;

fn unspecified(target: IpAddr) -> SocketAddr {
    match target {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// Set `IP_TTL` (IPv4) or `IPV6_UNICAST_HOPS` (IPv6) on `socket`.
fn set_ttl(socket: RawSocket, v6: bool, ttl: u8) -> io::Result<()> {
    let value = i32::from(ttl).to_ne_bytes();
    let (level, name) = if v6 {
        (IPPROTO_IPV6.0, IPV6_UNICAST_HOPS)
    } else {
        (IPPROTO_IP.0, IP_TTL)
    };
    // SAFETY: `socket` is a live socket owned by the caller for the whole call; the option value
    // is a 4-byte int that outlives the call and whose length is passed with it.
    let rc = unsafe { setsockopt(SOCKET(socket as usize), level, name, Some(&value)) };
    if rc == SOCKET_ERROR {
        // SAFETY: plain thread-local error query, no arguments.
        let code = unsafe { WSAGetLastError() };
        Err(io::Error::from_raw_os_error(code.0))
    } else {
        Ok(())
    }
}

/// The bytes `ping.exe` would send: the alphabet, repeated.
fn payload(len: u16) -> Vec<u8> {
    (0..usize::from(len))
        .map(|i| b'a' + (i % 23) as u8)
        .collect()
}

impl ProbeSender for WindowsSender {
    fn availability(&self, _mode: ProbeMode, _target: IpAddr) -> Result<(), ModeUnavailable> {
        Ok(())
    }

    fn local_addr_for(&self, target: IpAddr) -> Result<IpAddr, DiagError> {
        // Connecting a UDP socket sends nothing; it only makes the OS pick the route.
        let socket = UdpSocket::bind(unspecified(target))?;
        socket.connect(SocketAddr::new(target, 9))?;
        Ok(socket.local_addr()?.ip())
    }

    fn bind(&self, request: &ProbeRequest) -> Result<Box<dyn BoundProbe>, DiagError> {
        let v6 = request.target.is_ipv6();
        let dest = SocketAddr::new(request.target, request.port);
        match request.mode {
            ProbeMode::Udp => {
                let socket = UdpSocket::bind(unspecified(request.target))?;
                set_ttl(socket.as_raw_socket(), v6, request.ttl)?;
                let local_port = socket.local_addr()?.port();
                Ok(Box::new(UdpBound {
                    socket,
                    dest,
                    data: payload(request.payload_size),
                    local_port,
                }))
            }
            ProbeMode::TcpSyn { .. } => {
                let socket = if v6 {
                    TcpSocket::new_v6()?
                } else {
                    TcpSocket::new_v4()?
                };
                socket.bind(unspecified(request.target))?;
                set_ttl(socket.as_raw_socket(), v6, request.ttl)?;
                let local_port = socket.local_addr()?.port();
                Ok(Box::new(TcpBound {
                    socket,
                    dest,
                    local_port,
                }))
            }
            ProbeMode::Icmp => Err(DiagError::InvalidInput(
                "ICMP probes do not use sockets".to_owned(),
            )),
        }
    }
}

struct UdpBound {
    socket: UdpSocket,
    dest: SocketAddr,
    data: Vec<u8>,
    local_port: u16,
}

impl BoundProbe for UdpBound {
    fn local_port(&self) -> u16 {
        self.local_port
    }

    fn fire(self: Box<Self>) -> Result<SentProbe, DiagError> {
        self.socket.send_to(&self.data, self.dest)?;
        Ok(SentProbe {
            early: None,
            guard: Box::new(self.socket),
        })
    }
}

struct TcpBound {
    socket: TcpSocket,
    dest: SocketAddr,
    local_port: u16,
}

/// Aborts the connect task when the probe finishes, which closes the socket and with it stops
/// SYN retransmissions.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl BoundProbe for TcpBound {
    fn local_port(&self) -> u16 {
        self.local_port
    }

    fn fire(self: Box<Self>) -> Result<SentProbe, DiagError> {
        let (tx, rx) = oneshot::channel();
        let TcpBound { socket, dest, .. } = *self;
        let task = tokio::spawn(async move {
            match socket.connect(dest).await {
                // Connected = SYN-ACK. The stream is dropped at once (the handshake is the probe).
                Ok(stream) => {
                    drop(stream);
                    let _ = tx.send(ReachKind::SynAck);
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    let _ = tx.send(ReachKind::Rst);
                }
                // Anything else (unreachable, aborted): the capture decides.
                Err(_) => {}
            }
        });
        Ok(SentProbe {
            early: Some(rx),
            guard: Box::new(AbortOnDrop(task)),
        })
    }
}

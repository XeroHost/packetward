// SPDX-License-Identifier: GPL-3.0-or-later
//! Win32 ICMP helper API backend (`IcmpSendEcho2Ex` / `Icmp6SendEcho2`): no raw sockets, no
//! administrator rights. Everything `unsafe` in `pw-diag` lives here.
//!
//! Each probe runs the synchronous form of the call (no event, no APC) on tokio's blocking pool,
//! so an in-flight probe is bounded by its timeout and abandoning the future (cancellation) just
//! lets that call finish in the background.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2Ex,
    ICMPV6_ECHO_REPLY_LH, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION,
};
use windows::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};
use windows::Win32::System::IO::IO_STATUS_BLOCK;

use crate::echo::{
    ip_status, reply_buffer_len, status_from_code, EchoReply, EchoRequest, EchoStatus, Pinger,
};
use crate::error::DiagError;

/// [`Pinger`] backed by the Windows ICMP helper API (IPv4 and IPv6).
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsPinger;

impl Pinger for WindowsPinger {
    async fn echo(&self, request: &EchoRequest) -> Result<EchoReply, DiagError> {
        let request = request.clamped();
        tokio::task::spawn_blocking(move || send_echo(&request))
            .await
            .map_err(|e| DiagError::System {
                code: 0,
                message: format!("ICMP worker failed: {e}"),
            })?
    }
}

/// Owns an `IcmpCreateFile` / `Icmp6CreateFile` handle.
struct IcmpHandle(HANDLE);

impl IcmpHandle {
    fn open(v6: bool) -> Result<Self, DiagError> {
        // SAFETY: both functions take no arguments and return a new handle or an error.
        let created = unsafe {
            if v6 {
                Icmp6CreateFile()
            } else {
                IcmpCreateFile()
            }
        };
        match created {
            Ok(h) => Ok(Self(h)),
            Err(e) => Err(DiagError::System {
                code: u32::try_from(e.code().0 & 0xFFFF).unwrap_or(0),
                message: format!("cannot open an ICMP handle: {e}"),
            }),
        }
    }
}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from IcmpCreateFile/Icmp6CreateFile and is closed exactly once.
        let _ = unsafe { IcmpCloseHandle(self.0) };
    }
}

/// The payload `ping.exe` sends: the alphabet, repeated.
fn payload(len: u16) -> Vec<u8> {
    (0..usize::from(len))
        .map(|i| b'a' + (i % 23) as u8)
        .collect()
}

fn is_ip_status(code: u32) -> bool {
    // IP_STATUS_BASE (11000) .. IP_GENERAL_FAILURE (11050) and a little beyond.
    (11000..11100).contains(&code)
}

fn send_echo(req: &EchoRequest) -> Result<EchoReply, DiagError> {
    let handle = IcmpHandle::open(req.target.is_ipv6())?;
    let data = payload(req.payload_size);
    let options = IP_OPTION_INFORMATION {
        Ttl: req.ttl,
        Tos: 0,
        Flags: 0,
        OptionsSize: 0,
        OptionsData: ptr::null_mut(),
    };
    let timeout_ms = u32::try_from(req.timeout.as_millis())
        .unwrap_or(u32::MAX)
        .max(1);
    let reply_struct = match req.target {
        IpAddr::V4(_) => size_of::<ICMP_ECHO_REPLY>(),
        IpAddr::V6(_) => size_of::<ICMPV6_ECHO_REPLY_LH>(),
    };
    let bytes = reply_buffer_len(reply_struct, data.len(), size_of::<IO_STATUS_BLOCK>());
    // u64 words keep the buffer 8-byte aligned for the reply structures.
    let mut buffer = vec![0u64; bytes.div_ceil(8)];
    let buffer_bytes = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
    let request_size = u16::try_from(data.len()).unwrap_or(u16::MAX);

    let started = Instant::now();
    let count = match req.target {
        IpAddr::V4(dest) => {
            // The address is passed as the u32 whose in-memory bytes are the octets.
            let dest = u32::from_ne_bytes(dest.octets());
            // SAFETY: `handle` is a valid ICMP handle; `data` and `buffer` outlive the call and
            // their sizes are passed alongside; no event/APC is given, so the call is synchronous
            // and finished when it returns.
            unsafe {
                IcmpSendEcho2Ex(
                    handle.0,
                    None,
                    None,
                    None,
                    0,
                    dest,
                    data.as_ptr().cast::<c_void>(),
                    request_size,
                    Some(&options),
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer_bytes,
                    timeout_ms,
                )
            }
        }
        IpAddr::V6(dest) => {
            let source = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                ..SOCKADDR_IN6::default()
            };
            let mut destination = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                ..SOCKADDR_IN6::default()
            };
            destination.sin6_addr.u.Byte = dest.octets();
            // SAFETY: as above; both SOCKADDR_IN6 values live across the call.
            unsafe {
                Icmp6SendEcho2(
                    handle.0,
                    None,
                    None,
                    None,
                    &source,
                    &destination,
                    data.as_ptr().cast::<c_void>(),
                    request_size,
                    Some(&options),
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer_bytes,
                    timeout_ms,
                )
            }
        }
    };
    let elapsed = started.elapsed();
    // Read the error immediately, before anything else can overwrite it.
    // SAFETY: GetLastError has no preconditions.
    let last_error = unsafe { GetLastError() }.0;

    let parsed = parse_reply(&buffer, req.target);
    if count == 0 {
        return failed_reply(last_error, elapsed, parsed);
    }
    match parsed {
        Some(p) => Ok(p.into_reply(elapsed)),
        None => Ok(EchoReply::timed_out()),
    }
}

/// What the first reply structure in the buffer says.
struct Parsed {
    status: u32,
    from: IpAddr,
    api_rtt_ms: u32,
    ttl: Option<u8>,
}

impl Parsed {
    fn into_reply(self, elapsed: Duration) -> EchoReply {
        let status = status_from_code(self.status);
        let rtt = match status {
            EchoStatus::TimedOut => None,
            _ => Some(elapsed.max(Duration::from_millis(u64::from(self.api_rtt_ms)))),
        };
        EchoReply {
            status,
            from: Some(self.from),
            rtt,
            ttl: self.ttl,
        }
    }
}

fn parse_reply(buffer: &[u64], target: IpAddr) -> Option<Parsed> {
    match target {
        IpAddr::V4(_) => {
            if buffer.len() * 8 < size_of::<ICMP_ECHO_REPLY>() {
                return None;
            }
            // SAFETY: the buffer is at least one reply structure long (checked above) and was
            // zero-initialised, so every bit pattern read here is initialised; read_unaligned
            // copies the plain-old-data struct out. The embedded `Data` pointer is not followed.
            let r: ICMP_ECHO_REPLY =
                unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<ICMP_ECHO_REPLY>()) };
            if r.Address == 0 && r.Status == 0 && r.RoundTripTime == 0 {
                return None;
            }
            Some(Parsed {
                status: r.Status,
                from: IpAddr::V4(Ipv4Addr::from(r.Address.to_ne_bytes())),
                api_rtt_ms: r.RoundTripTime,
                ttl: Some(r.Options.Ttl),
            })
        }
        IpAddr::V6(_) => {
            if buffer.len() * 8 < size_of::<ICMPV6_ECHO_REPLY_LH>() {
                return None;
            }
            // SAFETY: as for IPv4.
            let r: ICMPV6_ECHO_REPLY_LH =
                unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>()) };
            let words = r.Address.sin6_addr;
            let status = r.Status;
            let rtt = r.RoundTripTime;
            if words == [0u16; 8] && status == 0 && rtt == 0 {
                return None;
            }
            let mut octets = [0u8; 16];
            for (i, w) in words.iter().enumerate() {
                // The words hold the address bytes in memory (network) order.
                octets[2 * i..2 * i + 2].copy_from_slice(&w.to_ne_bytes());
            }
            Some(Parsed {
                status,
                from: IpAddr::V6(Ipv6Addr::from(octets)),
                api_rtt_ms: rtt,
                ttl: None, // the ICMPv6 API does not report the hop limit
            })
        }
    }
}

/// The call returned 0: a timeout, an ICMP error (TTL exceeded, unreachable) or a real failure.
fn failed_reply(
    last_error: u32,
    elapsed: Duration,
    parsed: Option<Parsed>,
) -> Result<EchoReply, DiagError> {
    if last_error == ip_status::REQ_TIMED_OUT {
        return Ok(EchoReply::timed_out());
    }
    if is_ip_status(last_error) {
        // TTL-exceeded and unreachable answers may arrive as "0 replies + error code" with the
        // reply structure still filled in; use it when it agrees with the code.
        let from = parsed.filter(|p| p.status == last_error).map(|p| p.from);
        return Ok(EchoReply {
            status: status_from_code(last_error),
            from,
            rtt: Some(elapsed),
            ttl: None,
        });
    }
    Err(DiagError::System {
        code: last_error,
        message: "the ICMP echo request failed".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancel::CancelToken;
    use crate::mtr::{mtr, MtrOptions};
    use crate::names::NameCache;
    use crate::ping::{ping, PingOptions};
    use crate::sink::NullSink;
    use std::sync::Arc;

    fn loopback_v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    #[tokio::test]
    async fn ping_loopback_v4() {
        let cancel = CancelToken::new();
        let opts = PingOptions {
            count: 3,
            timeout: Duration::from_secs(2),
            interval: Duration::from_millis(200),
            ..PingOptions::default()
        };
        let s = ping(&WindowsPinger, loopback_v4(), &opts, &cancel, &mut NullSink).await;
        assert_eq!(s.sent, 3);
        assert_eq!(s.received, 3, "{s:?}");
        assert!(s.loss_percent.abs() < f64::EPSILON);
        let rtt = s.rtt.unwrap();
        assert!(rtt.max_ms < 1000.0);
    }

    #[tokio::test]
    async fn echo_loopback_v4_reports_ttl_and_source() {
        let req = EchoRequest {
            target: loopback_v4(),
            ttl: 64,
            payload_size: 32,
            timeout: Duration::from_secs(2),
        };
        let r = WindowsPinger.echo(&req).await.unwrap();
        assert_eq!(r.status, EchoStatus::Success);
        assert_eq!(r.from, Some(loopback_v4()));
        assert!(r.ttl.is_some());
        assert!(r.rtt.is_some());
    }

    #[tokio::test]
    async fn ping_loopback_v6() {
        let target = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let req = EchoRequest {
            target,
            ttl: 64,
            payload_size: 32,
            timeout: Duration::from_secs(2),
        };
        let r = WindowsPinger.echo(&req).await.unwrap();
        assert_eq!(r.status, EchoStatus::Success, "{r:?}");
        assert_eq!(r.from, Some(target));
        assert_eq!(r.ttl, None);
    }

    #[tokio::test]
    async fn mtr_loopback_reaches_destination_at_hop_one() {
        let cancel = CancelToken::new();
        let opts = MtrOptions {
            cycles: 3,
            interval: Duration::from_millis(200),
            timeout: Duration::from_secs(1),
            ..MtrOptions::default()
        };
        let snap = mtr(
            Arc::new(WindowsPinger),
            loopback_v4(),
            &opts,
            &NameCache::disabled(),
            &cancel,
            &mut NullSink,
        )
        .await
        .unwrap();
        assert!(snap.destination_reached, "{snap:?}");
        assert_eq!(snap.hops.len(), 1);
        assert_eq!(snap.hops[0].received, 3);
        assert_eq!(snap.cycle, 3);
    }

    #[tokio::test]
    async fn large_payload_and_ttl_one_do_not_overflow_the_buffer() {
        let req = EchoRequest {
            target: loopback_v4(),
            ttl: 1,
            payload_size: 1472,
            timeout: Duration::from_secs(2),
        };
        let r = WindowsPinger.echo(&req).await.unwrap();
        assert_eq!(r.status, EchoStatus::Success);
    }

    /// Exercises the TTL-exceeded path, which loopback cannot. Sends a handful of ICMP echoes
    /// towards a public resolver, so it is opt-in:
    /// `cargo test -p pw-diag -- --ignored mtr_live --nocapture`.
    #[tokio::test]
    #[ignore = "sends ICMP towards the internet"]
    async fn mtr_live_shows_ttl_exceeded_hops() {
        let opts = MtrOptions {
            cycles: 2,
            max_hops: 6,
            interval: Duration::from_millis(200),
            ..MtrOptions::default()
        };
        let snap = mtr(
            Arc::new(WindowsPinger),
            "1.1.1.1".parse().unwrap(),
            &opts,
            &NameCache::disabled(),
            &CancelToken::new(),
            &mut NullSink,
        )
        .await
        .unwrap();
        println!("{snap:#?}");
        let first = &snap.hops[0];
        assert!(
            first.addr.is_some(),
            "hop 1 should answer TTL exceeded: {first:?}"
        );
        assert_ne!(first.addr, Some("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn payload_pattern() {
        assert_eq!(payload(0).len(), 0);
        assert_eq!(&payload(3), b"abc");
        assert_eq!(payload(24)[23], b'a');
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Remote port check: one TCP connect test or one best-effort UDP probe against one port.
//!
//! This is a diagnostic ("is my service reachable from here?"), not a scanner, so the guardrails
//! are deliberate: a single port per call (port 0 is refused), the timeout is capped at 10 s, no
//! payload is ever sent over TCP, and [`PortCheckLimiter`] bounds how many checks run at once.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::error::DiagError;

/// Longest timeout a port check accepts.
pub const MAX_PORT_TIMEOUT: Duration = Duration::from_secs(10);
/// Shortest timeout a port check accepts.
pub const MIN_PORT_TIMEOUT: Duration = Duration::from_millis(100);
/// Default number of checks a [`PortCheckLimiter`] lets run at once.
pub const DEFAULT_CONCURRENCY: usize = 8;
/// Largest limit [`PortCheckLimiter::new`] accepts.
pub const MAX_CONCURRENCY: usize = 16;
/// Most addresses of one host tried by a TCP check.
const MAX_ADDRS: usize = 4;

/// What a check found out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    /// TCP: the connection was accepted. UDP: a reply came back.
    Open,
    /// Actively refused: a TCP reset, or an ICMP port-unreachable for UDP.
    Closed,
    /// TCP only: no answer at all within the timeout (typically a firewall dropping packets).
    Filtered,
    /// UDP only: no reply and no error. The port may be open (the service ignored the probe) or
    /// filtered; UDP cannot tell the two apart.
    Inconclusive,
    /// The check itself failed (unresolvable name, no route, ...).
    Error(String),
}

/// Transport of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortProtocol {
    /// TCP connect test.
    Tcp,
    /// UDP probe.
    Udp,
}

/// The result of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortCheck {
    /// Host as given.
    pub host: String,
    /// Port checked.
    pub port: u16,
    /// TCP or UDP.
    pub protocol: PortProtocol,
    /// Verdict.
    pub state: PortState,
    /// The address that decided the verdict, when one was reached.
    pub remote: Option<SocketAddr>,
    /// Wall time of the whole check (including name resolution).
    pub elapsed: Duration,
}

/// Force a timeout into `100 ms..=10 s`.
pub fn effective_timeout(timeout: Duration) -> Duration {
    timeout.clamp(MIN_PORT_TIMEOUT, MAX_PORT_TIMEOUT)
}

/// Reject requests that must never be sent.
pub fn validate_target(host: &str, port: u16) -> Result<(), DiagError> {
    if port == 0 {
        return Err(DiagError::InvalidInput(
            "port 0 cannot be checked".to_owned(),
        ));
    }
    let host = host.trim();
    if host.is_empty() {
        return Err(DiagError::InvalidInput("the host is empty".to_owned()));
    }
    if host.len() > 253 {
        return Err(DiagError::InvalidInput(
            "the host name is too long".to_owned(),
        ));
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '@' | '?' | '#'))
    {
        return Err(DiagError::InvalidInput(
            "the host must be a bare name or IP address".to_owned(),
        ));
    }
    Ok(())
}

/// Verdict for a failed TCP connect attempt.
pub fn classify_connect_error(e: &io::Error) -> PortState {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => PortState::Closed,
        io::ErrorKind::TimedOut => PortState::Filtered,
        _ => PortState::Error(e.to_string()),
    }
}

/// Verdict for a failed UDP send/receive. A connected UDP socket reports an ICMP port-unreachable
/// as "connection reset" on Windows and "connection refused" elsewhere.
pub fn classify_udp_error(e: &io::Error) -> PortState {
    match e.kind() {
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused => PortState::Closed,
        _ => PortState::Error(e.to_string()),
    }
}

/// Pick the most informative verdict when a host has several addresses:
/// Open > Closed > Filtered > Error. `None` when the list is empty.
pub fn best_state(states: impl IntoIterator<Item = PortState>) -> Option<PortState> {
    fn rank(s: &PortState) -> u8 {
        match s {
            PortState::Open => 4,
            PortState::Closed => 3,
            PortState::Filtered | PortState::Inconclusive => 2,
            PortState::Error(_) => 1,
        }
    }
    states.into_iter().fold(None, |best, s| match best {
        Some(b) if rank(&b) >= rank(&s) => Some(b),
        _ => Some(s),
    })
}

async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let host = host.trim();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for a in lookup_host((host, port))
        .await
        .map_err(|e| format!("could not resolve {host}: {e}"))?
    {
        if !addrs.contains(&a) {
            addrs.push(a);
        }
    }
    addrs.truncate(MAX_ADDRS);
    if addrs.is_empty() {
        return Err(format!("{host} has no addresses"));
    }
    Ok(addrs)
}

/// TCP connect test of `host:port`. The connection is closed again at once; nothing is sent.
///
/// Returns `Err` only for refused requests (port 0, malformed host). A host that cannot be
/// resolved is reported as `PortState::Error` in the result. The timeout covers name resolution
/// and all connection attempts together.
pub async fn tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<PortCheck, DiagError> {
    validate_target(host, port)?;
    let started = Instant::now();
    let deadline = started + effective_timeout(timeout);
    let mk = |state: PortState, remote: Option<SocketAddr>| PortCheck {
        host: host.trim().to_owned(),
        port,
        protocol: PortProtocol::Tcp,
        state,
        remote,
        elapsed: started.elapsed(),
    };

    let addrs = match tokio::time::timeout_at(deadline, resolve(host, port)).await {
        Ok(Ok(a)) => a,
        Ok(Err(msg)) => return Ok(mk(PortState::Error(msg), None)),
        Err(_) => return Ok(mk(PortState::Filtered, None)),
    };

    let total = addrs.len();
    let mut verdicts: Vec<(PortState, SocketAddr)> = Vec::new();
    for (i, addr) in addrs.into_iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        // Share what is left fairly, so a dead first address cannot starve the others.
        let left = u32::try_from(total - i).unwrap_or(1).max(1);
        let state = match tokio::time::timeout(remaining / left, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                drop(stream);
                PortState::Open
            }
            Ok(Err(e)) => classify_connect_error(&e),
            Err(_) => PortState::Filtered,
        };
        let done = state == PortState::Open;
        verdicts.push((state, addr));
        if done {
            break;
        }
    }

    let Some(best) = best_state(verdicts.iter().map(|(s, _)| s.clone())) else {
        return Ok(mk(PortState::Filtered, None));
    };
    let remote = verdicts.iter().find(|(s, _)| *s == best).map(|(_, a)| *a);
    Ok(mk(best, remote))
}

/// Best-effort UDP probe of `host:port`: one empty datagram, then wait for any reply.
///
/// * a reply: [`PortState::Open`];
/// * an ICMP port-unreachable: [`PortState::Closed`];
/// * silence: [`PortState::Inconclusive`] (never "open" and never "closed").
///
/// Only the first resolved address is probed. Same refusal rules and timeout as
/// [`tcp_connect`].
pub async fn udp_check(host: &str, port: u16, timeout: Duration) -> Result<PortCheck, DiagError> {
    validate_target(host, port)?;
    let started = Instant::now();
    let deadline = started + effective_timeout(timeout);
    let mk = |state: PortState, remote: Option<SocketAddr>| PortCheck {
        host: host.trim().to_owned(),
        port,
        protocol: PortProtocol::Udp,
        state,
        remote,
        elapsed: started.elapsed(),
    };

    let addr = match tokio::time::timeout_at(deadline, resolve(host, port)).await {
        Ok(Ok(a)) => a[0],
        Ok(Err(msg)) => return Ok(mk(PortState::Error(msg), None)),
        Err(_) => return Ok(mk(PortState::Inconclusive, None)),
    };

    let bind: SocketAddr = if addr.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let probe = async {
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(addr).await?;
        socket.send(&[]).await?;
        let mut buf = [0u8; 2048];
        socket.recv(&mut buf).await
    };
    let state = match tokio::time::timeout_at(deadline, probe).await {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(e)) => classify_udp_error(&e),
        Err(_) => PortState::Inconclusive,
    };
    Ok(mk(state, Some(addr)))
}

/// Bounds how many port checks run at the same time (share one limiter, clone it freely).
#[derive(Debug, Clone)]
pub struct PortCheckLimiter {
    semaphore: Arc<Semaphore>,
    limit: usize,
}

impl Default for PortCheckLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_CONCURRENCY)
    }
}

impl PortCheckLimiter {
    /// At most `limit` checks at once (clamped to `1..=16`).
    pub fn new(limit: usize) -> Self {
        let limit = limit.clamp(1, MAX_CONCURRENCY);
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
            limit,
        }
    }

    /// The effective limit.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Wait for a free slot. The slot is released when the permit is dropped.
    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, DiagError> {
        // The semaphore is never closed, so this cannot fail in practice.
        Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| DiagError::System {
                code: 0,
                message: "the port-check limiter was closed".to_owned(),
            })
    }

    /// [`tcp_connect`] under the limit.
    pub async fn tcp_connect(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<PortCheck, DiagError> {
        validate_target(host, port)?;
        let _permit = self.acquire().await?;
        tcp_connect(host, port, timeout).await
    }

    /// [`udp_check`] under the limit.
    pub async fn udp_check(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<PortCheck, DiagError> {
        validate_target(host, port)?;
        let _permit = self.acquire().await?;
        udp_check(host, port, timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    const LOCAL: &str = "127.0.0.1";

    #[test]
    fn guardrails() {
        assert!(validate_target(LOCAL, 0).is_err());
        assert!(validate_target("", 80).is_err());
        assert!(validate_target("  ", 80).is_err());
        assert!(validate_target("a b", 80).is_err());
        assert!(validate_target("http://example.com", 80).is_err());
        assert!(validate_target("user@example.com", 80).is_err());
        assert!(validate_target(&"a".repeat(254), 80).is_err());
        assert!(validate_target("example.com", 443).is_ok());
        assert!(validate_target("2001:db8::1", 443).is_ok());
        assert_eq!(
            effective_timeout(Duration::from_secs(600)),
            MAX_PORT_TIMEOUT
        );
        assert_eq!(effective_timeout(Duration::ZERO), MIN_PORT_TIMEOUT);
        assert_eq!(
            effective_timeout(Duration::from_secs(3)),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn classification() {
        let k = |kind| io::Error::from(kind);
        assert_eq!(
            classify_connect_error(&k(io::ErrorKind::ConnectionRefused)),
            PortState::Closed
        );
        assert_eq!(
            classify_connect_error(&k(io::ErrorKind::TimedOut)),
            PortState::Filtered
        );
        assert!(matches!(
            classify_connect_error(&k(io::ErrorKind::NetworkUnreachable)),
            PortState::Error(_)
        ));
        assert_eq!(
            classify_udp_error(&k(io::ErrorKind::ConnectionReset)),
            PortState::Closed
        );
        assert_eq!(
            classify_udp_error(&k(io::ErrorKind::ConnectionRefused)),
            PortState::Closed
        );
        assert!(matches!(
            classify_udp_error(&k(io::ErrorKind::PermissionDenied)),
            PortState::Error(_)
        ));
    }

    #[test]
    fn best_state_prefers_informative_verdicts() {
        use PortState::*;
        assert_eq!(
            best_state([Filtered, Closed, Error("x".into())]),
            Some(Closed)
        );
        assert_eq!(best_state([Error("x".into()), Filtered]), Some(Filtered));
        assert_eq!(best_state([Closed, Open, Filtered]), Some(Open));
        assert_eq!(best_state([]), None);
    }

    #[tokio::test]
    async fn refuses_port_zero_and_bad_hosts_without_touching_the_network() {
        assert!(matches!(
            tcp_connect(LOCAL, 0, Duration::from_secs(1)).await,
            Err(DiagError::InvalidInput(_))
        ));
        assert!(matches!(
            udp_check(LOCAL, 0, Duration::from_secs(1)).await,
            Err(DiagError::InvalidInput(_))
        ));
        assert!(matches!(
            tcp_connect("", 80, Duration::from_secs(1)).await,
            Err(DiagError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn tcp_open_on_loopback_listener() {
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let r = tcp_connect(LOCAL, port, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(r.state, PortState::Open);
        assert_eq!(r.protocol, PortProtocol::Tcp);
        assert_eq!(
            r.remote,
            Some(SocketAddr::new(LOCAL.parse().unwrap(), port))
        );
        assert!(r.elapsed < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn tcp_closed_on_loopback_port_nobody_listens_on() {
        let port = {
            let l = TcpListener::bind((LOCAL, 0)).await.unwrap();
            l.local_addr().unwrap().port()
        };
        // Windows retries the SYN after a reset, so a refusal can take about 2 s to be reported.
        let r = tcp_connect(LOCAL, port, Duration::from_secs(8))
            .await
            .unwrap();
        assert_eq!(r.state, PortState::Closed, "{r:?}");
    }

    #[tokio::test]
    async fn tcp_unresolvable_host_is_an_error_result_not_a_panic() {
        // The reserved `.invalid` TLD never resolves (RFC 6761); the lookup stays local or fails fast.
        let r = tcp_connect("nonexistent.invalid", 80, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(
            matches!(r.state, PortState::Error(_) | PortState::Filtered),
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn udp_reply_means_open() {
        let server = UdpSocket::bind((LOCAL, 0)).await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            if let Ok((_, peer)) = server.recv_from(&mut buf).await {
                let _ = server.send_to(b"pong", peer).await;
            }
        });
        let r = udp_check(LOCAL, port, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(r.state, PortState::Open);
        assert_eq!(r.protocol, PortProtocol::Udp);
    }

    #[tokio::test]
    async fn udp_silence_is_inconclusive() {
        let server = UdpSocket::bind((LOCAL, 0)).await.unwrap();
        let port = server.local_addr().unwrap().port();
        let r = udp_check(LOCAL, port, Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(r.state, PortState::Inconclusive);
        assert!(r.elapsed >= Duration::from_millis(100));
        drop(server);
    }

    #[tokio::test]
    async fn udp_port_unreachable_means_closed() {
        let port = {
            let s = UdpSocket::bind((LOCAL, 0)).await.unwrap();
            s.local_addr().unwrap().port()
        };
        let r = udp_check(LOCAL, port, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(r.state, PortState::Closed, "{r:?}");
    }

    #[tokio::test]
    async fn limiter_bounds_concurrency() {
        let limiter = PortCheckLimiter::new(2);
        assert_eq!(limiter.limit(), 2);
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (l, a, p) = (limiter.clone(), Arc::clone(&active), Arc::clone(&peak));
            tasks.push(tokio::spawn(async move {
                let _permit = l.acquire().await.unwrap();
                let now = a.fetch_add(1, Ordering::SeqCst) + 1;
                p.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                a.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(PortCheckLimiter::new(0).limit(), 1);
        assert_eq!(PortCheckLimiter::new(1000).limit(), MAX_CONCURRENCY);
        assert_eq!(PortCheckLimiter::default().limit(), DEFAULT_CONCURRENCY);
    }

    #[tokio::test]
    async fn limiter_wrappers_validate_first() {
        let limiter = PortCheckLimiter::new(1);
        assert!(limiter
            .tcp_connect(LOCAL, 0, Duration::from_secs(1))
            .await
            .is_err());
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let r = limiter
            .tcp_connect(LOCAL, port, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(r.state, PortState::Open);
    }
}

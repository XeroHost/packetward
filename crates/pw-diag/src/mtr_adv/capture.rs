// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! UDP and TCP-SYN probes: send with a normal socket (given TTL), read the answers from a capture
//! source.
//!
//! An ordinary socket never sees ICMP *time exceeded* for its own datagram / SYN, so the replies
//! are read from a `pw_capture::PacketSource` (Npcap, or the raw-socket backend) by one thread
//! per transport, parsed by [`super::wire`] and matched to the pending probe by local port,
//! destination address and destination port. The OS part (bind a socket, set the TTL, send) is
//! behind [`ProbeSender`], so everything else runs against fakes on any platform.
//!
//! Matching rules (see [`super::wire`] for the frame parsing):
//!
//! | Mode | Hop answers | Destination answers |
//! |---|---|---|
//! | UDP | ICMP time-exceeded quoting our datagram | ICMP port-unreachable from the target |
//! | TCP SYN | ICMP time-exceeded quoting our SYN | SYN-ACK or RST from the target (also learned from the OS `connect()` result, which works even when the capture misses inbound packets) |
//!
//! The pending table is bounded ([`MAX_PENDING_PROBES`]); a probe that is cancelled or times out
//! drops its socket (so Windows stops retransmitting a SYN) and removes its entry.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use pw_capture::{CaptureBackend, CaptureOpts, InterfaceId, LinkType, PacketSource, SourceEvent};
use tokio::sync::oneshot;
use tokio::time::Instant;

use super::wire::{parse_frame, IcmpErrorKind, TcpReplyKind, WireEvent, WireProto};
use super::{
    sys, ModeUnavailable, MtrError, PingerTransport, ProbeMode, ProbeReply, ProbeRequest,
    ProbeTransport, ReachKind,
};
use crate::error::DiagError;
use crate::sys::SystemPinger;

/// Most probes awaiting an answer at once (a run uses at most 16; this is the hard bound).
pub const MAX_PENDING_PROBES: usize = 256;
/// How long the capture thread blocks per read; bounds how long stopping it takes.
const CAPTURE_READ_TIMEOUT: Duration = Duration::from_millis(100);

/// A probe the OS has accepted but not yet sent: its local port is known so the answer can be
/// matched before a single byte leaves the machine.
pub trait BoundProbe: Send {
    /// Local port the probe will be sent from.
    fn local_port(&self) -> u16;
    /// Transmit it.
    fn fire(self: Box<Self>) -> Result<SentProbe, DiagError>;
}

/// What the sender hands back after transmitting.
pub struct SentProbe {
    /// An answer the OS itself learned about (the result of a TCP `connect()`: connected means
    /// SYN-ACK, refused means RST). Optional; the capture match is the primary source.
    pub early: Option<oneshot::Receiver<ReachKind>>,
    /// Keeps the socket / task alive; dropped when the probe finishes (this releases the port
    /// and stops SYN retransmission).
    pub guard: Box<dyn Send>,
}

/// The OS-specific half of UDP / TCP probes: sockets with a chosen TTL. Implemented by
/// [`sys::SocketSender`] on Windows and by fakes in tests.
pub trait ProbeSender: Send + Sync + 'static {
    /// Can this sender do `mode` towards `target` at all (right OS, right address family)?
    fn availability(&self, mode: ProbeMode, target: IpAddr) -> Result<(), ModeUnavailable>;
    /// The local address the OS would use to reach `target` (identifies the capture interface).
    fn local_addr_for(&self, target: IpAddr) -> Result<IpAddr, DiagError>;
    /// Create the socket for `request` (bound, TTL set) without sending anything.
    fn bind(&self, request: &ProbeRequest) -> Result<Box<dyn BoundProbe>, DiagError>;
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a matched frame said.
#[derive(Debug, Clone, Copy)]
enum Matched {
    Icmp { from: IpAddr, kind: IcmpErrorKind },
    Tcp { from: IpAddr, kind: TcpReplyKind },
}

struct Pending {
    target: IpAddr,
    dst_port: u16,
    tx: oneshot::Sender<Matched>,
}

#[derive(Default)]
struct Registry {
    map: Mutex<HashMap<(WireProto, u16), Pending>>,
}

impl Registry {
    fn register(
        self: &Arc<Self>,
        proto: WireProto,
        local_port: u16,
        pending: Pending,
    ) -> Result<PendingGuard, DiagError> {
        let mut map = lock(&self.map);
        if map.len() >= MAX_PENDING_PROBES {
            return Err(DiagError::InvalidInput(
                "too many probes in flight".to_owned(),
            ));
        }
        map.insert((proto, local_port), pending);
        Ok(PendingGuard {
            registry: Arc::clone(self),
            key: (proto, local_port),
        })
    }

    fn dispatch(&self, event: WireEvent) {
        let mut map = lock(&self.map);
        match event {
            WireEvent::IcmpError { from, kind, quoted } => {
                let key = (quoted.proto, quoted.src_port);
                let hit = map
                    .get(&key)
                    .is_some_and(|p| p.target == quoted.dst && p.dst_port == quoted.dst_port);
                if hit {
                    if let Some(p) = map.remove(&key) {
                        let _ = p.tx.send(Matched::Icmp { from, kind });
                    }
                }
            }
            WireEvent::TcpReply {
                from,
                src_port,
                dst_port,
                kind,
            } => {
                let key = (WireProto::Tcp, dst_port);
                let hit = map
                    .get(&key)
                    .is_some_and(|p| p.target == from && p.dst_port == src_port);
                if hit {
                    if let Some(p) = map.remove(&key) {
                        let _ = p.tx.send(Matched::Tcp { from, kind });
                    }
                }
            }
        }
    }

    fn clear(&self) {
        lock(&self.map).clear();
    }
}

struct PendingGuard {
    registry: Arc<Registry>,
    key: (WireProto, u16),
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        lock(&self.registry.map).remove(&self.key);
    }
}

/// One capture thread feeding a [`Registry`].
struct Listener {
    registry: Arc<Registry>,
    stop: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    local: IpAddr,
}

impl Listener {
    fn start(mut source: Box<dyn PacketSource>, local: IpAddr) -> std::io::Result<Self> {
        let registry = Arc::new(Registry::default());
        let stop = Arc::new(AtomicBool::new(false));
        let alive = Arc::new(AtomicBool::new(true));
        let (r, s, a) = (Arc::clone(&registry), Arc::clone(&stop), Arc::clone(&alive));
        std::thread::Builder::new()
            .name("pw-diag-probe-rx".to_owned())
            .spawn(move || {
                let link: LinkType = source.link_type();
                while !s.load(Ordering::Relaxed) {
                    match source.next() {
                        Ok(SourceEvent::Frame(frame)) => {
                            if let Some(event) = parse_frame(link, frame.data) {
                                r.dispatch(event);
                            }
                        }
                        Ok(SourceEvent::Timeout) => {}
                        Ok(SourceEvent::Eof) => break,
                        Err(e) => {
                            tracing::warn!("probe capture stopped: {e}");
                            break;
                        }
                    }
                }
                a.store(false, Ordering::Relaxed);
                // Wake every waiting probe: their receivers see a closed channel.
                r.clear();
            })?;
        Ok(Self {
            registry,
            stop,
            alive,
            local,
        })
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// [`ProbeTransport`] for UDP and TCP-SYN probes, generic over the OS sender. ICMP probes are
/// refused ([`ModeUnavailable`]): use [`super::PingerTransport`] or [`SystemProbeTransport`].
pub struct CaptureProbeTransport<S> {
    sender: S,
    backend: Option<Arc<dyn CaptureBackend>>,
    listener: Mutex<Option<Arc<Listener>>>,
}

impl<S> std::fmt::Debug for CaptureProbeTransport<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureProbeTransport")
            .field("capture_backend", &self.backend.is_some())
            .finish()
    }
}

impl<S: ProbeSender> CaptureProbeTransport<S> {
    /// `backend` opens the capture source on demand; `None` makes UDP / TCP report
    /// [`ModeUnavailable`] with an explanation.
    pub fn new(sender: S, backend: Option<Arc<dyn CaptureBackend>>) -> Self {
        Self {
            sender,
            backend,
            listener: Mutex::new(None),
        }
    }

    fn open_listener(
        &self,
        mode: ProbeMode,
        target: IpAddr,
    ) -> Result<Arc<Listener>, ModeUnavailable> {
        let unavailable = |reason: String| ModeUnavailable::new(mode, reason);
        let Some(backend) = &self.backend else {
            return Err(unavailable(
                "no capture backend is available to read the replies; install Npcap \
                 (https://npcap.com) or run the agent with administrator rights so the \
                 raw-socket backend can be used"
                    .to_owned(),
            ));
        };
        self.sender.availability(mode, target)?;
        let caps = backend.caps();
        if target.is_ipv6() && !caps.ipv6 {
            return Err(unavailable(format!(
                "the {} capture backend cannot read IPv6 replies; install Npcap (https://npcap.com)",
                caps.kind.label()
            )));
        }
        let local = self
            .sender
            .local_addr_for(target)
            .map_err(|e| unavailable(format!("cannot determine the local address: {e}")))?;
        if let Some(existing) = lock(&self.listener).as_ref() {
            if existing.is_alive() && existing.local == local {
                return Ok(Arc::clone(existing));
            }
        }
        let opts = CaptureOpts {
            read_timeout: CAPTURE_READ_TIMEOUT,
            ..CaptureOpts::default()
        };
        let source = backend
            .open(&InterfaceId::new(local.to_string()), &opts)
            .map_err(|e| {
                unavailable(format!(
                    "cannot open the capture interface {local} ({}): {e}",
                    caps.kind.label()
                ))
            })?;
        let listener = Listener::start(source, local)
            .map_err(|e| unavailable(format!("cannot start the capture thread: {e}")))?;
        let listener = Arc::new(listener);
        *lock(&self.listener) = Some(Arc::clone(&listener));
        Ok(listener)
    }

    fn active_listener(&self, mode: ProbeMode) -> Result<Arc<Listener>, MtrError> {
        match lock(&self.listener).as_ref() {
            Some(l) if l.is_alive() => Ok(Arc::clone(l)),
            _ => Err(DiagError::System {
                code: 0,
                message: format!("the capture feeding {mode} probes stopped"),
            }
            .into()),
        }
    }
}

fn proto_of(mode: ProbeMode) -> Option<WireProto> {
    match mode {
        ProbeMode::Icmp => None,
        ProbeMode::Udp => Some(WireProto::Udp),
        ProbeMode::TcpSyn { .. } => Some(WireProto::Tcp),
    }
}

fn classify(request: &ProbeRequest, matched: Matched, rtt: Duration) -> ProbeReply {
    match matched {
        Matched::Icmp { from, kind } => match kind {
            IcmpErrorKind::TimeExceeded => ProbeReply::ttl_expired(from, rtt),
            IcmpErrorKind::PortUnreachable
                if from == request.target && request.mode == ProbeMode::Udp =>
            {
                ProbeReply::reached(ReachKind::PortUnreachable, from, rtt)
            }
            IcmpErrorKind::PortUnreachable | IcmpErrorKind::OtherUnreachable => {
                ProbeReply::unreachable(from, rtt)
            }
        },
        Matched::Tcp { from, kind } => ProbeReply::reached(
            match kind {
                TcpReplyKind::SynAck => ReachKind::SynAck,
                TcpReplyKind::Rst => ReachKind::Rst,
            },
            from,
            rtt,
        ),
    }
}

enum Outcome {
    Wire(Matched),
    Os(ReachKind),
    Timeout,
    CaptureLost,
}

impl<S: ProbeSender> ProbeTransport for CaptureProbeTransport<S> {
    fn prepare(&self, mode: ProbeMode, target: IpAddr) -> Result<(), ModeUnavailable> {
        if !mode.needs_capture() {
            return Err(ModeUnavailable::new(
                mode,
                "ICMP echo does not use the capture transport",
            ));
        }
        self.open_listener(mode, target).map(|_| ())
    }

    async fn probe(&self, request: &ProbeRequest) -> Result<ProbeReply, MtrError> {
        let Some(proto) = proto_of(request.mode) else {
            return Err(ModeUnavailable::new(
                request.mode,
                "ICMP echo does not use the capture transport",
            )
            .into());
        };
        let listener = self.active_listener(request.mode)?;
        let bound = self.sender.bind(request)?;
        let local_port = bound.local_port();
        let (tx, mut rx) = oneshot::channel();
        // Registered before the first byte is sent, so a fast answer cannot be missed.
        let _pending = listener.registry.register(
            proto,
            local_port,
            Pending {
                target: request.target,
                dst_port: request.port,
                tx,
            },
        )?;
        let started = Instant::now();
        let SentProbe { early, guard } = bound.fire()?;
        let mut early = early;
        let deadline = tokio::time::sleep(request.timeout);
        tokio::pin!(deadline);
        let outcome = loop {
            tokio::select! {
                biased;
                got = &mut rx => break match got {
                    Ok(m) => Outcome::Wire(m),
                    Err(_) => Outcome::CaptureLost,
                },
                os = async {
                    match early.as_mut() {
                        Some(r) => r.await,
                        None => std::future::pending().await,
                    }
                } => match os {
                    Ok(kind) => break Outcome::Os(kind),
                    Err(_) => early = None,
                },
                () = &mut deadline => break Outcome::Timeout,
            }
        };
        let rtt = started.elapsed();
        drop(guard);
        match outcome {
            Outcome::Wire(m) => Ok(classify(request, m, rtt)),
            Outcome::Os(kind) => Ok(ProbeReply::reached(kind, request.target, rtt)),
            Outcome::Timeout => Ok(ProbeReply::timed_out()),
            Outcome::CaptureLost => Err(DiagError::System {
                code: 0,
                message: format!("the capture feeding {} probes stopped", request.mode),
            }
            .into()),
        }
    }
}

/// The transport of a real machine: ICMP through the Win32 ICMP helper API, UDP / TCP-SYN through
/// sockets plus a capture backend. Without a backend (`None`), UDP and TCP report
/// [`ModeUnavailable`] and ICMP keeps working.
#[derive(Debug)]
pub struct SystemProbeTransport {
    icmp: PingerTransport<SystemPinger>,
    wire: CaptureProbeTransport<sys::SocketSender>,
}

impl SystemProbeTransport {
    /// `capture` is the backend chosen by `pw_capture::select_backend` (Npcap preferred), or
    /// `None` when there is none.
    pub fn new(capture: Option<Arc<dyn CaptureBackend>>) -> Self {
        Self {
            icmp: PingerTransport::new(Arc::new(SystemPinger)),
            wire: CaptureProbeTransport::new(sys::SocketSender, capture),
        }
    }
}

impl ProbeTransport for SystemProbeTransport {
    fn prepare(&self, mode: ProbeMode, target: IpAddr) -> Result<(), ModeUnavailable> {
        match mode {
            ProbeMode::Icmp => self.icmp.prepare(mode, target),
            _ => self.wire.prepare(mode, target),
        }
    }

    async fn probe(&self, request: &ProbeRequest) -> Result<ProbeReply, MtrError> {
        match request.mode {
            ProbeMode::Icmp => self.icmp.probe(request).await,
            _ => self.wire.probe(request).await,
        }
    }
}

#[cfg(test)]
pub(crate) mod fakes {
    //! A fake sender plus a capture backend whose frames are fed through a channel, so the real
    //! listener thread, matching and classification run in tests.

    use std::sync::atomic::AtomicU16;
    use std::sync::mpsc;

    use pw_capture::{BackendCaps, BackendKind, CaptureError, Frame};

    use super::*;

    pub(crate) struct ChanSource {
        pub(crate) rx: mpsc::Receiver<Vec<u8>>,
        pub(crate) link: LinkType,
        pub(crate) local: Vec<IpAddr>,
        pub(crate) buf: Vec<u8>,
    }

    impl PacketSource for ChanSource {
        fn link_type(&self) -> LinkType {
            self.link
        }
        fn local_addrs(&self) -> &[IpAddr] {
            &self.local
        }
        fn next(&mut self) -> Result<SourceEvent<'_>, CaptureError> {
            match self.rx.recv_timeout(Duration::from_millis(20)) {
                Ok(frame) => {
                    self.buf = frame;
                    Ok(SourceEvent::Frame(Frame {
                        timestamp_ns: 0,
                        data: &self.buf,
                        original_len: u32::try_from(self.buf.len()).unwrap_or(u32::MAX),
                    }))
                }
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(SourceEvent::Timeout),
                Err(mpsc::RecvTimeoutError::Disconnected) => Ok(SourceEvent::Eof),
            }
        }
    }

    pub(crate) struct FakeBackend {
        pub(crate) source: Mutex<Option<ChanSource>>,
        pub(crate) caps: BackendCaps,
        pub(crate) opened: Mutex<Vec<String>>,
    }

    impl FakeBackend {
        pub(crate) fn new(source: ChanSource, ipv6: bool) -> Arc<Self> {
            Arc::new(Self {
                source: Mutex::new(Some(source)),
                caps: BackendCaps {
                    kind: if ipv6 {
                        BackendKind::Npcap
                    } else {
                        BackendKind::RawSocket
                    },
                    link_layer: false,
                    bpf: false,
                    sees_outbound: true,
                    ipv6,
                    needs_admin: false,
                },
                opened: Mutex::new(Vec::new()),
            })
        }
    }

    impl CaptureBackend for FakeBackend {
        fn caps(&self) -> BackendCaps {
            self.caps
        }
        fn open(
            &self,
            interface: &InterfaceId,
            _opts: &CaptureOpts,
        ) -> Result<Box<dyn PacketSource>, CaptureError> {
            lock(&self.opened).push(interface.to_string());
            match lock(&self.source).take() {
                Some(s) => Ok(Box::new(s)),
                None => Err(CaptureError::AccessDenied),
            }
        }
    }

    /// What the fake network does when a probe is fired: the frames to deliver (built from the
    /// request and the local port) and an optional OS-level answer.
    pub(crate) type Reaction =
        dyn Fn(&ProbeRequest, u16) -> (Vec<Vec<u8>>, Option<ReachKind>) + Send + Sync;

    pub(crate) struct FakeSender {
        pub(crate) local: IpAddr,
        pub(crate) frames: Mutex<mpsc::Sender<Vec<u8>>>,
        pub(crate) next_port: AtomicU16,
        pub(crate) react: Box<Reaction>,
        pub(crate) fired: Arc<Mutex<Vec<(ProbeRequest, u16)>>>,
    }

    struct FakeBound {
        request: ProbeRequest,
        port: u16,
        sender: mpsc::Sender<Vec<u8>>,
        react: (Vec<Vec<u8>>, Option<ReachKind>),
        fired: Arc<Mutex<Vec<(ProbeRequest, u16)>>>,
    }

    impl BoundProbe for FakeBound {
        fn local_port(&self) -> u16 {
            self.port
        }
        fn fire(self: Box<Self>) -> Result<SentProbe, DiagError> {
            lock(&self.fired).push((self.request.clone(), self.port));
            for frame in &self.react.0 {
                let _ = self.sender.send(frame.clone());
            }
            let early = self.react.1.map(|kind| {
                let (tx, rx) = oneshot::channel();
                let _ = tx.send(kind);
                rx
            });
            Ok(SentProbe {
                early,
                guard: Box::new(()),
            })
        }
    }

    impl ProbeSender for FakeSender {
        fn availability(&self, _mode: ProbeMode, _target: IpAddr) -> Result<(), ModeUnavailable> {
            Ok(())
        }
        fn local_addr_for(&self, _target: IpAddr) -> Result<IpAddr, DiagError> {
            Ok(self.local)
        }
        fn bind(&self, request: &ProbeRequest) -> Result<Box<dyn BoundProbe>, DiagError> {
            let port = self.next_port.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeBound {
                request: request.clone(),
                port,
                sender: lock(&self.frames).clone(),
                react: (self.react)(request, port),
                fired: Arc::clone(&self.fired),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU16;
    use std::sync::mpsc;

    use super::fakes::*;
    use super::*;
    use crate::mtr_adv::wire::testpkt::{icmp_error, quoted_probe, tcp_segment};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const LOCAL: &str = "192.168.1.5";
    const TARGET: &str = "1.1.1.1";

    fn request(mode: ProbeMode, ttl: u8, port: u16, timeout_ms: u64) -> ProbeRequest {
        ProbeRequest {
            target: ip(TARGET),
            mode,
            ttl,
            payload_size: 0,
            port,
            timeout: Duration::from_millis(timeout_ms),
            seq: 1,
        }
    }

    fn setup(
        ipv6_backend: bool,
        react: Box<Reaction>,
    ) -> (CaptureProbeTransport<FakeSender>, Arc<FakeBackend>) {
        let (tx, rx) = mpsc::channel();
        let source = ChanSource {
            rx,
            link: LinkType::RawIp,
            local: vec![ip(LOCAL)],
            buf: Vec::new(),
        };
        let backend = FakeBackend::new(source, ipv6_backend);
        let sender = FakeSender {
            local: ip(LOCAL),
            frames: Mutex::new(tx),
            next_port: AtomicU16::new(40_000),
            react,
            fired: Arc::new(Mutex::new(Vec::new())),
        };
        let transport = CaptureProbeTransport::new(
            sender,
            Some(Arc::clone(&backend) as Arc<dyn CaptureBackend>),
        );
        (transport, backend)
    }

    fn udp_frames(req: &ProbeRequest, port: u16) -> Vec<Vec<u8>> {
        let q = quoted_probe(ip(LOCAL), req.target, WireProto::Udp, port, req.port);
        if req.ttl < 3 {
            vec![icmp_error(
                ip(&format!("10.0.0.{}", req.ttl)),
                ip(LOCAL),
                11,
                0,
                &q,
            )]
        } else {
            vec![icmp_error(req.target, ip(LOCAL), 3, 3, &q)]
        }
    }

    #[tokio::test]
    async fn udp_hop_and_destination_are_matched_from_the_capture() {
        let (t, backend) = setup(false, Box::new(|r, p| (udp_frames(r, p), None)));
        t.prepare(ProbeMode::Udp, ip(TARGET)).unwrap();
        assert_eq!(lock(&backend.opened).as_slice(), [LOCAL.to_owned()]);

        let hop = t
            .probe(&request(ProbeMode::Udp, 2, 33434, 2000))
            .await
            .unwrap();
        assert_eq!(hop.from, Some(ip("10.0.0.2")));
        assert_eq!(hop.status, super::super::ProbeStatus::TtlExpired);
        assert!(hop.rtt.is_some());

        let dest = t
            .probe(&request(ProbeMode::Udp, 5, 33434, 2000))
            .await
            .unwrap();
        assert_eq!(
            dest.status,
            super::super::ProbeStatus::Reached(ReachKind::PortUnreachable)
        );
        assert_eq!(dest.from, Some(ip(TARGET)));
    }

    #[tokio::test]
    async fn port_unreachable_from_a_router_is_not_the_destination() {
        let (t, _b) = setup(
            false,
            Box::new(|r, p| {
                let q = quoted_probe(ip(LOCAL), r.target, WireProto::Udp, p, r.port);
                (vec![icmp_error(ip("10.0.0.9"), ip(LOCAL), 3, 3, &q)], None)
            }),
        );
        t.prepare(ProbeMode::Udp, ip(TARGET)).unwrap();
        let reply = t
            .probe(&request(ProbeMode::Udp, 4, 33434, 2000))
            .await
            .unwrap();
        assert_eq!(reply.status, super::super::ProbeStatus::Unreachable);
    }

    #[tokio::test]
    async fn tcp_syn_ack_and_rst_from_the_capture() {
        for (flags, want) in [(0x12u8, ReachKind::SynAck), (0x14, ReachKind::Rst)] {
            let (t, _b) = setup(
                false,
                Box::new(move |r, p| {
                    (
                        vec![tcp_segment(r.target, ip(LOCAL), r.port, p, flags)],
                        None,
                    )
                }),
            );
            let mode = ProbeMode::TcpSyn { port: 443 };
            t.prepare(mode, ip(TARGET)).unwrap();
            let reply = t.probe(&request(mode, 9, 443, 2000)).await.unwrap();
            assert_eq!(reply.status, super::super::ProbeStatus::Reached(want));
            assert_eq!(reply.from, Some(ip(TARGET)));
        }
    }

    #[tokio::test]
    async fn tcp_destination_is_also_learned_from_the_os_when_capture_misses_it() {
        let (t, _b) = setup(false, Box::new(|_r, _p| (Vec::new(), Some(ReachKind::Rst))));
        let mode = ProbeMode::TcpSyn { port: 443 };
        t.prepare(mode, ip(TARGET)).unwrap();
        let reply = t.probe(&request(mode, 9, 443, 2000)).await.unwrap();
        assert_eq!(
            reply.status,
            super::super::ProbeStatus::Reached(ReachKind::Rst)
        );
    }

    #[tokio::test]
    async fn silence_times_out_and_unrelated_frames_are_ignored() {
        let (t, _b) = setup(
            false,
            Box::new(|r, p| {
                // Right shape, wrong destination port / wrong local port: must not match.
                let wrong_port = quoted_probe(ip(LOCAL), r.target, WireProto::Udp, p, r.port + 1);
                let wrong_local = quoted_probe(ip(LOCAL), r.target, WireProto::Udp, p + 1, r.port);
                let wrong_dst = quoted_probe(ip(LOCAL), ip("8.8.8.8"), WireProto::Udp, p, r.port);
                (
                    vec![
                        icmp_error(ip("10.0.0.1"), ip(LOCAL), 11, 0, &wrong_port),
                        icmp_error(ip("10.0.0.1"), ip(LOCAL), 11, 0, &wrong_local),
                        icmp_error(ip("10.0.0.1"), ip(LOCAL), 11, 0, &wrong_dst),
                        tcp_segment(r.target, ip(LOCAL), r.port, p, 0x12),
                    ],
                    None,
                )
            }),
        );
        t.prepare(ProbeMode::Udp, ip(TARGET)).unwrap();
        let reply = t
            .probe(&request(ProbeMode::Udp, 1, 33434, 300))
            .await
            .unwrap();
        assert_eq!(reply, ProbeReply::timed_out());
        assert!(lock(&t.active_listener(ProbeMode::Udp).unwrap().registry.map).is_empty());
    }

    #[test]
    fn modes_are_unavailable_with_a_reason() {
        // No backend at all.
        let (tx, _rx) = mpsc::channel();
        let sender = FakeSender {
            local: ip(LOCAL),
            frames: Mutex::new(tx),
            next_port: AtomicU16::new(40_000),
            react: Box::new(|_, _| (Vec::new(), None)),
            fired: Arc::new(Mutex::new(Vec::new())),
        };
        let none = CaptureProbeTransport::new(sender, None);
        let err = none.prepare(ProbeMode::Udp, ip(TARGET)).unwrap_err();
        assert_eq!(err.mode, ProbeMode::Udp);
        assert!(err.reason.contains("Npcap"), "{}", err.reason);

        // IPv4-only backend (raw sockets) and an IPv6 target.
        let (t, backend) = setup(false, Box::new(|_, _| (Vec::new(), None)));
        let err = t
            .prepare(ProbeMode::TcpSyn { port: 80 }, ip("2606:4700:4700::1111"))
            .unwrap_err();
        assert!(err.reason.contains("IPv6"), "{}", err.reason);
        assert!(lock(&backend.opened).is_empty(), "nothing was opened");

        // The backend refuses to open (no administrator rights).
        let (t, backend) = setup(false, Box::new(|_, _| (Vec::new(), None)));
        lock(&backend.source).take();
        let err = t.prepare(ProbeMode::Udp, ip(TARGET)).unwrap_err();
        assert!(err.reason.contains("administrator"), "{}", err.reason);

        // ICMP is not this transport's job.
        assert!(t.prepare(ProbeMode::Icmp, ip(TARGET)).is_err());
    }

    #[tokio::test]
    async fn a_dead_capture_is_an_error_not_a_hang() {
        let (t, _b) = setup(false, Box::new(|_, _| (Vec::new(), None)));
        t.prepare(ProbeMode::Udp, ip(TARGET)).unwrap();
        // Dropping the sender closes the channel: the source reports Eof and the thread ends.
        let listener = t.active_listener(ProbeMode::Udp).unwrap();
        *lock(&t.sender.frames) = mpsc::channel().0;
        for _ in 0..100 {
            if !listener.is_alive() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // `t.sender.frames` held the only sender clone used by the source's channel; replacing it
        // dropped it and the source saw Eof (bound probes clone the sender per probe).
        assert!(!listener.is_alive());
        let err = t
            .probe(&request(ProbeMode::Udp, 1, 33434, 500))
            .await
            .unwrap_err();
        assert!(matches!(err, MtrError::Diag(_)), "{err:?}");
    }

    #[tokio::test]
    async fn pending_table_is_bounded_and_cleaned_up() {
        let registry = Arc::new(Registry::default());
        let mut guards = Vec::new();
        for port in 0..u16::try_from(MAX_PENDING_PROBES).unwrap() {
            let (tx, _rx) = oneshot::channel();
            guards.push(
                registry
                    .register(
                        WireProto::Udp,
                        port,
                        Pending {
                            target: ip(TARGET),
                            dst_port: 1,
                            tx,
                        },
                    )
                    .unwrap(),
            );
        }
        let (tx, _rx) = oneshot::channel();
        assert!(registry
            .register(
                WireProto::Udp,
                60_000,
                Pending {
                    target: ip(TARGET),
                    dst_port: 1,
                    tx
                }
            )
            .is_err());
        drop(guards);
        assert!(lock(&registry.map).is_empty());
    }
}

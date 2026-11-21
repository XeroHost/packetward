// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! MTR (simple): ICMP echo with an incrementing TTL, repeated for N cycles, with per-hop
//! statistics streamed once per cycle.
//!
//! Each cycle probes TTL 1, 2, 3, ... (several TTLs concurrently, see
//! [`MtrOptions::parallelism`]) until the destination answers. Once the destination hop is
//! known, later cycles never send a TTL above it, except when a probe *at* the destination hop
//! comes back "TTL exceeded" - positive evidence that the path got longer - in which case the
//! cycle looks further, up to `max_hops`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::cancel::CancelToken;
use crate::echo::{clamp_timeout, EchoReply, EchoStatus, Pinger, DEFAULT_PAYLOAD, MAX_PAYLOAD};
use crate::error::DiagError;
use crate::mtr_adv::{
    AdvMtrOptions, MtrError, PingerTransport, ProbeReply, ProbeRequest, ProbeStatus,
    ProbeTransport, ReachKind,
};
use crate::names::{NameCache, ReverseLookup};
use crate::ping::MIN_INTERVAL;
use crate::sink::Sink;
use crate::stats::{loss_percent, RttStats, RttSummary};

/// Most cycles one run may do.
pub const MAX_CYCLES: u32 = 1000;
/// Highest `max_hops` accepted.
pub const MAX_HOPS_LIMIT: u8 = 64;
/// Most TTLs probed concurrently.
pub const MAX_PARALLELISM: u8 = 16;
/// Distinct addresses remembered per hop (equal-cost paths answer from several routers).
pub const MAX_ADDRS_PER_HOP: usize = 8;

/// MTR parameters. Out-of-range values are clamped, see [`MtrOptions::normalized`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtrOptions {
    /// Number of cycles (default 10, at most [`MAX_CYCLES`]).
    pub cycles: u32,
    /// Highest TTL probed (default 30, `1..=`[`MAX_HOPS_LIMIT`]).
    pub max_hops: u8,
    /// Per-probe timeout (default 1 s, at most 10 s).
    pub timeout: Duration,
    /// Echo payload size in bytes (default 32).
    pub packet_size: u16,
    /// Time between the starts of two cycles (default 1 s, at least 200 ms).
    pub interval: Duration,
    /// How many TTLs are probed at the same time (default 8, `1..=`[`MAX_PARALLELISM`]).
    /// `1` probes strictly one hop at a time.
    pub parallelism: u8,
}

impl Default for MtrOptions {
    fn default() -> Self {
        Self {
            cycles: 10,
            max_hops: 30,
            timeout: Duration::from_secs(1),
            packet_size: DEFAULT_PAYLOAD,
            interval: Duration::from_secs(1),
            parallelism: 8,
        }
    }
}

impl MtrOptions {
    /// The options with every field forced into its supported range.
    pub fn normalized(&self) -> MtrOptions {
        MtrOptions {
            cycles: self.cycles.clamp(1, MAX_CYCLES),
            max_hops: self.max_hops.clamp(1, MAX_HOPS_LIMIT),
            timeout: clamp_timeout(self.timeout),
            packet_size: self.packet_size.min(MAX_PAYLOAD),
            interval: self.interval.max(MIN_INTERVAL),
            parallelism: self.parallelism.clamp(1, MAX_PARALLELISM),
        }
    }
}

/// Running statistics of one hop (one TTL). Pure: no I/O, no clock.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HopStats {
    sent: u64,
    received: u64,
    rtt: RttStats,
    addr: Option<IpAddr>,
    seen: Vec<IpAddr>,
    address_changes: u32,
}

impl HopStats {
    /// A hop nothing was sent to yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A probe was sent and nothing (usable) came back.
    pub fn record_lost(&mut self) {
        self.sent += 1;
    }

    /// A probe was sent and `addr` answered after `rtt`.
    pub fn record_reply(&mut self, addr: IpAddr, rtt: Duration) {
        self.sent += 1;
        self.received += 1;
        self.rtt.add(rtt);
        if self.addr.is_some_and(|prev| prev != addr) {
            self.address_changes += 1;
        }
        self.addr = Some(addr);
        if !self.seen.contains(&addr) && self.seen.len() < MAX_ADDRS_PER_HOP {
            self.seen.push(addr);
        }
    }

    /// Probes sent (answered or not).
    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// Probes answered.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Loss in percent.
    pub fn loss_percent(&self) -> f64 {
        loss_percent(self.sent, self.received)
    }

    /// The address that answered most recently.
    pub fn addr(&self) -> Option<IpAddr> {
        self.addr
    }

    /// Frozen copy for display. `name` is the reverse-DNS name of the current address, if known.
    pub fn snapshot(&self, ttl: u8, name: Option<String>) -> HopSnapshot {
        HopSnapshot {
            ttl,
            addr: self.addr,
            other_addrs: self
                .seen
                .iter()
                .copied()
                .filter(|a| Some(*a) != self.addr)
                .collect(),
            name,
            sent: self.sent,
            received: self.received,
            loss_percent: self.loss_percent(),
            rtt: self.rtt.summary(),
            address_changes: self.address_changes,
        }
    }
}

/// One row of an MTR table.
#[derive(Debug, Clone, PartialEq)]
pub struct HopSnapshot {
    /// Hop number (the TTL that reaches it), starting at 1.
    pub ttl: u8,
    /// Address that answered most recently; `None` when the hop never answered.
    pub addr: Option<IpAddr>,
    /// Other addresses that answered at this TTL (route change or equal-cost multipath).
    pub other_addrs: Vec<IpAddr>,
    /// Reverse-DNS name of `addr`.
    pub name: Option<String>,
    /// Probes sent to this hop.
    pub sent: u64,
    /// Probes answered.
    pub received: u64,
    /// Loss in percent.
    pub loss_percent: f64,
    /// last / best / avg / worst / stdev / jitter; `None` when the hop never answered.
    pub rtt: Option<RttSummary>,
    /// How often the answering address changed.
    pub address_changes: u32,
}

/// The whole table after some number of cycles.
#[derive(Debug, Clone, PartialEq)]
pub struct MtrSnapshot {
    /// The destination traced.
    pub target: IpAddr,
    /// Cycles completed so far.
    pub cycle: u32,
    /// Cycles requested.
    pub total_cycles: u32,
    /// One entry per hop, from TTL 1 up to the destination (or `max_hops` when it never answered).
    pub hops: Vec<HopSnapshot>,
    /// The destination itself answered (not just a router saying "unreachable").
    pub destination_reached: bool,
    /// Only set on the value *returned* by [`mtr`]: the run was cancelled before finishing.
    pub cancelled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct End {
    ttl: u8,
    reached: bool,
    via: Option<ReachKind>,
}

/// A table as produced by the shared cycle engine: the simple snapshot plus how the destination
/// answered. [`mtr()`] keeps the first, [`crate::mtr_adv::mtr_with`] builds its richer snapshot
/// from both.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CoreSnapshot {
    pub(crate) snapshot: MtrSnapshot,
    pub(crate) reached_via: Option<ReachKind>,
}

#[derive(Debug)]
struct MtrState {
    target: IpAddr,
    hops: Vec<HopStats>,
    end: Option<End>,
    cycles_done: u32,
    next_seq: u32,
}

impl MtrState {
    fn new(target: IpAddr) -> Self {
        Self {
            target,
            hops: Vec::new(),
            end: None,
            cycles_done: 0,
            next_seq: 0,
        }
    }

    fn apply(&mut self, ttl: u8, outcome: &Result<ProbeReply, MtrError>) {
        let idx = usize::from(ttl).saturating_sub(1);
        if self.hops.len() <= idx {
            self.hops.resize_with(idx + 1, HopStats::new);
        }
        let hop = &mut self.hops[idx];
        match outcome {
            Ok(ProbeReply {
                status: ProbeStatus::Reached(_) | ProbeStatus::TtlExpired | ProbeStatus::Unreachable,
                from: Some(from),
                rtt: Some(rtt),
            }) => hop.record_reply(*from, *rtt),
            _ => hop.record_lost(),
        }
    }

    fn set_end(&mut self, end: Option<End>) {
        self.end = end;
        if let Some(e) = end {
            self.hops.truncate(usize::from(e.ttl));
        }
    }

    fn addrs(&self) -> Vec<IpAddr> {
        self.hops.iter().filter_map(HopStats::addr).collect()
    }

    fn snapshot<R: ReverseLookup>(
        &self,
        total: u32,
        names: Option<&NameCache<R>>,
        cancelled: bool,
    ) -> CoreSnapshot {
        let hops = self
            .hops
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let ttl = u8::try_from(i + 1).unwrap_or(u8::MAX);
                let name = names.and_then(|n| h.addr().and_then(|a| n.name(a)));
                h.snapshot(ttl, name)
            })
            .collect();
        CoreSnapshot {
            snapshot: MtrSnapshot {
                target: self.target,
                cycle: self.cycles_done,
                total_cycles: total,
                hops,
                destination_reached: self.end.is_some_and(|e| e.reached),
                cancelled,
            },
            reached_via: self.end.and_then(|e| e.via),
        }
    }
}

/// Does this reply end the trace (nothing beyond it can be reached)?
fn terminal(reply: &EchoReply, target: IpAddr) -> Option<bool> {
    match reply.status {
        EchoStatus::Success => Some(true),
        EchoStatus::Unreachable if reply.from.is_some() => Some(reply.from == Some(target)),
        EchoStatus::TtlExpired | EchoStatus::Unreachable | EchoStatus::TimedOut => {
            if reply.from == Some(target) && reply.status != EchoStatus::TimedOut {
                Some(true)
            } else {
                None
            }
        }
        EchoStatus::Other(_) => None,
    }
}

async fn probe_wave<T: ProbeTransport + 'static>(
    transport: &Arc<T>,
    requests: Vec<ProbeRequest>,
    cancel: &CancelToken,
) -> Option<Vec<(u8, Result<ProbeReply, MtrError>)>> {
    let wanted: Vec<u8> = requests.iter().map(|r| r.ttl).collect();
    let mut set = JoinSet::new();
    for req in requests {
        let transport = Arc::clone(transport);
        set.spawn(async move { (req.ttl, transport.probe(&req).await) });
    }
    let mut out = Vec::with_capacity(wanted.len());
    loop {
        tokio::select! {
            next = set.join_next() => match next {
                Some(Ok(item)) => out.push(item),
                Some(Err(e)) => tracing::warn!("mtr probe task failed: {e}"),
                None => break,
            },
            () = cancel.cancelled() => return None,
        }
    }
    for ttl in wanted {
        if !out.iter().any(|(t, _)| *t == ttl) {
            out.push((
                ttl,
                Err(DiagError::System {
                    code: 0,
                    message: "probe task failed".to_owned(),
                }
                .into()),
            ));
        }
    }
    out.sort_by_key(|(ttl, _)| *ttl);
    Some(out)
}

enum CycleEnd {
    Done,
    Cancelled,
}

async fn run_cycle<T: ProbeTransport + 'static>(
    transport: &Arc<T>,
    state: &mut MtrState,
    opts: &AdvMtrOptions,
    cancel: &CancelToken,
) -> Result<CycleEnd, MtrError> {
    let target = state.target;
    let known = state.end.map(|e| e.ttl);
    let mut upper = known.unwrap_or(opts.max_hops);
    let mut next: u16 = 1;
    let mut cycle_end: Option<End> = None;
    let mut answered = 0u32;
    let mut failed = 0u32;
    let mut first_err: Option<MtrError> = None;
    let mut lengthened = false;

    loop {
        let last = (next + u16::from(opts.parallelism) - 1).min(u16::from(upper));
        let requests: Vec<ProbeRequest> = (next..=last)
            .filter_map(|t| u8::try_from(t).ok())
            .map(|ttl| {
                state.next_seq = state.next_seq.wrapping_add(1);
                ProbeRequest {
                    target,
                    mode: opts.mode,
                    ttl,
                    payload_size: opts.packet_size,
                    port: opts.probe_port(),
                    timeout: opts.timeout,
                    seq: state.next_seq,
                }
            })
            .collect();
        let Some(results) = probe_wave(transport, requests, cancel).await else {
            return Ok(CycleEnd::Cancelled);
        };
        for (ttl, outcome) in results {
            // Replies from beyond the destination (sent in the same wave) are noise.
            if cycle_end.is_some_and(|e| ttl > e.ttl) {
                continue;
            }
            match &outcome {
                Ok(_) => answered += 1,
                Err(_) => failed += 1,
            }
            state.apply(ttl, &outcome);
            match outcome {
                Ok(reply) => {
                    if let Some(reached) = terminal(&reply.to_echo(), target) {
                        let via = match reply.status {
                            ProbeStatus::Reached(kind) => Some(kind),
                            _ => None,
                        };
                        cycle_end = Some(End { ttl, reached, via });
                    } else if Some(ttl) == known
                        && reply.status == ProbeStatus::TtlExpired
                        && reply.from.is_some()
                    {
                        lengthened = true;
                    }
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if answered == 0 && failed > 0 {
            // Nothing could even be sent; do not grind through every remaining TTL.
            if let Some(e) = first_err {
                return Err(e);
            }
        }
        if cycle_end.is_some() {
            break;
        }
        if last >= u16::from(upper) {
            if lengthened && upper < opts.max_hops {
                upper = opts.max_hops;
            } else {
                break;
            }
        }
        next = last + 1;
    }

    if cycle_end.is_none() && lengthened {
        // The old destination hop now answers "TTL exceeded": forget it and look further next time.
        state.end = None;
    }
    if cycle_end.is_some() {
        state.set_end(cycle_end);
    }
    Ok(CycleEnd::Done)
}

/// The cycle engine shared by [`mtr()`] and [`crate::mtr_adv::mtr_with`]. `opts` must already be
/// normalized (and validated) for `target`.
///
/// Delivers a [`CoreSnapshot`] to `sink` after every cycle and returns the last one. See [`mtr()`]
/// for the cancellation rules.
pub(crate) async fn run_trace<T, R, S>(
    transport: Arc<T>,
    target: IpAddr,
    opts: &AdvMtrOptions,
    names: &NameCache<R>,
    cancel: &CancelToken,
    sink: &mut S,
) -> Result<CoreSnapshot, MtrError>
where
    T: ProbeTransport + 'static,
    R: ReverseLookup,
    S: Sink<CoreSnapshot>,
{
    transport.prepare(opts.mode, target)?;
    let names = opts.resolve_names.then_some(names);
    let mut state = MtrState::new(target);

    for cycle in 0..opts.cycles {
        if cancel.is_cancelled() {
            return Ok(state.snapshot(opts.cycles, names, true));
        }
        let started = Instant::now();
        match run_cycle(&transport, &mut state, opts, cancel).await? {
            CycleEnd::Cancelled => return Ok(state.snapshot(opts.cycles, names, true)),
            CycleEnd::Done => {}
        }
        state.cycles_done = cycle + 1;

        if let Some(names) = names {
            let addrs = state.addrs();
            tokio::select! {
                () = names.resolve(&addrs) => {}
                () = cancel.cancelled() => {}
            }
        }
        let snapshot = state.snapshot(opts.cycles, names, false);
        let delivered = tokio::select! {
            ok = sink.deliver(snapshot) => ok,
            () = cancel.cancelled() => false,
        };
        if !delivered {
            return Ok(state.snapshot(opts.cycles, names, true));
        }
        if cycle + 1 < opts.cycles {
            tokio::select! {
                () = tokio::time::sleep_until(started + opts.interval) => {}
                () = cancel.cancelled() => {
                    return Ok(state.snapshot(opts.cycles, names, true));
                }
            }
        }
    }
    Ok(state.snapshot(opts.cycles, names, false))
}

/// Adapts a sink of simple snapshots to the engine's [`CoreSnapshot`].
struct SimpleSink<'a, S>(&'a mut S);

impl<S: Sink<MtrSnapshot>> Sink<CoreSnapshot> for SimpleSink<'_, S> {
    async fn deliver(&mut self, item: CoreSnapshot) -> bool {
        self.0.deliver(item.snapshot).await
    }
}

/// Trace the route to `target` with ICMP echo, delivering an [`MtrSnapshot`] to `sink` after
/// every cycle, and return the last snapshot. (For UDP / TCP-SYN probes, ASN / country and
/// export see [`crate::mtr_adv`].)
///
/// `names` resolves hop addresses to host names after each cycle (bounded by its own timeout,
/// shared across runs); pass [`NameCache::disabled`] to skip that.
///
/// Cancelling `cancel` (or dropping a channel sink's receiver) discards the cycle in flight and
/// returns the table of the completed cycles with `cancelled == true`. An `Err` means no probe
/// could be sent at all.
pub async fn mtr<P, R, S>(
    pinger: Arc<P>,
    target: IpAddr,
    options: &MtrOptions,
    names: &NameCache<R>,
    cancel: &CancelToken,
    sink: &mut S,
) -> Result<MtrSnapshot, DiagError>
where
    P: Pinger + 'static,
    R: ReverseLookup,
    S: Sink<MtrSnapshot>,
{
    let opts = AdvMtrOptions::from(&options.normalized()).normalized_for(target);
    let transport = Arc::new(PingerTransport::new(pinger));
    let mut sink = SimpleSink(sink);
    match run_trace(transport, target, &opts, names, cancel, &mut sink).await {
        Ok(last) => Ok(last.snapshot),
        Err(MtrError::Diag(e)) => Err(e),
        Err(MtrError::ModeUnavailable(m)) => Err(DiagError::InvalidInput(m.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakePinger;
    use crate::sink::{FnSink, NullSink};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn dest() -> IpAddr {
        ip("203.0.113.9")
    }

    fn router(ttl: u8) -> IpAddr {
        ip(&format!("10.0.0.{ttl}"))
    }

    fn reply(status: EchoStatus, from: IpAddr, ms: u64) -> Result<EchoReply, DiagError> {
        Ok(EchoReply {
            status,
            from: Some(from),
            rtt: Some(Duration::from_millis(ms)),
            ttl: Some(60),
        })
    }

    /// A route with `dest_ttl - 1` routers and the destination at `dest_ttl`. Probes with a larger
    /// TTL reach the destination too (as on a real network).
    fn straight_route(dest_ttl: u8) -> FakePinger {
        FakePinger::new(move |req, _| {
            if req.ttl < dest_ttl {
                reply(
                    EchoStatus::TtlExpired,
                    router(req.ttl),
                    u64::from(req.ttl) * 5,
                )
            } else {
                reply(EchoStatus::Success, dest(), u64::from(dest_ttl) * 5)
            }
        })
    }

    fn opts(cycles: u32) -> MtrOptions {
        MtrOptions {
            cycles,
            ..MtrOptions::default()
        }
    }

    async fn run(
        pinger: Arc<FakePinger>,
        options: &MtrOptions,
        cancel: &CancelToken,
    ) -> (Result<MtrSnapshot, DiagError>, Vec<MtrSnapshot>) {
        let mut snaps = Vec::new();
        let mut sink = FnSink(|s: MtrSnapshot| snaps.push(s));
        let r = mtr(
            pinger,
            dest(),
            options,
            &NameCache::disabled(),
            cancel,
            &mut sink,
        )
        .await;
        (r, snaps)
    }

    #[test]
    fn hop_stats_accounting() {
        let mut h = HopStats::new();
        h.record_reply(ip("10.0.0.1"), Duration::from_millis(10));
        h.record_lost();
        h.record_reply(ip("10.0.0.1"), Duration::from_millis(30));
        h.record_lost();
        assert_eq!((h.sent(), h.received()), (4, 2));
        assert!((h.loss_percent() - 50.0).abs() < 1e-9);
        let s = h.snapshot(3, Some("r.example".into()));
        let rtt = s.rtt.unwrap();
        assert!((rtt.avg_ms - 20.0).abs() < 1e-9);
        assert!((rtt.min_ms - 10.0).abs() < 1e-9 && (rtt.max_ms - 30.0).abs() < 1e-9);
        assert!((rtt.last_ms - 30.0).abs() < 1e-9);
        assert!((rtt.jitter_ms - 20.0).abs() < 1e-9);
        assert_eq!(s.ttl, 3);
        assert_eq!(s.name.as_deref(), Some("r.example"));
        assert_eq!(s.address_changes, 0);
        assert!(s.other_addrs.is_empty());
    }

    #[test]
    fn hop_that_never_answers_has_no_rtt() {
        let mut h = HopStats::new();
        h.record_lost();
        h.record_lost();
        let s = h.snapshot(1, None);
        assert!(s.rtt.is_none() && s.addr.is_none());
        assert!((s.loss_percent - 100.0).abs() < 1e-9);
    }

    #[test]
    fn hop_tracks_address_changes_with_bound() {
        let mut h = HopStats::new();
        for i in 1..=12u8 {
            h.record_reply(router(i), Duration::from_millis(1));
        }
        let s = h.snapshot(1, None);
        assert_eq!(s.address_changes, 11);
        assert_eq!(s.addr, Some(router(12)));
        assert_eq!(s.other_addrs.len(), MAX_ADDRS_PER_HOP);
    }

    #[test]
    fn options_are_clamped() {
        let o = MtrOptions {
            cycles: 0,
            max_hops: 255,
            timeout: Duration::ZERO,
            packet_size: u16::MAX,
            interval: Duration::ZERO,
            parallelism: 0,
        }
        .normalized();
        assert_eq!(o.cycles, 1);
        assert_eq!(o.max_hops, MAX_HOPS_LIMIT);
        assert_eq!(o.packet_size, MAX_PAYLOAD);
        assert_eq!(o.interval, MIN_INTERVAL);
        assert_eq!(o.parallelism, 1);
        assert_eq!(
            MtrOptions {
                cycles: u32::MAX,
                ..MtrOptions::default()
            }
            .normalized()
            .cycles,
            MAX_CYCLES
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stops_at_destination_and_streams_one_snapshot_per_cycle() {
        let pinger = Arc::new(straight_route(4));
        let (r, snaps) = run(Arc::clone(&pinger), &opts(3), &CancelToken::new()).await;
        let last = r.unwrap();
        assert_eq!(snaps.len(), 3);
        assert_eq!(
            snaps.iter().map(|s| s.cycle).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(last, snaps[2]);
        assert!(last.destination_reached && !last.cancelled);
        assert_eq!(last.hops.len(), 4, "table ends at the destination");
        assert_eq!(last.hops[3].addr, Some(dest()));
        assert!(last.hops.iter().all(|h| h.sent == 3 && h.received == 3));
        assert_eq!(
            snaps[0].hops[0].sent, 1,
            "snapshots are per cycle, not final-only"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn never_probes_beyond_destination_once_known() {
        let pinger = Arc::new(straight_route(3));
        let o = MtrOptions {
            parallelism: 1,
            ..opts(5)
        };
        let (r, _) = run(Arc::clone(&pinger), &o, &CancelToken::new()).await;
        r.unwrap();
        let reqs = pinger.requests();
        assert_eq!(reqs.len(), 15, "5 cycles x 3 hops, nothing beyond hop 3");
        assert!(reqs.iter().all(|q| q.ttl <= 3));
    }

    #[tokio::test(start_paused = true)]
    async fn waves_overshoot_only_in_the_first_cycle() {
        let pinger = Arc::new(straight_route(3));
        let (r, _) = run(Arc::clone(&pinger), &opts(4), &CancelToken::new()).await;
        let last = r.unwrap();
        let reqs = pinger.requests();
        // First wave of 8 probes TTL 1..=8; afterwards only 1..=3.
        assert_eq!(reqs.len(), 8 + 3 * 3);
        assert!(reqs[8..].iter().all(|q| q.ttl <= 3));
        // Probes beyond the destination in the first wave are not counted.
        assert_eq!(last.hops.len(), 3);
        assert!(last.hops.iter().all(|h| h.sent == 4));
    }

    #[tokio::test(start_paused = true)]
    async fn non_responding_hops_count_as_loss_and_trace_continues() {
        // hop 2 never answers, destination at 4.
        let pinger = Arc::new(FakePinger::new(|req, _| match req.ttl {
            2 => Ok(EchoReply::timed_out()),
            t if t < 4 => reply(EchoStatus::TtlExpired, router(t), 10),
            _ => reply(EchoStatus::Success, dest(), 40),
        }));
        let (r, _) = run(pinger, &opts(3), &CancelToken::new()).await;
        let last = r.unwrap();
        assert_eq!(last.hops.len(), 4);
        let h2 = &last.hops[1];
        assert_eq!((h2.sent, h2.received), (3, 0));
        assert!((h2.loss_percent - 100.0).abs() < 1e-9);
        assert!(h2.addr.is_none() && h2.rtt.is_none());
        assert!(last.destination_reached);
    }

    #[tokio::test(start_paused = true)]
    async fn partial_loss_is_a_percentage() {
        // hop 1 drops every other probe.
        let pinger = Arc::new(FakePinger::new(|req, n| match req.ttl {
            1 if n % 2 == 1 => Ok(EchoReply::timed_out()),
            1 => reply(EchoStatus::TtlExpired, router(1), 2),
            _ => reply(EchoStatus::Success, dest(), 9),
        }));
        let (r, _) = run(pinger, &opts(4), &CancelToken::new()).await;
        let h1 = &r.unwrap().hops[0];
        assert_eq!((h1.sent, h1.received), (4, 2));
        assert!((h1.loss_percent - 50.0).abs() < 1e-9);
    }

    #[tokio::test(start_paused = true)]
    async fn unreachable_destination_probes_to_max_hops() {
        let pinger = Arc::new(FakePinger::new(|req, _| {
            if req.ttl <= 2 {
                reply(EchoStatus::TtlExpired, router(req.ttl), 5)
            } else {
                Ok(EchoReply::timed_out())
            }
        }));
        let o = MtrOptions {
            max_hops: 6,
            ..opts(2)
        };
        let (r, _) = run(Arc::clone(&pinger), &o, &CancelToken::new()).await;
        let last = r.unwrap();
        assert!(!last.destination_reached);
        assert_eq!(last.hops.len(), 6, "never goes past max_hops");
        assert!(pinger.requests().iter().all(|q| q.ttl <= 6));
        assert!(last.hops[2..]
            .iter()
            .all(|h| h.received == 0 && h.sent == 2));
    }

    #[tokio::test(start_paused = true)]
    async fn router_unreachable_ends_the_trace_without_reaching_destination() {
        let pinger = Arc::new(FakePinger::new(|req, _| match req.ttl {
            1 => reply(EchoStatus::TtlExpired, router(1), 1),
            2 => reply(EchoStatus::Unreachable, router(2), 2),
            _ => Ok(EchoReply::timed_out()),
        }));
        let o = MtrOptions {
            parallelism: 1,
            ..opts(2)
        };
        let (r, _) = run(Arc::clone(&pinger), &o, &CancelToken::new()).await;
        let last = r.unwrap();
        assert!(!last.destination_reached);
        assert_eq!(last.hops.len(), 2);
        assert!(pinger.requests().iter().all(|q| q.ttl <= 2));
    }

    #[tokio::test(start_paused = true)]
    async fn route_change_updates_address_and_keeps_stats() {
        // From cycle 2 on, hop 2 is answered by another router.
        let pinger = Arc::new(FakePinger::new(|req, n| match req.ttl {
            1 => reply(EchoStatus::TtlExpired, router(1), 1),
            2 => {
                let who = if n < 2 { router(2) } else { ip("10.9.9.9") };
                reply(EchoStatus::TtlExpired, who, 7)
            }
            _ => reply(EchoStatus::Success, dest(), 20),
        }));
        let (r, _) = run(pinger, &opts(4), &CancelToken::new()).await;
        let h2 = &r.unwrap().hops[1];
        assert_eq!(h2.addr, Some(ip("10.9.9.9")));
        assert_eq!(h2.other_addrs, vec![router(2)]);
        assert_eq!(h2.address_changes, 1);
        assert_eq!((h2.sent, h2.received), (4, 4));
    }

    #[tokio::test(start_paused = true)]
    async fn route_getting_shorter_truncates_the_table() {
        // Destination at hop 5 for two cycles, then at hop 3.
        let mut cycle = 0u32;
        let pinger = Arc::new(FakePinger::new(move |req, _| {
            if req.ttl == 1 {
                cycle += 1;
            }
            let dest_ttl = if cycle <= 2 { 5 } else { 3 };
            if req.ttl < dest_ttl {
                reply(EchoStatus::TtlExpired, router(req.ttl), 5)
            } else {
                reply(EchoStatus::Success, dest(), 30)
            }
        }));
        let o = MtrOptions {
            parallelism: 1,
            ..opts(4)
        };
        let (r, snaps) = run(Arc::clone(&pinger), &o, &CancelToken::new()).await;
        assert_eq!(snaps[1].hops.len(), 5);
        let last = r.unwrap();
        assert_eq!(last.hops.len(), 3);
        assert_eq!(last.hops[2].addr, Some(dest()));
        assert!(last.destination_reached);
        // After the change nothing was probed above the new destination hop.
        let reqs = pinger.requests();
        assert!(reqs[reqs.len() - 3..].iter().all(|q| q.ttl <= 3));
    }

    #[tokio::test(start_paused = true)]
    async fn route_getting_longer_is_found() {
        // Destination at hop 3 for the first cycle, at hop 5 afterwards. The probe at the old
        // destination hop now comes back "TTL exceeded", which makes the cycle look further.
        let mut cycle = 0u32;
        let pinger = Arc::new(FakePinger::new(move |req, _| {
            if req.ttl == 1 {
                cycle += 1;
            }
            let dest_ttl = if cycle <= 1 { 3 } else { 5 };
            if req.ttl < dest_ttl {
                reply(EchoStatus::TtlExpired, router(req.ttl), 5)
            } else {
                reply(EchoStatus::Success, dest(), 30)
            }
        }));
        let o = MtrOptions {
            parallelism: 1,
            ..opts(3)
        };
        let (r, snaps) = run(Arc::clone(&pinger), &o, &CancelToken::new()).await;
        assert_eq!(snaps[0].hops.len(), 3);
        let last = r.unwrap();
        assert_eq!(last.hops.len(), 5);
        assert_eq!(last.hops[4].addr, Some(dest()));
        assert!(last.destination_reached);
        assert!(pinger.requests().iter().all(|q| q.ttl <= 5));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_at_destination_hop_does_not_extend_the_search() {
        // The destination silently drops one probe; that must not trigger probing up to max_hops.
        let pinger = Arc::new(FakePinger::new(|req, n| {
            if req.ttl < 3 {
                reply(EchoStatus::TtlExpired, router(req.ttl), 5)
            } else if n == 1 {
                Ok(EchoReply::timed_out())
            } else {
                reply(EchoStatus::Success, dest(), 30)
            }
        }));
        let o = MtrOptions {
            parallelism: 1,
            ..opts(3)
        };
        let (r, _) = run(Arc::clone(&pinger), &o, &CancelToken::new()).await;
        let last = r.unwrap();
        assert!(pinger.requests().iter().all(|q| q.ttl <= 3));
        assert!(last.destination_reached);
        assert_eq!((last.hops[2].sent, last.hops[2].received), (3, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_between_cycles_returns_completed_cycles() {
        let pinger = Arc::new(straight_route(3));
        let cancel = CancelToken::new();
        let c2 = cancel.clone();
        let mut sink = FnSink(move |s: MtrSnapshot| {
            if s.cycle == 2 {
                c2.cancel();
            }
        });
        let r = mtr(
            pinger,
            dest(),
            &opts(10),
            &NameCache::disabled(),
            &cancel,
            &mut sink,
        )
        .await
        .unwrap();
        assert!(r.cancelled);
        assert_eq!(r.cycle, 2);
        assert!(r.hops.iter().all(|h| h.sent == 2));
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_mid_cycle_discards_that_cycle_promptly() {
        let pinger = Arc::new(straight_route(3).with_delay(Duration::from_secs(5)));
        let cancel = CancelToken::new();
        let c2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            c2.cancel();
        });
        let t0 = Instant::now();
        let (r, snaps) = run(pinger, &opts(10), &cancel).await;
        let r = r.unwrap();
        assert!(r.cancelled && r.cycle == 0 && r.hops.is_empty());
        assert!(snaps.is_empty());
        assert!(t0.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_receiver_stops_the_run() {
        let pinger = Arc::new(straight_route(3));
        let (mut tx, rx) = tokio::sync::mpsc::channel::<MtrSnapshot>(1);
        drop(rx);
        let r = mtr(
            Arc::clone(&pinger),
            dest(),
            &opts(5),
            &NameCache::disabled(),
            &CancelToken::new(),
            &mut tx,
        )
        .await
        .unwrap();
        assert!(r.cancelled);
        assert_eq!(pinger.requests().len(), 8, "only the first cycle ran");
    }

    #[tokio::test(start_paused = true)]
    async fn cycles_are_paced_by_the_interval() {
        let pinger = Arc::new(straight_route(2));
        let t0 = Instant::now();
        let mut sink = NullSink;
        mtr(
            pinger,
            dest(),
            &opts(3),
            &NameCache::disabled(),
            &CancelToken::new(),
            &mut sink,
        )
        .await
        .unwrap();
        assert_eq!(t0.elapsed(), Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn send_failure_on_every_probe_is_an_error() {
        let pinger = Arc::new(FakePinger::new(|_, _| Err(DiagError::Unsupported("icmp"))));
        let (r, snaps) = run(pinger, &opts(3), &CancelToken::new()).await;
        assert!(matches!(r, Err(DiagError::Unsupported(_))));
        assert!(snaps.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn reverse_names_appear_in_snapshots() {
        use crate::names::ReverseLookup;
        struct Names;
        impl ReverseLookup for Names {
            async fn reverse(&self, ip: IpAddr) -> Option<String> {
                (ip == router(1)).then(|| "edge.example.net".to_owned())
            }
        }
        let names = NameCache::new(Arc::new(Names), Duration::from_secs(1));
        let mut snaps = Vec::new();
        let mut sink = FnSink(|s: MtrSnapshot| snaps.push(s));
        mtr(
            Arc::new(straight_route(3)),
            dest(),
            &opts(2),
            &names,
            &CancelToken::new(),
            &mut sink,
        )
        .await
        .unwrap();
        assert_eq!(snaps[0].hops[0].name.as_deref(), Some("edge.example.net"));
        assert_eq!(snaps[0].hops[1].name, None);
    }

    #[test]
    fn terminal_rules() {
        let t = dest();
        let mk = |status, from: Option<IpAddr>| EchoReply {
            status,
            from,
            rtt: None,
            ttl: None,
        };
        assert_eq!(terminal(&mk(EchoStatus::Success, Some(t)), t), Some(true));
        assert_eq!(
            terminal(&mk(EchoStatus::TtlExpired, Some(router(1))), t),
            None
        );
        assert_eq!(terminal(&mk(EchoStatus::TimedOut, None), t), None);
        assert_eq!(terminal(&mk(EchoStatus::Other(11050), None), t), None);
        assert_eq!(
            terminal(&mk(EchoStatus::Unreachable, Some(router(2))), t),
            Some(false)
        );
        assert_eq!(
            terminal(&mk(EchoStatus::Unreachable, Some(t)), t),
            Some(true)
        );
        assert_eq!(terminal(&mk(EchoStatus::Unreachable, None), t), None);
    }
}

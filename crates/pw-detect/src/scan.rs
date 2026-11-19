// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded, exact distinct-destination-port / destination-host sets for scan detection.
//!
//! Every source starts with a tiny inline set (4 ports, 4 hosts). When a fifth live entry shows up the
//! source is *promoted* to a [`Tracker`] taken from a bounded slab ([`Trackers`]) and recycled through
//! a free list, so steady state does not allocate. Trackers hold up to [`PORT_CAP`] ports and
//! [`HOST_CAP`] hosts with the second they were last probed (entries older than the largest window,
//! 60 s, are reusable). When a tracker is full of live entries the overflow is remembered
//! (`*_sat`), and the distinct count is reported as at least the cap; configuration clamps the
//! thresholds to the caps, so saturation always means "fires".
//!
//! If the slab itself is exhausted (more than `max_scan_trackers` simultaneous scanners) the source
//! stays inline and overwrites its stalest entry: the scan is then under-counted and
//! `scan_tracker_exhausted` is incremented.
//!
//! Timestamps here are `second + 1` as `u32` so that `0` can mean "empty".

use std::net::IpAddr;

/// Exact distinct destination ports tracked per promoted source.
pub(crate) const PORT_CAP: usize = 512;
/// Exact distinct destination hosts tracked per promoted source.
pub(crate) const HOST_CAP: usize = 64;
const INLINE: usize = 4;
const NO_TRACKER: u32 = u32::MAX;
/// Largest detector window; entries older than this are free for reuse.
const MAX_WINDOW_SECS: u32 = 60;

#[derive(Debug, Clone, Copy, Default)]
struct Entry {
    key: u32,
    /// `second + 1`; 0 = empty.
    seen: u32,
}

impl Entry {
    fn age(self, now1: u32) -> u32 {
        now1.saturating_sub(self.seen)
    }

    fn live(self, now1: u32) -> bool {
        self.seen != 0 && self.age(now1) <= MAX_WINDOW_SECS
    }
}

/// Deterministic 32-bit hash of an address (SplitMix-style fold; no external state).
pub(crate) fn host_hash(ip: IpAddr) -> u32 {
    fn mix(mut x: u64) -> u64 {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^ (x >> 31)
    }
    let h = match ip.to_canonical() {
        IpAddr::V4(v4) => mix(u64::from(u32::from(v4))),
        IpAddr::V6(v6) => {
            let b = u128::from(v6);
            mix((b >> 64) as u64 ^ mix(b as u64))
        }
    };
    (h >> 32) as u32
}

enum Upsert {
    Done,
    Full,
}

fn upsert_inline(arr: &mut [Entry; INLINE], now1: u32, key: u32, force: bool) -> Upsert {
    let mut free: Option<usize> = None;
    for (i, e) in arr.iter_mut().enumerate() {
        if e.live(now1) {
            if e.key == key {
                e.seen = now1;
                return Upsert::Done;
            }
        } else if free.is_none() {
            free = Some(i);
        }
    }
    if let Some(i) = free {
        arr[i] = Entry { key, seen: now1 };
        return Upsert::Done;
    }
    if force {
        // Overwrite the stalest live entry (lossy, only when the slab is exhausted).
        let victim = arr
            .iter()
            .enumerate()
            .min_by_key(|(i, e)| (e.seen, *i))
            .map_or(0, |(i, _)| i);
        arr[victim] = Entry { key, seen: now1 };
        return Upsert::Done;
    }
    Upsert::Full
}

fn count_inline(arr: &[Entry; INLINE], now1: u32, window: u32) -> u32 {
    arr.iter()
        .filter(|e| e.seen != 0 && e.age(now1) <= window)
        .count() as u32
}

/// Expanded distinct sets of one source.
#[derive(Debug)]
pub(crate) struct Tracker {
    ports: Vec<Entry>,
    hosts: Vec<Entry>,
    /// `second + 1` of the last time a port/host was dropped because the set was full of live entries.
    ports_sat: u32,
    hosts_sat: u32,
}

impl Tracker {
    fn new() -> Self {
        Self {
            ports: Vec::with_capacity(PORT_CAP),
            hosts: Vec::with_capacity(HOST_CAP),
            ports_sat: 0,
            hosts_sat: 0,
        }
    }

    fn reset(&mut self) {
        self.ports.clear();
        self.hosts.clear();
        self.ports_sat = 0;
        self.hosts_sat = 0;
    }

    /// Insert or refresh. Returns `false` when the set is full of live entries and `key` was dropped.
    fn upsert(set: &mut Vec<Entry>, cap: usize, now1: u32, key: u32) -> bool {
        if let Some(e) = set.iter_mut().find(|e| e.key == key && e.seen != 0) {
            e.seen = now1;
            return true;
        }
        if set.len() < cap {
            set.push(Entry { key, seen: now1 });
            return true;
        }
        if let Some(e) = set.iter_mut().find(|e| !e.live(now1)) {
            *e = Entry { key, seen: now1 };
            return true;
        }
        false
    }

    fn touch(&mut self, now1: u32, port: u32, host: u32) {
        if !Self::upsert(&mut self.ports, PORT_CAP, now1, port) {
            self.ports_sat = now1;
        }
        if !Self::upsert(&mut self.hosts, HOST_CAP, now1, host) {
            self.hosts_sat = now1;
        }
    }

    fn count(set: &[Entry], sat: u32, cap: usize, now1: u32, window: u32) -> u32 {
        let n = set
            .iter()
            .filter(|e| e.seen != 0 && e.age(now1) <= window)
            .count();
        let n = if sat != 0 && now1.saturating_sub(sat) <= window {
            n.max(cap)
        } else {
            n
        };
        n as u32
    }

    fn any_live(&self, now1: u32) -> bool {
        self.ports.iter().any(|e| e.live(now1)) || self.hosts.iter().any(|e| e.live(now1))
    }
}

/// Bounded pool of [`Tracker`]s.
#[derive(Debug)]
pub(crate) struct Trackers {
    slots: Vec<Tracker>,
    free: Vec<u32>,
    max: usize,
}

impl Trackers {
    pub fn new(max: usize) -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            max,
        }
    }

    pub fn set_max(&mut self, max: usize) {
        self.max = max;
    }

    pub fn in_use(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    fn alloc(&mut self) -> Option<u32> {
        if let Some(i) = self.free.pop() {
            return Some(i);
        }
        if self.slots.len() < self.max {
            let i = u32::try_from(self.slots.len()).ok()?;
            self.slots.push(Tracker::new());
            return Some(i);
        }
        None
    }

    fn release(&mut self, idx: u32) {
        if let Some(t) = self.slots.get_mut(idx as usize) {
            t.reset();
            self.free.push(idx);
        }
    }

    fn get(&self, idx: u32) -> Option<&Tracker> {
        self.slots.get(idx as usize)
    }

    fn get_mut(&mut self, idx: u32) -> Option<&mut Tracker> {
        self.slots.get_mut(idx as usize)
    }
}

/// Outcome of recording a probe.
pub(crate) enum Touch {
    Ok,
    /// The slab is exhausted; the probe was recorded lossily.
    Exhausted,
}

/// The per-source probe record: an inline set plus an optional promoted [`Tracker`].
#[derive(Debug)]
pub(crate) struct Probes {
    ports: [Entry; INLINE],
    hosts: [Entry; INLINE],
    tracker: u32,
}

impl Probes {
    pub fn new() -> Self {
        Self {
            ports: [Entry::default(); INLINE],
            hosts: [Entry::default(); INLINE],
            tracker: NO_TRACKER,
        }
    }

    /// Record a probe of `port` on destination `host` (a [`host_hash`]) at `sec`.
    pub fn touch(&mut self, sec: u64, port: u16, host: u32, trackers: &mut Trackers) -> Touch {
        let now1 = u32::try_from(sec.saturating_add(1)).unwrap_or(u32::MAX);
        let port = u32::from(port);
        if self.tracker != NO_TRACKER {
            if let Some(t) = trackers.get_mut(self.tracker) {
                t.touch(now1, port, host);
                return Touch::Ok;
            }
            self.tracker = NO_TRACKER;
        }
        let p = upsert_inline(&mut self.ports, now1, port, false);
        let h = upsert_inline(&mut self.hosts, now1, host, false);
        if matches!(p, Upsert::Done) && matches!(h, Upsert::Done) {
            return Touch::Ok;
        }
        match trackers.alloc() {
            Some(idx) => {
                if let Some(t) = trackers.get_mut(idx) {
                    for e in self.ports.iter().filter(|e| e.live(now1)) {
                        t.touch(now1, e.key, host);
                    }
                    for e in self.hosts.iter().filter(|e| e.live(now1)) {
                        t.touch(now1, port, e.key);
                    }
                    t.touch(now1, port, host);
                    self.tracker = idx;
                    self.ports = [Entry::default(); INLINE];
                    self.hosts = [Entry::default(); INLINE];
                }
                Touch::Ok
            }
            None => {
                upsert_inline(&mut self.ports, now1, port, true);
                upsert_inline(&mut self.hosts, now1, host, true);
                Touch::Exhausted
            }
        }
    }

    /// `(distinct ports, distinct hosts)` probed during the last `window` completed seconds plus
    /// the one in progress.
    pub fn distinct(&self, cur_sec: u64, window: u32, trackers: &Trackers) -> (u32, u32) {
        let now1 = u32::try_from(cur_sec.saturating_add(1)).unwrap_or(u32::MAX);
        if self.tracker != NO_TRACKER {
            if let Some(t) = trackers.get(self.tracker) {
                return (
                    Tracker::count(&t.ports, t.ports_sat, PORT_CAP, now1, window),
                    Tracker::count(&t.hosts, t.hosts_sat, HOST_CAP, now1, window),
                );
            }
        }
        (
            count_inline(&self.ports, now1, window),
            count_inline(&self.hosts, now1, window),
        )
    }

    /// Whether any entry could still matter to a detector window.
    pub fn has_live(&self, cur_sec: u64, trackers: &Trackers) -> bool {
        let now1 = u32::try_from(cur_sec.saturating_add(1)).unwrap_or(u32::MAX);
        if self.tracker != NO_TRACKER {
            if let Some(t) = trackers.get(self.tracker) {
                return t.any_live(now1);
            }
        }
        self.ports.iter().any(|e| e.live(now1)) || self.hosts.iter().any(|e| e.live(now1))
    }

    /// Return the tracker (if any) to the pool.
    pub fn release(&mut self, trackers: &mut Trackers) {
        if self.tracker != NO_TRACKER {
            trackers.release(self.tracker);
            self.tracker = NO_TRACKER;
        }
    }

    /// Demote to the inline set when everything expired, freeing the tracker.
    pub fn compact(&mut self, cur_sec: u64, trackers: &mut Trackers) {
        if self.tracker != NO_TRACKER && !self.has_live(cur_sec, trackers) {
            self.release(trackers);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(n: u8) -> u32 {
        host_hash(IpAddr::from([198, 51, 100, n]))
    }

    #[test]
    fn promotes_after_four_ports_and_counts_exactly() {
        let mut trackers = Trackers::new(4);
        let mut p = Probes::new();
        for port in 1..=300u16 {
            p.touch(1_000, port, host(1), &mut trackers);
        }
        assert_eq!(trackers.in_use(), 1);
        assert_eq!(p.distinct(1_001, 10, &trackers), (300, 1));
        // Same ports again do not change the count.
        for port in 1..=300u16 {
            p.touch(1_001, port, host(1), &mut trackers);
        }
        assert_eq!(p.distinct(1_001, 10, &trackers).0, 300);
        // Window expiry: nothing newer than 1_001, evaluated 11 s later.
        assert_eq!(p.distinct(1_012, 10, &trackers).0, 0);
    }

    #[test]
    fn saturates_at_cap_and_reports_at_least_cap() {
        let mut trackers = Trackers::new(1);
        let mut p = Probes::new();
        for port in 1..=1_000u16 {
            p.touch(5, port, host(1), &mut trackers);
        }
        assert_eq!(p.distinct(6, 10, &trackers).0 as usize, PORT_CAP);
    }

    #[test]
    fn exhausted_slab_is_reported_and_stays_bounded() {
        let mut trackers = Trackers::new(1);
        let mut a = Probes::new();
        let mut b = Probes::new();
        for port in 1..=10u16 {
            a.touch(5, port, host(1), &mut trackers);
        }
        let mut exhausted = false;
        for port in 1..=10u16 {
            if matches!(b.touch(5, port, host(2), &mut trackers), Touch::Exhausted) {
                exhausted = true;
            }
        }
        assert!(exhausted);
        assert_eq!(trackers.in_use(), 1);
        assert!(b.distinct(6, 10, &trackers).0 <= INLINE as u32);
        a.release(&mut trackers);
        assert_eq!(trackers.in_use(), 0);
    }

    #[test]
    fn compact_releases_expired_trackers() {
        let mut trackers = Trackers::new(2);
        let mut p = Probes::new();
        for port in 1..=20u16 {
            p.touch(100, port, host(1), &mut trackers);
        }
        assert_eq!(trackers.in_use(), 1);
        p.compact(150, &mut trackers);
        assert_eq!(trackers.in_use(), 1);
        p.compact(200, &mut trackers);
        assert_eq!(trackers.in_use(), 0);
    }

    #[test]
    fn hosts_are_counted_separately_from_ports() {
        let mut trackers = Trackers::new(2);
        let mut p = Probes::new();
        for n in 1..=40u8 {
            p.touch(10, 22, host(n), &mut trackers);
        }
        assert_eq!(p.distinct(11, 10, &trackers), (1, 40));
    }
}

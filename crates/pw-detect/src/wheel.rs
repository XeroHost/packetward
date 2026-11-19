// SPDX-License-Identifier: GPL-3.0-or-later
//! Fixed-size, allocation-free sliding counters.
//!
//! A [`Wheel`] is a ring of `N` cells, each tagged with the epoch (`second / LEN`) it holds. Writing
//! into an epoch lazily resets a cell that still holds an older epoch, so nothing has to run per
//! tick or per source to "roll" the window. Reading sums the `epochs` most recent *completed*
//! epochs (`cur-epochs ..= cur-1`); the epoch in progress is excluded.

use pw_core::{PacketMeta, Protocol, TCP_ACK, TCP_RST, TCP_SYN};

const EMPTY: u32 = u32::MAX;

/// Summed counters of a window, widened to `u64`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Totals {
    pub pkts: u64,
    pub bytes: u64,
    /// Inbound SYN-only packets (new connection attempts).
    pub syn: u64,
    /// Inbound ACK-bearing TCP packets that are neither SYN nor RST.
    pub ack: u64,
    pub udp: u64,
    pub udp_bytes: u64,
    pub icmp: u64,
    pub out_pkts: u64,
    pub out_bytes: u64,
    /// Outbound SYN-ACKs: how many handshakes this machine answered.
    pub synack_out: u64,
}

pub(crate) trait Slot: Copy + Default {
    fn accumulate(&self, totals: &mut Totals);
}

#[derive(Clone, Copy)]
struct Cell<C: Slot> {
    epoch: u32,
    slot: C,
}

pub(crate) struct Wheel<C: Slot, const N: usize, const LEN: u64> {
    cells: [Cell<C>; N],
}

impl<C: Slot, const N: usize, const LEN: u64> Wheel<C, N, LEN> {
    pub fn new() -> Self {
        Self {
            cells: std::array::from_fn(|_| Cell {
                epoch: EMPTY,
                slot: C::default(),
            }),
        }
    }

    fn epoch_of(sec: u64) -> u32 {
        u32::try_from(sec / LEN).map_or(EMPTY - 1, |e| e.min(EMPTY - 1))
    }

    /// The counters of the epoch that contains `sec`, reset first if the cell held an older one.
    pub fn at(&mut self, sec: u64) -> &mut C {
        let epoch = Self::epoch_of(sec);
        let idx = epoch as usize % N;
        let cell = &mut self.cells[idx];
        if cell.epoch != epoch {
            cell.epoch = epoch;
            cell.slot = C::default();
        }
        &mut cell.slot
    }

    /// Sum of the `epochs` completed epochs before the one containing `cur_sec`.
    /// `epochs` must be < `N` so the epoch in progress never aliases a counted one.
    pub fn totals(&self, cur_sec: u64, epochs: usize) -> Totals {
        debug_assert!(epochs < N);
        let cur = u64::from(Self::epoch_of(cur_sec));
        let mut totals = Totals::default();
        for back in 1..=epochs as u64 {
            if back > cur {
                break;
            }
            // `cur - back` < `cur` <= u32::MAX - 1, so the conversion cannot fail.
            let Ok(epoch) = u32::try_from(cur - back) else {
                break;
            };
            let cell = &self.cells[epoch as usize % N];
            if cell.epoch == epoch {
                cell.slot.accumulate(&mut totals);
            }
        }
        totals
    }
}

/// What one inbound packet contributes (the packet itself is always +1 in `pkts`).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Delta {
    pub bytes: u32,
    pub syn: u32,
    pub ack: u32,
    pub udp: u32,
    pub udp_bytes: u32,
    pub icmp: u32,
}

impl Delta {
    /// Classify an inbound packet. Returns the delta and whether the packet is a *probe* for the
    /// port-scan detector (SYN-only, NULL/FIN/Xmas, or UDP from a non-well-known source port).
    pub fn classify(p: &PacketMeta) -> (Delta, bool) {
        let mut d = Delta {
            bytes: p.len,
            ..Delta::default()
        };
        let mut probe = false;
        match p.proto {
            Protocol::Tcp => {
                let f = p.tcp_flags;
                if f & (TCP_SYN | TCP_ACK) == TCP_SYN {
                    d.syn = 1;
                    probe = f & TCP_RST == 0;
                } else if f & (TCP_SYN | TCP_ACK | TCP_RST) == 0 {
                    // NULL, FIN-only, Xmas: stealth-scan probes.
                    probe = true;
                } else if f & TCP_ACK != 0 && f & (TCP_SYN | TCP_RST) == 0 {
                    d.ack = 1;
                }
            }
            Protocol::Udp => {
                d.udp = 1;
                d.udp_bytes = p.len;
                probe = p.src_port >= 1024;
            }
            Protocol::Icmp => d.icmp = 1,
            Protocol::Other(_) => {}
        }
        (d, probe)
    }
}

/// Per-source counters (28 bytes). Saturating: a single epoch cannot overflow into nonsense.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SrcCounters {
    pkts: u32,
    bytes: u32,
    syn: u32,
    ack: u32,
    udp: u32,
    udp_bytes: u32,
    icmp: u32,
}

impl SrcCounters {
    pub fn add(&mut self, d: &Delta) {
        self.pkts = self.pkts.saturating_add(1);
        self.bytes = self.bytes.saturating_add(d.bytes);
        self.syn = self.syn.saturating_add(d.syn);
        self.ack = self.ack.saturating_add(d.ack);
        self.udp = self.udp.saturating_add(d.udp);
        self.udp_bytes = self.udp_bytes.saturating_add(d.udp_bytes);
        self.icmp = self.icmp.saturating_add(d.icmp);
    }
}

impl Slot for SrcCounters {
    fn accumulate(&self, t: &mut Totals) {
        t.pkts += u64::from(self.pkts);
        t.bytes += u64::from(self.bytes);
        t.syn += u64::from(self.syn);
        t.ack += u64::from(self.ack);
        t.udp += u64::from(self.udp);
        t.udp_bytes += u64::from(self.udp_bytes);
        t.icmp += u64::from(self.icmp);
    }
}

/// Whole-machine counters, including the outbound side (which only informs ratios and metrics).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct GlobalCounters {
    t: Totals,
}

impl GlobalCounters {
    pub fn add_inbound(&mut self, d: &Delta) {
        let t = &mut self.t;
        t.pkts = t.pkts.saturating_add(1);
        t.bytes = t.bytes.saturating_add(u64::from(d.bytes));
        t.syn = t.syn.saturating_add(u64::from(d.syn));
        t.ack = t.ack.saturating_add(u64::from(d.ack));
        t.udp = t.udp.saturating_add(u64::from(d.udp));
        t.udp_bytes = t.udp_bytes.saturating_add(u64::from(d.udp_bytes));
        t.icmp = t.icmp.saturating_add(u64::from(d.icmp));
    }

    pub fn add_outbound(&mut self, p: &PacketMeta) {
        let t = &mut self.t;
        t.out_pkts = t.out_pkts.saturating_add(1);
        t.out_bytes = t.out_bytes.saturating_add(u64::from(p.len));
        if p.is_syn_ack() {
            t.synack_out = t.synack_out.saturating_add(1);
        }
    }
}

impl Slot for GlobalCounters {
    fn accumulate(&self, t: &mut Totals) {
        let s = &self.t;
        t.pkts += s.pkts;
        t.bytes += s.bytes;
        t.syn += s.syn;
        t.ack += s.ack;
        t.udp += s.udp;
        t.udp_bytes += s.udp_bytes;
        t.icmp += s.icmp;
        t.out_pkts += s.out_pkts;
        t.out_bytes += s.out_bytes;
        t.synack_out += s.synack_out;
    }
}

/// New-connection counter for connection snapshots (reported in `syn`).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NewCounter(pub u32);

impl Slot for NewCounter {
    fn accumulate(&self, t: &mut Totals) {
        t.syn += u64::from(self.0);
    }
}

pub(crate) type FineWheel<C> = Wheel<C, 11, 1>;
pub(crate) type CoarseWheel<C> = Wheel<C, 7, 10>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wheel_sums_only_completed_epochs_in_range() {
        let mut w: FineWheel<NewCounter> = Wheel::new();
        w.at(100).0 = 5;
        w.at(105).0 = 7;
        // Epoch 105 is in progress at 105 and excluded; epoch 100 is inside the last 10 completed.
        assert_eq!(w.totals(105, 10).syn, 5);
        assert_eq!(w.totals(106, 10).syn, 12);
        // 100 is cur-10 at 110 (still inside), cur-11 at 111 (expired).
        assert_eq!(w.totals(110, 10).syn, 12);
        assert_eq!(w.totals(111, 10).syn, 7);
        assert_eq!(w.totals(106, 1).syn, 7);
    }

    #[test]
    fn wheel_cell_is_reused_without_leaking_old_counts() {
        let mut w: FineWheel<NewCounter> = Wheel::new();
        w.at(0).0 = 9;
        // Same slot (11 epochs later) must start from zero.
        assert_eq!(w.at(11).0, 0);
    }

    #[test]
    fn wheel_near_zero_does_not_underflow() {
        let mut w: FineWheel<NewCounter> = Wheel::new();
        w.at(0).0 = 3;
        assert_eq!(w.totals(2, 10).syn, 3);
        assert_eq!(w.totals(0, 10).syn, 0);
    }
}

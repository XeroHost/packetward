// SPDX-License-Identifier: GPL-3.0-or-later
//! Turns raw network state into the once-a-second snapshot the clients see.

use std::cmp::Reverse;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use pw_netstat::aggregate::{count_connections, rdp_peers, top_remote};
use pw_netstat::{
    classify_kind, counts_toward_total, ConnectionTable, NetStat, RateTracker, DEFAULT_RDP_PORT,
};
use pw_proto::{
    InterfaceKind, InterfaceStats, LiveStats, LogonAudit, RdpSession, RdpTrust, TrafficTotals,
};

use crate::trust::TrustState;

/// How many remote addresses `live.stats` carries.
pub const TOP_REMOTE: usize = 10;

/// What one poll produced: the aggregate for `live.stats` and the full table for
/// `netstat.connections`.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub stats: LiveStats,
    pub table: Arc<ConnectionTable>,
}

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Polls a [`NetStat`] source. Synchronous and clock-injected so it is easy to test; the engine
/// runs it on a blocking thread.
pub struct Poller {
    netstat: Arc<dyn NetStat>,
    tracker: RateTracker,
    seq: u64,
    /// Refresh the (comparatively slow) RDP data every this many polls.
    rdp_every: u32,
    polls_since_rdp: u32,
    rdp_sessions: Vec<RdpSession>,
    rdp_port: u16,
    last_table: Arc<ConnectionTable>,
    trust: Arc<TrustState>,
    /// The audit policy changes rarely; re-read it every this many polls.
    polls_since_audit: u32,
    audit: LogonAudit,
}

const AUDIT_EVERY: u32 = 30;

impl Poller {
    pub fn new(netstat: Arc<dyn NetStat>, rdp_every: u32, trust: Arc<TrustState>) -> Self {
        Self {
            netstat,
            tracker: RateTracker::new(),
            seq: 0,
            rdp_every: rdp_every.max(1),
            polls_since_rdp: u32::MAX, // refresh on the first poll
            rdp_sessions: Vec::new(),
            rdp_port: DEFAULT_RDP_PORT,
            last_table: Arc::new(ConnectionTable::default()),
            trust,
            polls_since_audit: u32::MAX, // read on the first poll
            audit: LogonAudit::default(),
        }
    }

    /// One poll. A source that fails keeps the previous value for that part instead of failing the
    /// whole snapshot: during an attack is exactly when a half-broken API must not blank the UI.
    pub fn poll(&mut self, now: Instant, unix_ms: u64) -> Snapshot {
        self.seq += 1;

        match self.netstat.connections() {
            Ok(table) => self.last_table = Arc::new(table),
            Err(err) => {
                tracing::warn!(%err, "could not read the connection table; keeping the last one")
            }
        }
        let table = Arc::clone(&self.last_table);

        self.polls_since_rdp = self.polls_since_rdp.saturating_add(1);
        if self.polls_since_rdp >= self.rdp_every {
            self.polls_since_rdp = 0;
            self.rdp_port = self.netstat.rdp_port();
            match self.netstat.rdp_sessions() {
                Ok(sessions) => self.rdp_sessions = sessions,
                Err(err) => {
                    tracing::warn!(%err, "could not read the RDP sessions; keeping the last list")
                }
            }
        }

        self.polls_since_audit = self.polls_since_audit.saturating_add(1);
        if self.polls_since_audit >= AUDIT_EVERY {
            self.polls_since_audit = 0;
            self.audit = self.netstat.logon_audit();
        }

        let (interfaces, totals) = match self.netstat.interfaces() {
            Ok(samples) => self.interface_stats(now, &samples),
            Err(err) => {
                tracing::warn!(%err, "could not read the interface counters");
                (Vec::new(), TrafficTotals::default())
            }
        };

        let stats = LiveStats {
            seq: self.seq,
            unix_ms,
            interfaces,
            totals,
            connections: count_connections(&table.rows),
            top_remote: top_remote(&table.rows, TOP_REMOTE),
            rdp_sessions: self.rdp_sessions.clone(),
            rdp_peers: rdp_peers(&table.rows, self.rdp_port),
            rdp_port: self.rdp_port,
            rdp_trust: RdpTrust {
                window_days: self.trust.window_days(),
                feed: self.trust.feed(),
                audit: self.audit,
                addresses: self.trust.addresses(unix_ms),
            },
        };
        Snapshot { stats, table }
    }

    fn interface_stats(
        &mut self,
        now: Instant,
        samples: &[pw_netstat::InterfaceSample],
    ) -> (Vec<InterfaceStats>, TrafficTotals) {
        let counters: Vec<_> = samples.iter().map(|s| (s.index, s.counters)).collect();
        let rates = self.tracker.update(now, &counters);

        let mut totals = TrafficTotals::default();
        let mut slowest: Option<u64> = None;
        let mut shown = Vec::new();
        for sample in samples {
            let kind = classify_kind(sample);
            let counted = counts_toward_total(sample, kind);
            let rate = rates.get(&sample.index).copied().unwrap_or_default();
            if counted {
                totals.in_bps += rate.in_bps;
                totals.out_bps += rate.out_bps;
                totals.in_pps += rate.in_pps;
                totals.out_pps += rate.out_pps;
                if sample.link_speed_bps > 0 {
                    slowest = Some(
                        slowest.map_or(sample.link_speed_bps, |s| s.min(sample.link_speed_bps)),
                    );
                }
            }
            if !worth_showing(sample, kind, counted) {
                continue;
            }
            shown.push(InterfaceStats {
                index: sample.index,
                name: sample.name.clone(),
                description: sample.description.clone(),
                kind,
                up: sample.oper_up,
                counts_toward_total: counted,
                link_speed_bps: sample.link_speed_bps,
                in_bps: rate.in_bps,
                out_bps: rate.out_bps,
                in_pps: rate.in_pps,
                out_pps: rate.out_pps,
            });
        }
        totals.link_speed_bps = slowest.unwrap_or(0);
        // Counted adapters first, then by name: stable order from one tick to the next.
        shown.sort_by(|a, b| {
            (Reverse(a.counts_toward_total), &a.name)
                .cmp(&(Reverse(b.counts_toward_total), &b.name))
        });
        (shown, totals)
    }
}

/// The per-adapter breakdown lists real adapters and tunnels that actually carried traffic. Filter
/// layers (they repeat the adapter below them), loopback, down interfaces and idle placeholders
/// such as the WAN miniports are noise.
fn worth_showing(sample: &pw_netstat::InterfaceSample, kind: InterfaceKind, counted: bool) -> bool {
    if counted {
        return true;
    }
    if sample.filter || !sample.oper_up || kind == InterfaceKind::Loopback {
        return false;
    }
    sample.counters.in_octets > 0 || sample.counters.out_octets > 0
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pw_netstat::fake::FakeNetStat;
    use pw_netstat::{if_type, Counters, InterfaceSample};
    use pw_proto::{Connection, Proto, RdpSessionState, TcpState};

    use super::*;

    fn nic(index: u32, name: &str, counters: Counters) -> InterfaceSample {
        InterfaceSample {
            index,
            name: name.into(),
            description: "Red Hat VirtIO Ethernet Adapter".into(),
            if_type: if_type::ETHERNET,
            oper_up: true,
            hardware: true,
            filter: false,
            connector_present: true,
            has_default_gateway: true,
            link_speed_bps: 10_000_000_000,
            counters,
        }
    }

    fn established(remote: &str, local_port: u16, pid: u32) -> Connection {
        Connection {
            proto: Proto::Tcp,
            local_addr: "10.0.0.5".into(),
            local_port,
            remote_addr: remote.into(),
            remote_port: 50000,
            state: Some(TcpState::Established),
            pid,
        }
    }

    fn poller(fake: &Arc<FakeNetStat>) -> Poller {
        Poller::new(fake.clone(), 5, TrustState::new(30))
    }

    #[test]
    fn totals_sum_only_real_adapters_and_filter_layers_never_double_count() {
        let fake = Arc::new(FakeNetStat::new());
        let t0 = Instant::now();
        let mut poller = poller(&fake);

        // A real NIC, its two filter layers (identical counters) and a loopback.
        let make = |bytes: u64| {
            let counters = Counters {
                in_octets: bytes,
                out_octets: bytes / 2,
                in_packets: bytes / 100,
                out_packets: bytes / 200,
            };
            let mut filter_a = nic(16, "Ethernet-WFP", counters);
            filter_a.filter = true;
            filter_a.hardware = false;
            filter_a.has_default_gateway = false;
            let mut filter_b = filter_a.clone();
            filter_b.index = 17;
            let mut loopback = nic(1, "Loopback", counters);
            loopback.if_type = if_type::LOOPBACK;
            loopback.has_default_gateway = false;
            vec![nic(15, "Ethernet", counters), filter_a, filter_b, loopback]
        };
        fake.set_interfaces(make(0));
        poller.poll(t0, 1_000);
        fake.set_interfaces(make(1_250_000));
        let snapshot = poller.poll(t0 + Duration::from_secs(1), 2_000);

        // 1.25 MB in one second = 10 Mbit/s in, 5 Mbit/s out — counted once, not three times.
        assert_eq!(snapshot.stats.totals.in_bps, 10_000_000.0);
        assert_eq!(snapshot.stats.totals.out_bps, 5_000_000.0);
        assert_eq!(snapshot.stats.totals.link_speed_bps, 10_000_000_000);
        assert_eq!(
            snapshot.stats.interfaces.len(),
            1,
            "filter layers and loopback are hidden"
        );
        assert_eq!(snapshot.stats.interfaces[0].name, "Ethernet");
    }

    #[test]
    fn tunnels_with_traffic_are_shown_but_not_summed_and_idle_ones_are_hidden() {
        let fake = Arc::new(FakeNetStat::new());
        let t0 = Instant::now();
        let mut poller = poller(&fake);
        let busy = Counters {
            in_octets: 0,
            out_octets: 0,
            in_packets: 0,
            out_packets: 0,
        };
        let make = |tunnel_bytes: u64| {
            let mut wireguard = nic(
                30,
                "WireGuard",
                Counters {
                    in_octets: tunnel_bytes,
                    ..busy
                },
            );
            wireguard.description = "WireGuard Tunnel".into();
            wireguard.hardware = false;
            wireguard.has_default_gateway = false;
            let mut idle = nic(31, "Local Area Connection* 7", busy);
            idle.description = "WAN Miniport (IP)".into();
            idle.hardware = false;
            idle.has_default_gateway = false;
            vec![nic(15, "Ethernet", busy), wireguard, idle]
        };
        fake.set_interfaces(make(1));
        poller.poll(t0, 1);
        fake.set_interfaces(make(1_000_001));
        let snapshot = poller.poll(t0 + Duration::from_secs(1), 2);

        let names: Vec<&str> = snapshot
            .stats
            .interfaces
            .iter()
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["Ethernet", "WireGuard"],
            "counted adapter first, idle WAN miniport hidden"
        );
        let wireguard = &snapshot.stats.interfaces[1];
        assert_eq!(wireguard.kind, InterfaceKind::Tunnel);
        assert!(!wireguard.counts_toward_total);
        assert!(wireguard.in_bps > 0.0);
        assert_eq!(
            snapshot.stats.totals.in_bps, 0.0,
            "the tunnel is not part of the total"
        );
    }

    #[test]
    fn connection_counts_top_remote_and_rdp_peers_come_from_the_full_table() {
        let fake = Arc::new(FakeNetStat::new());
        fake.set_connections(ConnectionTable {
            rows: vec![
                established("14.224.238.73", 3389, 1340),
                established("143.20.99.200", 3389, 1340),
                established("203.0.113.5", 443, 800),
                established("203.0.113.5", 443, 800),
            ],
            processes: [(1340, "svchost.exe".to_owned())].into(),
        });
        fake.set_rdp_sessions(vec![RdpSession {
            session_id: 2,
            user: "Administrator".into(),
            state: RdpSessionState::Active,
            reported_addr: Some("100.102.180.59".into()),
            client_name: "LAPTOP".into(),
        }]);
        let snapshot = poller(&fake).poll(Instant::now(), 5);

        assert_eq!(snapshot.stats.connections.total, 4);
        assert_eq!(snapshot.stats.connections.established, 4);
        assert_eq!(snapshot.stats.top_remote[0].addr, "203.0.113.5");
        assert_eq!(snapshot.stats.rdp_peers, ["14.224.238.73", "143.20.99.200"]);
        assert_eq!(snapshot.stats.rdp_port, 3389);
        assert_eq!(
            snapshot.stats.rdp_sessions[0].reported_addr.as_deref(),
            Some("100.102.180.59")
        );
        assert_eq!(snapshot.table.rows.len(), 4);
    }

    #[test]
    fn a_failing_source_keeps_the_previous_table_instead_of_blanking_the_snapshot() {
        let fake = Arc::new(FakeNetStat::new());
        fake.set_connections(ConnectionTable {
            rows: vec![established("198.51.100.1", 443, 1)],
            processes: Default::default(),
        });
        let mut poller = poller(&fake);
        let first = poller.poll(Instant::now(), 1);
        assert_eq!(first.stats.connections.total, 1);

        fake.set_connections_failing(true);
        let second = poller.poll(Instant::now(), 2);
        assert_eq!(
            second.stats.connections.total, 1,
            "the last good table is kept"
        );
        assert_eq!(second.stats.seq, 2, "the sequence still advances");
    }

    #[test]
    fn sequence_increases_and_rdp_data_is_refreshed_every_n_polls() {
        let fake = Arc::new(FakeNetStat::new());
        let mut poller = Poller::new(fake.clone(), 3, TrustState::new(30));
        let session = |user: &str| RdpSession {
            session_id: 1,
            user: user.into(),
            state: RdpSessionState::Active,
            reported_addr: None,
            client_name: String::new(),
        };
        fake.set_rdp_sessions(vec![session("first")]);
        assert_eq!(
            poller.poll(Instant::now(), 1).stats.rdp_sessions[0].user,
            "first"
        ); // poll 1: refresh
        fake.set_rdp_sessions(vec![session("second")]);
        assert_eq!(
            poller.poll(Instant::now(), 2).stats.rdp_sessions[0].user,
            "first"
        ); // cached
        assert_eq!(
            poller.poll(Instant::now(), 3).stats.rdp_sessions[0].user,
            "first"
        ); // cached
        let fourth = poller.poll(Instant::now(), 4); // refresh again
        assert_eq!(fourth.stats.rdp_sessions[0].user, "second");
        assert_eq!(fourth.stats.seq, 4);
    }
}

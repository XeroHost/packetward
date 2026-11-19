// SPDX-License-Identifier: GPL-3.0-or-later
//! Counts and rankings computed from the **full** connection table, before any row cap.

use std::collections::HashMap;
use std::net::IpAddr;

use pw_proto::{Connection, ConnectionCounts, Proto, RemoteTalker, TcpState};

pub fn count_connections(rows: &[Connection]) -> ConnectionCounts {
    let mut counts = ConnectionCounts {
        total: u32::try_from(rows.len()).unwrap_or(u32::MAX),
        ..ConnectionCounts::default()
    };
    for row in rows {
        match (row.proto, row.state) {
            (Proto::Udp, _) => counts.udp += 1,
            (Proto::Tcp, Some(TcpState::Established)) => counts.established += 1,
            (Proto::Tcp, Some(TcpState::Listen)) => counts.listen += 1,
            (Proto::Tcp, Some(TcpState::TimeWait)) => counts.time_wait += 1,
            (Proto::Tcp, Some(TcpState::SynReceived)) => counts.syn_received += 1,
            (Proto::Tcp, _) => counts.other_tcp += 1,
        }
    }
    counts
}

/// Remote addresses holding the most connections.
///
/// Counts every TCP state except LISTEN (a flood leaves SYN_RECEIVED and TIME_WAIT rows, which are
/// exactly what should rank), and ignores rows without a real remote: wildcard (`0.0.0.0`, `::`),
/// loopback and UDP endpoints. IPv4-mapped IPv6 addresses are folded into their IPv4 form. Ties
/// break by address so the order is stable from one second to the next.
pub fn top_remote(rows: &[Connection], limit: usize) -> Vec<RemoteTalker> {
    let mut per_addr: HashMap<IpAddr, u32> = HashMap::new();
    for row in rows {
        if row.proto != Proto::Tcp || row.state == Some(TcpState::Listen) {
            continue;
        }
        let Ok(addr) = row.remote_addr.parse::<IpAddr>() else {
            continue;
        };
        let addr = addr.to_canonical();
        if addr.is_unspecified() || addr.is_loopback() {
            continue;
        }
        *per_addr.entry(addr).or_insert(0) += 1;
    }
    let mut ranked: Vec<(IpAddr, u32)> = per_addr.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked
        .into_iter()
        .take(limit)
        .map(|(addr, connections)| RemoteTalker {
            addr: addr.to_string(),
            connections,
        })
        .collect()
}

/// Addresses with an ESTABLISHED TCP connection to the RDP listener port, as the server sees them.
/// Unlike `WTSClientAddress` (what the client says about itself) this is the real source address, but it
/// also includes peers that have not logged in (a brute-force bot holds such a connection during
/// NLA), so it does not by itself identify the legitimate client.
///
/// IPv4-mapped IPv6 peers are folded to IPv4; the result is sorted and de-duplicated.
pub fn rdp_peers(rows: &[Connection], rdp_port: u16) -> Vec<String> {
    let mut peers: Vec<IpAddr> = rows
        .iter()
        .filter(|row| {
            row.proto == Proto::Tcp
                && row.state == Some(TcpState::Established)
                && row.local_port == rdp_port
        })
        .filter_map(|row| row.remote_addr.parse::<IpAddr>().ok())
        .map(|addr| addr.to_canonical())
        .filter(|addr| !addr.is_unspecified() && !addr.is_loopback())
        .collect();
    peers.sort();
    peers.dedup();
    peers.into_iter().map(|addr| addr.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(remote: &str, state: TcpState) -> Connection {
        Connection {
            proto: Proto::Tcp,
            local_addr: "10.0.0.5".into(),
            local_port: 3389,
            remote_addr: remote.into(),
            remote_port: 50000,
            state: Some(state),
            pid: 4,
        }
    }

    fn udp() -> Connection {
        Connection {
            proto: Proto::Udp,
            local_addr: "0.0.0.0".into(),
            local_port: 5353,
            remote_addr: String::new(),
            remote_port: 0,
            state: None,
            pid: 1,
        }
    }

    #[test]
    fn counts_every_state_and_udp() {
        let rows = vec![
            tcp("1.1.1.1", TcpState::Established),
            tcp("1.1.1.2", TcpState::Established),
            tcp("", TcpState::Listen),
            tcp("2.2.2.2", TcpState::TimeWait),
            tcp("3.3.3.3", TcpState::SynReceived),
            tcp("4.4.4.4", TcpState::FinWait1),
            udp(),
            udp(),
        ];
        let counts = count_connections(&rows);
        assert_eq!(counts.total, 8);
        assert_eq!(counts.established, 2);
        assert_eq!(counts.listen, 1);
        assert_eq!(counts.time_wait, 1);
        assert_eq!(counts.syn_received, 1);
        assert_eq!(counts.other_tcp, 1);
        assert_eq!(counts.udp, 2);
    }

    #[test]
    fn top_remote_ranks_by_connections_and_breaks_ties_by_address() {
        let rows = vec![
            tcp("9.9.9.9", TcpState::Established),
            tcp("8.8.8.8", TcpState::Established),
            tcp("8.8.8.8", TcpState::Established),
            tcp("7.7.7.7", TcpState::Established),
            tcp("7.7.7.7", TcpState::TimeWait),
            tcp("1.1.1.1", TcpState::Established),
        ];
        let top = top_remote(&rows, 10);
        let ranked: Vec<(&str, u32)> = top
            .iter()
            .map(|t| (t.addr.as_str(), t.connections))
            .collect();
        assert_eq!(
            ranked,
            [
                ("7.7.7.7", 2),
                ("8.8.8.8", 2),
                ("1.1.1.1", 1),
                ("9.9.9.9", 1)
            ]
        );
    }

    #[test]
    fn listeners_wildcards_loopback_and_udp_never_rank() {
        let rows = vec![
            tcp("0.0.0.0", TcpState::Established),
            tcp("::", TcpState::Established),
            tcp("127.0.0.1", TcpState::Established),
            tcp("::1", TcpState::Established),
            tcp("5.5.5.5", TcpState::Listen),
            tcp("", TcpState::Established),
            udp(),
            tcp("203.0.113.9", TcpState::Established),
        ];
        let top = top_remote(&rows, 10);
        assert_eq!(
            top,
            vec![RemoteTalker {
                addr: "203.0.113.9".into(),
                connections: 1
            }]
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_is_folded_into_ipv4() {
        let rows = vec![
            tcp("::ffff:203.0.113.9", TcpState::Established),
            tcp("203.0.113.9", TcpState::Established),
            tcp("2001:db8::1", TcpState::Established),
        ];
        let top = top_remote(&rows, 10);
        assert_eq!(
            top[0],
            RemoteTalker {
                addr: "203.0.113.9".into(),
                connections: 2
            }
        );
        assert_eq!(top[1].addr, "2001:db8::1");
    }

    #[test]
    fn the_limit_is_applied_after_ranking() {
        let rows: Vec<Connection> = (1..=50)
            .flat_map(|i| {
                (0..i).map(move |_| tcp(&format!("198.51.100.{i}"), TcpState::Established))
            })
            .collect();
        let top = top_remote(&rows, 3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].addr, "198.51.100.50");
        assert_eq!(top[0].connections, 50);
    }

    fn to_port(remote: &str, state: TcpState, local_port: u16) -> Connection {
        Connection {
            local_port,
            ..tcp(remote, state)
        }
    }

    #[test]
    fn rdp_peers_are_the_established_peers_of_the_rdp_port() {
        let rows = vec![
            to_port("14.224.238.73", TcpState::Established, 3389),
            to_port("143.20.99.200", TcpState::Established, 3389),
            to_port("14.224.238.73", TcpState::Established, 3389), // second connection, same peer
            to_port("203.0.113.7", TcpState::TimeWait, 3389),      // not established
            to_port("", TcpState::Listen, 3389),
            to_port("198.51.100.1", TcpState::Established, 443), // other port
            to_port("127.0.0.1", TcpState::Established, 3389),   // loopback never counts
            to_port("::ffff:143.20.99.200", TcpState::Established, 3389), // mapped duplicate
            udp(),
        ];
        assert_eq!(rdp_peers(&rows, 3389), ["14.224.238.73", "143.20.99.200"]);
    }

    #[test]
    fn rdp_peers_follow_a_non_default_port() {
        let rows = vec![
            to_port("203.0.113.5", TcpState::Established, 3390),
            to_port("203.0.113.6", TcpState::Established, 3389),
        ];
        assert_eq!(rdp_peers(&rows, 3390), ["203.0.113.5"]);
        assert!(rdp_peers(&rows, 9999).is_empty());
    }

    #[test]
    fn a_syn_flood_ranks_the_attacker_first() {
        let mut rows = vec![tcp("198.51.100.7", TcpState::Established)];
        rows.extend((0..5000).map(|_| tcp("203.0.113.66", TcpState::SynReceived)));
        let top = top_remote(&rows, 5);
        assert_eq!(top[0].addr, "203.0.113.66");
        assert_eq!(top[0].connections, 5000);
        assert_eq!(count_connections(&rows).syn_received, 5000);
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Parsers for the raw buffers returned by `GetExtendedTcpTable` / `GetExtendedUdpTable`
//! (`TCP_TABLE_OWNER_PID_ALL` / `UDP_TABLE_OWNER_PID`), for IPv4 and IPv6.
//!
//! The buffers are parsed as plain bytes with explicit offsets: no pointer casts, no alignment
//! assumptions, no `unsafe`, and the same code is tested on Linux with synthetic buffers.
//!
//! Layout (all fields are 4-byte DWORDs unless noted; the table is a DWORD row count followed by
//! the rows back to back):
//!
//! | table | row size | fields (offset) |
//! |---|---|---|
//! | TCP v4 | 24 | state 0, local addr 4, local port 8, remote addr 12, remote port 16, pid 20 |
//! | TCP v6 | 56 | local addr\[16\] 0, local scope 16, local port 20, remote addr\[16\] 24, remote scope 40, remote port 44, state 48, pid 52 |
//! | UDP v4 | 12 | local addr 0, local port 4, pid 8 |
//! | UDP v6 | 28 | local addr\[16\] 0, local scope 16, local port 20, pid 24 |
//!
//! Addresses are stored in network byte order, so the bytes in memory read `a.b.c.d`. A port is a
//! DWORD whose **first two bytes in memory** hold the port in network byte order.

use std::net::{Ipv4Addr, Ipv6Addr};

use pw_proto::{Connection, Proto, TcpState};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TableError {
    #[error(
        "table buffer too short: {rows} rows of {row_size} bytes need {need} bytes, have {have}"
    )]
    Truncated {
        rows: usize,
        row_size: usize,
        need: usize,
        have: usize,
    },
}

const TCP4_ROW: usize = 24;
const TCP6_ROW: usize = 56;
const UDP4_ROW: usize = 12;
const UDP6_ROW: usize = 28;

fn dword(row: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&row[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn port(row: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([row[offset], row[offset + 1]])
}

fn ipv4(row: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        row[offset],
        row[offset + 1],
        row[offset + 2],
        row[offset + 3],
    )
}

fn ipv6(row: &[u8], offset: usize) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&row[offset..offset + 16]);
    Ipv6Addr::from(octets)
}

/// `MIB_TCP_STATE` to [`TcpState`]. Values outside 1..=12 map to `Closed`.
pub fn tcp_state(value: u32) -> TcpState {
    match value {
        2 => TcpState::Listen,
        3 => TcpState::SynSent,
        4 => TcpState::SynReceived,
        5 => TcpState::Established,
        6 => TcpState::FinWait1,
        7 => TcpState::FinWait2,
        8 => TcpState::CloseWait,
        9 => TcpState::Closing,
        10 => TcpState::LastAck,
        11 => TcpState::TimeWait,
        12 => TcpState::DeleteTcb,
        _ => TcpState::Closed,
    }
}

/// The rows of a table buffer, or an error if the buffer is shorter than its own row count says.
fn rows(buf: &[u8], row_size: usize) -> Result<impl Iterator<Item = &[u8]>, TableError> {
    let count = if buf.len() >= 4 {
        dword(buf, 0) as usize
    } else {
        0
    };
    let need = count
        .checked_mul(row_size)
        .and_then(|bytes| bytes.checked_add(4))
        .unwrap_or(usize::MAX);
    if count > 0 && buf.len() < need {
        return Err(TableError::Truncated {
            rows: count,
            row_size,
            need,
            have: buf.len(),
        });
    }
    let body = buf.get(4..).unwrap_or(&[]);
    Ok(body.chunks_exact(row_size).take(count))
}

/// Wildcard remote of a listener: shown as an empty string instead of `0.0.0.0:0`.
fn remote_text(addr: String, unspecified: bool, port: u16) -> String {
    if unspecified && port == 0 {
        String::new()
    } else {
        addr
    }
}

pub fn parse_tcp4(buf: &[u8]) -> Result<Vec<Connection>, TableError> {
    Ok(rows(buf, TCP4_ROW)?
        .map(|row| {
            let remote = ipv4(row, 12);
            let remote_port = port(row, 16);
            Connection {
                proto: Proto::Tcp,
                local_addr: ipv4(row, 4).to_string(),
                local_port: port(row, 8),
                remote_addr: remote_text(remote.to_string(), remote.is_unspecified(), remote_port),
                remote_port,
                state: Some(tcp_state(dword(row, 0))),
                pid: dword(row, 20),
            }
        })
        .collect())
}

pub fn parse_tcp6(buf: &[u8]) -> Result<Vec<Connection>, TableError> {
    Ok(rows(buf, TCP6_ROW)?
        .map(|row| {
            let remote = ipv6(row, 24);
            let remote_port = port(row, 44);
            Connection {
                proto: Proto::Tcp,
                local_addr: ipv6(row, 0).to_string(),
                local_port: port(row, 20),
                remote_addr: remote_text(remote.to_string(), remote.is_unspecified(), remote_port),
                remote_port,
                state: Some(tcp_state(dword(row, 48))),
                pid: dword(row, 52),
            }
        })
        .collect())
}

pub fn parse_udp4(buf: &[u8]) -> Result<Vec<Connection>, TableError> {
    Ok(rows(buf, UDP4_ROW)?
        .map(|row| Connection {
            proto: Proto::Udp,
            local_addr: ipv4(row, 0).to_string(),
            local_port: port(row, 4),
            remote_addr: String::new(),
            remote_port: 0,
            state: None,
            pid: dword(row, 8),
        })
        .collect())
}

pub fn parse_udp6(buf: &[u8]) -> Result<Vec<Connection>, TableError> {
    Ok(rows(buf, UDP6_ROW)?
        .map(|row| Connection {
            proto: Proto::Udp,
            local_addr: ipv6(row, 0).to_string(),
            local_port: port(row, 20),
            remote_addr: String::new(),
            remote_port: 0,
            state: None,
            pid: dword(row, 24),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = (rows.len() as u32).to_le_bytes().to_vec();
        for row in rows {
            buf.extend_from_slice(row);
        }
        buf
    }

    /// A port DWORD as Windows stores it: network-order bytes first, then two zero bytes.
    fn port_dword(port: u16) -> [u8; 4] {
        let be = port.to_be_bytes();
        [be[0], be[1], 0, 0]
    }

    fn tcp4_row(
        state: u32,
        local: [u8; 4],
        lport: u16,
        remote: [u8; 4],
        rport: u16,
        pid: u32,
    ) -> Vec<u8> {
        let mut row = Vec::new();
        row.extend_from_slice(&state.to_le_bytes());
        row.extend_from_slice(&local);
        row.extend_from_slice(&port_dword(lport));
        row.extend_from_slice(&remote);
        row.extend_from_slice(&port_dword(rport));
        row.extend_from_slice(&pid.to_le_bytes());
        row
    }

    #[test]
    fn parses_an_established_ipv4_connection() {
        // 10.0.0.5:3389 <- 203.0.113.9:51234, state ESTABLISHED, pid 1234.
        let buf = table(&[tcp4_row(
            5,
            [10, 0, 0, 5],
            3389,
            [203, 0, 113, 9],
            51234,
            1234,
        )]);
        let rows = parse_tcp4(&buf).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.local_addr, "10.0.0.5");
        assert_eq!(row.local_port, 3389);
        assert_eq!(row.remote_addr, "203.0.113.9");
        assert_eq!(row.remote_port, 51234);
        assert_eq!(row.state, Some(TcpState::Established));
        assert_eq!(row.pid, 1234);
    }

    #[test]
    fn a_listener_has_an_empty_remote() {
        let buf = table(&[tcp4_row(2, [0, 0, 0, 0], 443, [0, 0, 0, 0], 0, 4)]);
        let row = &parse_tcp4(&buf).unwrap()[0];
        assert_eq!(row.state, Some(TcpState::Listen));
        assert_eq!(row.local_addr, "0.0.0.0");
        assert_eq!(row.remote_addr, "");
        assert_eq!(row.remote_port, 0);
    }

    #[test]
    fn ports_above_255_are_read_in_network_order() {
        // 0x1F90 = 8080; a byte-order mistake would give 0x901F = 36895.
        let buf = table(&[tcp4_row(5, [1, 2, 3, 4], 8080, [5, 6, 7, 8], 80, 1)]);
        let row = &parse_tcp4(&buf).unwrap()[0];
        assert_eq!(row.local_port, 8080);
        assert_eq!(row.remote_port, 80);
    }

    #[test]
    fn every_tcp_state_maps_and_unknown_values_become_closed() {
        let expected = [
            (1, TcpState::Closed),
            (2, TcpState::Listen),
            (3, TcpState::SynSent),
            (4, TcpState::SynReceived),
            (5, TcpState::Established),
            (6, TcpState::FinWait1),
            (7, TcpState::FinWait2),
            (8, TcpState::CloseWait),
            (9, TcpState::Closing),
            (10, TcpState::LastAck),
            (11, TcpState::TimeWait),
            (12, TcpState::DeleteTcb),
            (0, TcpState::Closed),
            (99, TcpState::Closed),
        ];
        for (value, state) in expected {
            assert_eq!(tcp_state(value), state, "{value}");
        }
    }

    #[test]
    fn parses_ipv6_tcp_rows() {
        let local = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5).octets();
        let remote = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9).octets();
        let mut row = Vec::new();
        row.extend_from_slice(&local);
        row.extend_from_slice(&0u32.to_le_bytes());
        row.extend_from_slice(&port_dword(3389));
        row.extend_from_slice(&remote);
        row.extend_from_slice(&7u32.to_le_bytes()); // remote scope id
        row.extend_from_slice(&port_dword(40000));
        row.extend_from_slice(&5u32.to_le_bytes()); // ESTABLISHED
        row.extend_from_slice(&777u32.to_le_bytes());
        assert_eq!(row.len(), TCP6_ROW);
        let parsed = parse_tcp6(&table(&[row])).unwrap();
        assert_eq!(parsed[0].local_addr, "2001:db8::5");
        assert_eq!(parsed[0].local_port, 3389);
        assert_eq!(parsed[0].remote_addr, "2001:db8::9");
        assert_eq!(parsed[0].remote_port, 40000);
        assert_eq!(parsed[0].state, Some(TcpState::Established));
        assert_eq!(parsed[0].pid, 777);
    }

    #[test]
    fn parses_udp_rows_for_both_families() {
        let mut v4 = Vec::new();
        v4.extend_from_slice(&[0, 0, 0, 0]);
        v4.extend_from_slice(&port_dword(5353));
        v4.extend_from_slice(&88u32.to_le_bytes());
        let parsed = parse_udp4(&table(&[v4])).unwrap();
        assert_eq!(parsed[0].proto, Proto::Udp);
        assert_eq!(parsed[0].local_port, 5353);
        assert_eq!(parsed[0].pid, 88);
        assert_eq!(parsed[0].state, None);

        let mut v6 = Vec::new();
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&0u32.to_le_bytes());
        v6.extend_from_slice(&port_dword(123));
        v6.extend_from_slice(&99u32.to_le_bytes());
        assert_eq!(v6.len(), UDP6_ROW);
        let parsed = parse_udp6(&table(&[v6])).unwrap();
        assert_eq!(parsed[0].local_addr, "::1");
        assert_eq!(parsed[0].local_port, 123);
        assert_eq!(parsed[0].pid, 99);
    }

    #[test]
    fn an_empty_or_tiny_buffer_is_an_empty_table() {
        assert!(parse_tcp4(&[]).unwrap().is_empty());
        assert!(parse_tcp4(&[0, 0]).unwrap().is_empty());
        assert!(parse_tcp4(&0u32.to_le_bytes()).unwrap().is_empty());
    }

    #[test]
    fn a_buffer_shorter_than_its_row_count_is_an_error_not_a_panic() {
        let mut buf = table(&[tcp4_row(5, [1, 1, 1, 1], 1, [2, 2, 2, 2], 2, 3)]);
        buf.truncate(buf.len() - 1);
        assert!(matches!(
            parse_tcp4(&buf),
            Err(TableError::Truncated { .. })
        ));

        // A hostile row count must not overflow the size computation.
        let hostile = u32::MAX.to_le_bytes();
        assert!(matches!(
            parse_tcp6(&hostile),
            Err(TableError::Truncated { .. })
        ));
    }

    #[test]
    fn trailing_bytes_beyond_the_declared_rows_are_ignored() {
        let mut buf = table(&[tcp4_row(5, [1, 1, 1, 1], 1, [2, 2, 2, 2], 2, 3)]);
        buf.extend_from_slice(&[0xAA; 50]);
        assert_eq!(parse_tcp4(&buf).unwrap().len(), 1);
    }

    #[test]
    fn thousands_of_rows_parse() {
        let rows: Vec<Vec<u8>> = (0..5000u32)
            .map(|i| {
                tcp4_row(
                    5,
                    [10, 0, 0, 1],
                    3389,
                    [198, 51, (i >> 8) as u8, i as u8],
                    1024 + (i % 60000) as u16,
                    i,
                )
            })
            .collect();
        let parsed = parse_tcp4(&table(&rows)).unwrap();
        assert_eq!(parsed.len(), 5000);
        assert_eq!(parsed[4999].pid, 4999);
    }
}

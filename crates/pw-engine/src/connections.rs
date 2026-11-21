// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Builds the `netstat.connections` reply from the latest snapshot, within one IPC frame.

use std::collections::BTreeMap;

use pw_proto::{Connection, ConnectionsResponse, DEFAULT_CONNECTION_LIMIT, MAX_FRAME_BYTES};

use crate::poller::Snapshot;

/// Fixed JSON overhead of one connection row (field names, quotes, separators, numbers, state).
const ROW_OVERHEAD: usize = 150;
/// Part of a frame the reply may use for rows; the rest is for the envelope, the process-name map
/// and the totals, plus slack for estimation error.
const FRAME_BUDGET: usize = (MAX_FRAME_BYTES as usize) * 85 / 100;

fn estimated_size(row: &Connection) -> usize {
    ROW_OVERHEAD + row.local_addr.len() + row.remote_addr.len()
}

/// The connection table for a client: at most `limit` rows (and never more than
/// [`DEFAULT_CONNECTION_LIMIT`]), cut earlier if they would not fit in one 4 MB frame. `total`
/// always reports the real size of the table, so the UI can say it is truncated.
///
/// Process names are sent once per PID in use rather than once per row.
pub fn response(snapshot: Option<&Snapshot>, limit: Option<u32>) -> ConnectionsResponse {
    let Some(snapshot) = snapshot else {
        return ConnectionsResponse {
            connections: Vec::new(),
            processes: BTreeMap::new(),
            total: 0,
            truncated: false,
            sampled_unix_ms: 0,
        };
    };
    let rows = &snapshot.table.rows;
    let cap = limit
        .unwrap_or(DEFAULT_CONNECTION_LIMIT)
        .min(DEFAULT_CONNECTION_LIMIT) as usize;

    let mut used = 0usize;
    let mut taken = 0usize;
    for row in rows.iter().take(cap) {
        used += estimated_size(row);
        if used > FRAME_BUDGET {
            break;
        }
        taken += 1;
    }
    let connections: Vec<Connection> = rows[..taken].to_vec();

    let processes = connections
        .iter()
        .filter_map(|row| {
            snapshot
                .table
                .processes
                .get(&row.pid)
                .map(|name| (row.pid, name.clone()))
        })
        .collect();

    ConnectionsResponse {
        total: u32::try_from(rows.len()).unwrap_or(u32::MAX),
        truncated: taken < rows.len(),
        connections,
        processes,
        sampled_unix_ms: snapshot.stats.unix_ms,
    }
}

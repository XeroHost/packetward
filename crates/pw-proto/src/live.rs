// SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Deserialize, Serialize};

/// Payload of the `live.heartbeat` topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct Heartbeat {
    /// Starts at 1 for each subscription and increases by one per event.
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub seq: u64,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub uptime_secs: u64,
    /// Agent wall clock, milliseconds since the Unix epoch.
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub unix_ms: u64,
}

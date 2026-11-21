// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
use serde::{Deserialize, Serialize};

/// Reply to `system.info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SystemInfo {
    pub agent_version: String,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub hostname: String,
    /// `std::env::consts::OS`, e.g. "windows".
    pub os_family: String,
    pub pid: u32,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub uptime_secs: u64,
    /// True when running under the service control manager, false for `run --console`.
    pub service_mode: bool,
}

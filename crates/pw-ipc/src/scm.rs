// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Read-only view of the agent's Windows service registration, so a client that cannot reach the
//! pipe can tell "not installed" from "stopped".

use std::io;

use crate::sys::windows::{service_state, RawServiceState};

/// Name the agent registers itself under.
pub const SERVICE_NAME: &str = "PacketWard";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentService {
    NotInstalled,
    Stopped,
    Starting,
    Running,
    Stopping,
}

/// Queries the service control manager. Needs no special rights.
pub fn agent_service() -> io::Result<AgentService> {
    Ok(match service_state(SERVICE_NAME)? {
        None => AgentService::NotInstalled,
        Some(RawServiceState::Stopped) => AgentService::Stopped,
        Some(RawServiceState::StartPending) => AgentService::Starting,
        Some(RawServiceState::Running | RawServiceState::Other) => AgentService::Running,
        Some(RawServiceState::StopPending) => AgentService::Stopping,
    })
}

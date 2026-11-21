// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
use serde::{Deserialize, Serialize};

/// Bumped on breaking protocol changes. A different major means the two sides cannot talk.
pub const PROTOCOL_MAJOR: u16 = 1;
/// Bumped on backwards-compatible additions.
pub const PROTOCOL_MINOR: u16 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub enum ClientKind {
    Desktop,
    Pwctl,
    /// `pwctl mcp`, the stdio MCP server; the agent applies the MCP policy to these connections.
    Mcp,
}

/// Payload of `session.hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct HelloRequest {
    pub client: ClientKind,
    pub client_version: String,
    pub protocol_major: u16,
    pub protocol_minor: u16,
}

/// Reply to `session.hello`. The agent sends it even when the majors differ (right before it
/// closes the connection) so the UI can tell whether the agent or the UI is the outdated side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct HelloResponse {
    pub agent_version: String,
    pub protocol_major: u16,
    pub protocol_minor: u16,
}

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! pw-mcp — the MCP server library behind `pwctl mcp` (milestone M11, ARCHITECTURE §6.14).
//!
//! The crate has no engine dependency. It mirrors the agent's tool catalog ([`catalog`]), builds the
//! JSON schemas of the tool arguments, wraps every result in the untrusted-field envelope
//! ([`envelope`]), provides the three prompts ([`prompts`]) and serves the Model Context Protocol
//! over stdio ([`server`]), forwarding each tool call to the agent through a [`pw_ipc::Client`].
//!
//! The **agent** owns enforcement: the master switch, the per-tool level, the write and probe rate
//! limits, the approval queue and the Guardian's protected set. This crate lists the **full** catalog
//! even when a tool is disabled; the agent answers `Forbidden` at call time, and that error is shown
//! to the AI as a tool error.

pub mod catalog;
pub mod envelope;
pub mod prompts;
pub mod server;
#[cfg(test)]
mod tests;

use pw_proto::ErrorPayload;

/// Errors of the library itself (argument validation, transport, job timeout).
#[derive(Debug, thiserror::Error)]
pub enum McpError {
    /// The caller's arguments are malformed or outside the tool's bounds.
    #[error("invalid arguments: {0}")]
    Args(String),
    /// The agent answered with a typed error (the message is the agent's, never rewritten).
    #[error("the agent refused the call ({:?}): {}", .0.code, .0.message)]
    Agent(ErrorPayload),
    /// The IPC connection failed or the agent closed it.
    #[error("the agent connection failed: {0}")]
    Client(#[from] pw_ipc::ClientError),
    /// A job tool did not finish before its deadline.
    #[error("the job did not finish in time")]
    Timeout,
    /// A job tool reported a failure.
    #[error("the job failed: {0}")]
    Job(String),
    /// The agent's reply could not be encoded as JSON (never expected for a pw-proto DTO).
    #[error("could not encode the reply: {0}")]
    Encode(String),
    /// The MCP stdio transport could not be started or stopped.
    #[error("the MCP transport failed: {0}")]
    Transport(String),
}

impl McpError {
    /// The message shown to the AI. Agent errors keep the agent's wording, with the code in front so
    /// `Forbidden`, `RateLimited` and a `BlockRefusal` are distinguishable.
    pub fn message(&self) -> String {
        match self {
            Self::Agent(payload) => format!("{:?}: {}", payload.code, payload.message),
            other => other.to_string(),
        }
    }
}

impl From<serde_json::Error> for McpError {
    fn from(err: serde_json::Error) -> Self {
        Self::Args(err.to_string())
    }
}

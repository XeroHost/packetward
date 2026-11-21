// SPDX-License-Identifier: GPL-3.0-or-later
//! `pwctl mcp` — the stdio MCP server (milestone M11, ARCHITECTURE §6.14).
//!
//! An AI client (Claude Desktop, Claude Code, OpenCode, Cursor) launches this command and speaks
//! Model Context Protocol over **stdout**. Stdout therefore belongs to the JSON-RPC transport: this
//! module never prints to it, and nothing in the CLI installs a stdout log sink, so diagnostics go to
//! stderr only. The pipe client handshakes as `ClientKind::Mcp`, which makes the agent apply the MCP
//! policy (master switch, per-tool level, rate limits, approvals, audit) to every call.

use std::process::ExitCode;

use pw_proto::ClientKind;

use crate::status::connect_client_as;

/// Serves MCP over stdin/stdout until the client closes the session.
pub async fn run() -> ExitCode {
    let client = match connect_client_as(ClientKind::Mcp).await {
        Ok(client) => client,
        Err(code) => return code,
    };
    match pw_mcp::server::serve(client).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("The MCP server stopped: {err}");
            ExitCode::from(1)
        }
    }
}

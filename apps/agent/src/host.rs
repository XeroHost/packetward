// SPDX-License-Identifier: GPL-3.0-or-later
//! Runs the engine behind the named pipe until told to stop. Shared by the service and `--console`.

use std::future::Future;
use std::sync::Arc;

use anyhow::Context;
use pw_engine::{Engine, EngineConfig};
use pw_ipc::pipe::{pipe_sddl, PipeListener, PIPE_NAME};
use pw_ipc::{access, serve};

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn run_agent(
    service_mode: bool,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    let operators = match access::operators_group_sid() {
        Ok(Some(sid)) => Some(sid),
        Ok(None) => {
            tracing::warn!(
                "the 'PacketWard Operators' group does not exist; only SYSTEM and Administrators \
                 can use the pipe (run `packetward-agent repair`)"
            );
            None
        }
        Err(err) => {
            tracing::warn!(%err, "could not look up the operators group; continuing without it");
            None
        }
    };

    // Fails if another process already owns the pipe name; never serve on a squatted pipe.
    let listener = PipeListener::bind(PIPE_NAME, &pipe_sddl(operators.as_deref()))
        .with_context(|| format!("could not create the IPC pipe {PIPE_NAME}"))?;

    let engine = Arc::new(Engine::new(EngineConfig::new(AGENT_VERSION, service_mode)));
    tracing::info!(
        version = AGENT_VERSION,
        service_mode,
        pipe = PIPE_NAME,
        "agent started"
    );
    // An accept failure is an error, not a clean stop: the service must exit non-zero so Windows
    // restarts it (failure actions do not fire after a clean stop).
    serve(listener, engine, shutdown)
        .await
        .context("the IPC listener stopped unexpectedly")?;
    tracing::info!("agent stopped");
    Ok(())
}

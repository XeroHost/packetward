// SPDX-License-Identifier: GPL-3.0-or-later
//! Runs the engine behind the named pipe until told to stop. Shared by the service and `--console`.

use std::future::Future;
use std::sync::Arc;

use anyhow::Context;
use pw_engine::{Engine, EngineConfig};
use pw_ipc::pipe::{pipe_sddl_with_members, PipeListener, PIPE_NAME};
use pw_ipc::{access, serve};
use pw_netstat::WindowsNetStat;

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn run_agent(
    service_mode: bool,
    capture: bool,
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

    // The members' own SIDs go in the ACL too: a user added to the group in the session they are in
    // has no group in their token yet, but their own SID is there, so they connect without signing out.
    let members = access::operator_member_sids().unwrap_or_else(|err| {
        tracing::warn!(%err, "could not list the operators; relying on the group alone");
        Vec::new()
    });

    // Fails if another process already owns the pipe name; never serve on a squatted pipe.
    let listener = PipeListener::bind(
        PIPE_NAME,
        &pipe_sddl_with_members(operators.as_deref(), &members),
    )
    .with_context(|| format!("could not create the IPC pipe {PIPE_NAME}"))?;

    // The data folder holds the Guardian state, the allowlist and the alerts: only SYSTEM and
    // Administrators may write there, before anything is read from it.
    if let Err(err) = pw_engine::ensure_private_dir(&crate::logging::data_dir()) {
        tracing::error!(%err, "could not restrict the data folder to administrators");
    }
    let engine = Arc::new(Engine::with_system_firewall(
        {
            let mut config = EngineConfig::new(AGENT_VERSION, service_mode);
            // Passive and bounded: the live capture feeds the traffic page and the detectors.
            config.capture_autostart = capture;
            config.alerts_log = Some(crate::logging::data_dir().join("alerts.jsonl"));
            config.defense_dir = Some(crate::logging::data_dir());
            config.intel_dir = Some(crate::logging::data_dir().join("intel"));
            config
        },
        Arc::new(WindowsNetStat::new()),
    ));
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

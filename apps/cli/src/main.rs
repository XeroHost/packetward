// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! pwctl — basic command line client for emergency recovery and scripting.

#[cfg(windows)]
mod cli;
#[cfg(windows)]
mod defense;
#[cfg(windows)]
mod mcp;
#[cfg(windows)]
mod rdp;
#[cfg(windows)]
mod status;
#[cfg(windows)]
mod support;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use clap::Parser;

    use crate::cli::{Cli, Command, FirewallAction, GuardianArg, RdpAction};

    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("pwctl: could not start the async runtime: {err}");
            return std::process::ExitCode::from(1);
        }
    };
    match cli.command {
        Command::Status => runtime.block_on(status::run()),
        Command::Block {
            targets,
            minutes,
            reason,
        } => runtime.block_on(defense::block(targets, minutes, reason)),
        Command::Unblock { targets, all } => runtime.block_on(defense::unblock(targets, all)),
        Command::Firewall { action } => match action {
            FirewallAction::List => runtime.block_on(defense::list_blocks()),
            FirewallAction::Purge { confirm } => runtime.block_on(defense::purge(confirm)),
        },
        Command::Rdp { action } => match action {
            RdpAction::Status => runtime.block_on(rdp::status()),
            RdpAction::Confirm { id } => runtime.block_on(rdp::confirm(id, false)),
            RdpAction::Cancel { id } => runtime.block_on(rdp::confirm(id, true)),
            RdpAction::Reset { offline } => runtime.block_on(rdp::reset(offline)),
        },
        Command::Guardian { mode, yes } => runtime.block_on(defense::guardian(
            mode.map(|m| match m {
                GuardianArg::Off => pw_proto::GuardianMode::Off,
                GuardianArg::Monitor => pw_proto::GuardianMode::Monitor,
                GuardianArg::Active => pw_proto::GuardianMode::Active,
            }),
            yes,
        )),
        Command::SupportBundle {
            anonymize,
            capture_secs,
            no_logs,
            out,
            preview,
        } => runtime.block_on(support::run(support::Options {
            anonymize,
            capture_secs,
            no_logs,
            out,
            preview_only: preview,
        })),
        // stdout belongs to the MCP transport here: `mcp::run` only writes to stderr.
        Command::Mcp => runtime.block_on(mcp::run()),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("pwctl only runs on Windows.");
    std::process::exit(1);
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! pwctl — basic command line client for emergency recovery and scripting.

#[cfg(windows)]
mod defense;
#[cfg(windows)]
mod rdp;
#[cfg(windows)]
mod status;
#[cfg(windows)]
mod support;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use clap::{Parser, Subcommand};

    #[derive(Parser)]
    #[command(name = "pwctl", version, about = "PacketWard command line client")]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Show whether the agent is reachable and what it reports.
        Status,
        /// Block addresses or CIDR blocks through the firewall (protected addresses are refused).
        Block {
            targets: Vec<String>,
            /// Remove the block after this many minutes.
            #[arg(long)]
            minutes: Option<u64>,
            #[arg(long, default_value = "pwctl")]
            reason: String,
        },
        /// Remove blocks: the given addresses, or every block with --all (emergency recovery).
        Unblock {
            targets: Vec<String>,
            #[arg(long)]
            all: bool,
        },
        /// Firewall rules and blocks made by PacketWard.
        Firewall {
            #[command(subcommand)]
            action: FirewallAction,
        },
        /// Remote Desktop: exposure audit, confirm/cancel a pending change, factory reset.
        Rdp {
            #[command(subcommand)]
            action: RdpAction,
        },
        /// Show or set the Guardian mode (off, monitor, active).
        Guardian {
            #[arg(value_enum)]
            mode: Option<GuardianArg>,
            /// Confirm switching to Active after reviewing the Monitor report.
            #[arg(long)]
            yes: bool,
        },
        /// Build a support zip (traffic summary, adapters, logs, optional short capture) and save it
        /// locally. Nothing is uploaded.
        SupportBundle {
            /// Replace this machine's own addresses and name with placeholders (the capture is left out).
            #[arg(long)]
            anonymize: bool,
            /// Seconds of traffic to record into the bundle (0 = none, at most 120).
            #[arg(long, default_value_t = 60)]
            capture_secs: u32,
            /// Leave the agent log out.
            #[arg(long)]
            no_logs: bool,
            /// Folder to save into (default: Documents\PacketWard\support).
            #[arg(long)]
            out: Option<std::path::PathBuf>,
            /// Only show what the bundle would contain.
            #[arg(long)]
            preview: bool,
        },
    }

    #[derive(Subcommand)]
    enum FirewallAction {
        /// List the blocks PacketWard applied.
        List,
        /// Remove every PacketWard firewall rule (blocks included).
        Purge {
            /// The typed phrase, required when a PacketWard RDP rule exists.
            #[arg(long)]
            confirm: Option<String>,
        },
    }

    #[derive(Subcommand)]
    enum RdpAction {
        /// Show how Remote Desktop is configured and exposed.
        Status,
        /// Keep a change that is waiting for confirmation (run it from a NEW connection).
        Confirm { id: u64 },
        /// Revert a change that is waiting for confirmation.
        Cancel { id: u64 },
        /// Restore Remote Desktop to factory state: port 3389, built-in rules, no PacketWard restriction.
        Reset {
            /// Do not talk to the agent; change the machine directly (elevated shell).
            #[arg(long)]
            offline: bool,
        },
    }

    #[derive(Clone, Copy, clap::ValueEnum)]
    enum GuardianArg {
        Off,
        Monitor,
        Active,
    }

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
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("pwctl only runs on Windows.");
    std::process::exit(1);
}

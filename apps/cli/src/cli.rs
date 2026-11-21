// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The command line surface: `pwctl <command>`. Kept apart from `main` so the parser can be tested
//! without touching the agent.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pwctl", version, about = "PacketWard command line client")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
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
    /// Run as a Model Context Protocol server over stdio. Meant to be launched by an AI client, not
    /// by hand; stdout carries only the protocol.
    Mcp,
}

#[derive(Subcommand)]
pub(crate) enum FirewallAction {
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
pub(crate) enum RdpAction {
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
pub(crate) enum GuardianArg {
    Off,
    Monitor,
    Active,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn mcp_subcommand_exists() {
        let cli = match parse(&["pwctl", "mcp"]) {
            Ok(cli) => cli,
            Err(err) => panic!("`pwctl mcp` must parse: {err}"),
        };
        assert!(matches!(cli.command, Command::Mcp));
    }

    #[test]
    fn mcp_takes_no_arguments() {
        assert!(parse(&["pwctl", "mcp", "extra"]).is_err());
        assert!(parse(&["pwctl", "mcp", "--verbose"]).is_err());
    }
}

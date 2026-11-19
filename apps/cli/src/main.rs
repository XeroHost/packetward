// SPDX-License-Identifier: GPL-3.0-or-later
//! pwctl — basic command line client for emergency recovery and scripting.

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

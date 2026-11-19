// SPDX-License-Identifier: GPL-3.0-or-later
//! pwctl — basic command line client for emergency recovery and scripting.

#[cfg(windows)]
mod status;

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
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("pwctl only runs on Windows.");
    std::process::exit(1);
}

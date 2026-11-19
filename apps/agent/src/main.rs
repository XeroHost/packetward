// SPDX-License-Identifier: GPL-3.0-or-later
//! packetward-agent — Windows service host for pw-engine (install, uninstall, run).

#[cfg(windows)]
mod host;
#[cfg(windows)]
mod logging;
#[cfg(windows)]
mod service;

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use clap::Parser;

    let cli = service::Cli::parse();
    service::dispatch(cli)
}

#[cfg(not(windows))]
fn main() {
    eprintln!("packetward-agent only runs on Windows.");
    std::process::exit(1);
}

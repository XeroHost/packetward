// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! pw-speed-server: speed test server for XeroHost nodes (/ping, /download, /upload, /info).

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use pw_speed_server::{Config, Overrides, DEFAULT_CONFIG_TOML};
use tracing_subscriber::EnvFilter;

/// Speed test server for XeroHost nodes.
///
/// Configuration precedence: defaults < config file < PW_SPEED_* environment variables < these flags.
#[derive(Debug, Parser)]
#[command(name = "pw-speed-server", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, env = "PW_SPEED_CONFIG", value_name = "FILE")]
    config: Option<PathBuf>,
    /// Print the default configuration (commented TOML) and exit.
    #[arg(long)]
    print_default_config: bool,
    /// Load and validate the configuration, then exit.
    #[arg(long)]
    check_config: bool,
    /// Address to listen on, e.g. 0.0.0.0:8080.
    #[arg(long, value_name = "ADDR")]
    listen: Option<SocketAddr>,
    /// Node id (matches nodes.json).
    #[arg(long, value_name = "ID")]
    node_id: Option<String>,
    /// Node display name.
    #[arg(long, value_name = "NAME")]
    node_name: Option<String>,
    /// Node location text.
    #[arg(long, value_name = "TEXT")]
    location: Option<String>,
    /// Log filter, e.g. info or pw_speed_server=debug.
    #[arg(long, value_name = "FILTER")]
    log_level: Option<String>,
}

fn load_config(cli: &Cli) -> anyhow::Result<Config> {
    let mut config = match &cli.config {
        Some(path) => Config::from_file(path)?,
        None => Config::default(),
    };
    config.apply_env(&|name| std::env::var(name).ok())?;
    config.apply_overrides(&Overrides {
        listen: cli.listen,
        node_id: cli.node_id.clone(),
        node_name: cli.node_name.clone(),
        location: cli.location.clone(),
        log_level: cli.log_level.clone(),
    });
    config.validate()?;
    Ok(config)
}

fn init_logging(config: &Config) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&config.logging.level)
        .with_context(|| format!("invalid logging.level {:?}", config.logging.level))?;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false);
    if config.logging.format == "json" {
        builder.json().init();
    } else {
        builder.init();
    }
    Ok(())
}

/// Resolves on Ctrl-C or (on Unix) SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
                return;
            }
            Err(e) => tracing::warn!(error = %e, "cannot install SIGTERM handler"),
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.print_default_config {
        print!("{DEFAULT_CONFIG_TOML}");
        return Ok(());
    }
    let config = load_config(&cli).context("configuration error")?;
    if cli.check_config {
        eprintln!("configuration OK");
        return Ok(());
    }
    init_logging(&config)?;
    let server = pw_speed_server::start(config).await?;
    shutdown_signal().await;
    tracing::info!("shutdown requested");
    server.shutdown();
    server.wait().await;
    tracing::info!("bye");
    Ok(())
}

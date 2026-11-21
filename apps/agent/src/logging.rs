// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Logging: daily-rotated files in `%ProgramData%\PacketWard\logs`, plus stderr in console mode.

use std::path::PathBuf;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// `%ProgramData%\PacketWard`, falling back to the Windows default location.
pub fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("PacketWard")
}

pub fn log_dir() -> PathBuf {
    data_dir().join("logs")
}

/// Keeps the background log writer alive; drop it only when the process is about to exit.
pub struct LogGuard {
    _file: Option<WorkerGuard>,
}

/// Installs the global subscriber. `console` adds a stderr layer for interactive runs.
pub fn init(console: bool) -> LogGuard {
    let filter =
        || EnvFilter::try_from_env("PACKETWARD_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    let (file_layer, guard) = match std::fs::create_dir_all(log_dir()) {
        Ok(()) => {
            let appender = tracing_appender::rolling::daily(log_dir(), "agent.log");
            let (writer, guard) = tracing_appender::non_blocking(appender);
            (
                Some(fmt::layer().with_ansi(false).with_writer(writer)),
                Some(guard),
            )
        }
        Err(_) => (None, None),
    };
    let console_layer = console.then(|| fmt::layer().with_writer(std::io::stderr));

    // Ignoring the error: a second init (tests, restarts inside one process) must not abort.
    let _ = tracing_subscriber::registry()
        .with(filter())
        .with(file_layer)
        .with(console_layer)
        .try_init();
    if guard.is_none() {
        tracing::warn!(dir = %log_dir().display(), "could not create the log directory; file logging is off");
    }
    LogGuard { _file: guard }
}

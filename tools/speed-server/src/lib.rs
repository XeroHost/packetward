// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! pw-speed-server: the speed-test server deployed on XeroHost nodes.
//!
//! Endpoints: `GET /ping`, `GET /download?bytes=N`, `POST /upload`, `GET /info`, `GET /healthz`.
//! See `README.md` for configuration and deployment.

pub mod app;
pub mod config;
pub mod error;
pub mod io;
pub mod ip;
pub mod limits;
pub mod payload;
pub mod server;

pub use config::{Config, ConfigError, Overrides, DEFAULT_CONFIG_TOML};
pub use server::{start, RunningServer, ServerError};

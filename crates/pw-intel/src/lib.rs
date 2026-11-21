// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! pw-intel — GeoIP/ASN, AbuseIPDB client, reputation cache and blocklists.
//!
//! Everything here is platform-agnostic and network-free by construction: HTTP goes through the
//! [`Fetcher`] trait (the real implementation, `HttpFetcher`, is behind the opt-in `http` feature) and time
//! through [`Clock`], so every module is tested on Linux with fakes. No module talks to the network on its own,
//! and nothing here is telemetry (see `CLAUDE.md`, safety rules).
//!
//! * [`geo`] — DB-IP Lite country + ASN lookup over `.mmdb` files, status states and the monthly update logic.
//! * [`abuseipdb`] — `check` (cached, rate-limit aware, only with a key) and an explicit manual `report`.
//! * [`blocklist`] — parsing, aggregation, protected-set subtraction, minisign verification and refresh logic.
//! * [`nodes`] — the XeroHost `nodes.json` list.
//! * [`net`] — the single definition of "reserved / never external" address space.
//! * [`secret`] — the [`SecretStore`] abstraction (Windows Credential Manager behind `cfg(windows)`).

#![forbid(unsafe_code)]

pub mod abuseipdb;
pub mod blocklist;
mod clock;
mod fetch;
pub mod geo;
#[cfg(feature = "http")]
mod http;
pub mod net;
pub mod nodes;
pub mod secret;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use clock::{Clock, SystemClock, UnixSecs};
pub use fetch::{FetchError, FetchRequest, FetchResponse, Fetcher, HttpMethod};
#[cfg(feature = "http")]
pub use http::{HttpFetcher, HttpFetcherConfig};
pub use secret::{MemorySecretStore, Secret, SecretError, SecretStore};

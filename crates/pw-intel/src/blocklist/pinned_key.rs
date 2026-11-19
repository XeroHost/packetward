// SPDX-License-Identifier: GPL-3.0-or-later
//! The minisign public key the XeroHost shared blocklist must be signed with.
//!
//! **Placeholder.** The real key does not exist yet; it is generated on the owner's own PC (never on a development
//! VPS) following `docs/RELEASE-KEYS.md`, step 2. Until then this is `None` and the XeroHost list fails closed:
//! it cannot be enabled, refreshed or applied, and the error says "no pinned key configured".
//!
//! To pin the key, replace `None` with `Some("RWQ…")`, the second line of the `.pub` file (base64, starts with
//! `RW`). It is public by design. Rotating it means shipping a new app version.

/// Base64 minisign public key, or `None` while unset (the XeroHost list is then disabled).
pub const PINNED_PUBLIC_KEY: Option<&str> = None;

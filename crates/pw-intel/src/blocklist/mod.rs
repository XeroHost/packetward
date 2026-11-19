// SPDX-License-Identifier: GPL-3.0-or-later
//! Blocklists: the signed XeroHost shared list and opt-in public lists.
//!
//! Pipeline: download (size-capped while streaming) → for the XeroHost list, minisign verification against the
//! pinned key (fails closed) → parse (counting garbage) → drop reserved space and too-broad entries → de-duplicate
//! and aggregate to minimal CIDRs → subtract the protected set. Applying the result to the firewall is the
//! caller's job (`pw-firewall`, batched rules named `PW-List-<id>-NNN`).

mod manager;
mod parse;
mod pinned_key;
mod ranges;
mod scheduler;
mod source;
mod verify;

pub use manager::{BlocklistManager, ListConfig, ListSnapshot, ListStatus};
pub use parse::{
    build_list, exclude_protected, parse_list, BuiltList, ParseError, ParseLimits, ParseReport,
    MAX_LIST_BYTES, MAX_LIST_ENTRIES, MIN_PREFIX_V4, MIN_PREFIX_V6,
};
pub use pinned_key::PINNED_PUBLIC_KEY;
pub use ranges::{aggregate, aggregate_excluding};
pub use scheduler::{
    clamp_interval, is_due, next_attempt, retry_delay_secs, ScheduleState, MAX_REFRESH_SECS,
    MIN_REFRESH_SECS,
};
pub use source::{
    builtin_sources, download, BlocklistError, ListKind, ListSource, SIGNATURE_MAX_BYTES,
    XEROHOST_LIST_ID, XEROHOST_LIST_URL, XEROHOST_REPO, XEROHOST_SIGNATURE_URL,
};
pub use verify::{Verifier, VerifyError};

#[cfg(test)]
mod tests;

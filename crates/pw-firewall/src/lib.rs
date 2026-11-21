// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! pw-firewall — Windows Firewall (COM INetFwPolicy2) behind a trait; batching; reconcile.
//!
//! Layers, from the bottom:
//!
//! * [`FirewallBackend`]: raw rule storage. [`sys::windows::WindowsFirewall`] talks COM
//!   (`INetFwPolicy2`, never `netsh`); [`fake::FakeFirewall`] is an in-memory stand-in for tests.
//! * [`FirewallManager`]: implements the object-safe [`Firewall`] trait on any backend and enforces
//!   every safety rule: protected set, breadth limits, foreign-rule protection, lockout
//!   confirmations and operation ordering.
//! * Pure helpers: [`reconcile::plan_reconcile`] (batch planning), [`guard`] (checks), [`addr`]
//!   (address/port parsing), [`names`] (validation) and the RDP Shield types in [`shield`].
//!
//! Every rule PacketWard creates is in the group [`names::GROUP`] and carries [`names::MARKER`] in
//! its description. Rules outside that group are read-only unless the caller opts in.

pub mod addr;
pub mod error;
pub mod fake;
pub mod guard;
pub mod manager;
pub mod model;
pub mod names;
pub mod reconcile;
pub mod shield;
pub mod sys;

#[cfg(test)]
mod tests;

pub use error::{FirewallError, RefusedBlocks, Result};
pub use guard::{
    hard_floor, BlockOptions, Confirmation, LockoutReason, ProtectedPolicy, CONFIRMATION_PHRASE,
    MIN_PREFIX_V4, MIN_PREFIX_V6,
};
pub use manager::{
    BatchOutcome, Firewall, FirewallBackend, FirewallManager, PurgeReport, RuleOptions,
};
pub use model::{Action, Direction, Protocol, Rule, RuleFilter, PROFILES_ALL};
pub use names::{BatchId, GROUP, MARKER};
pub use reconcile::{
    plan_reconcile, split_expired, BatchConfig, DesiredBlock, ExistingBatchRule, ReconcilePlan,
    RuleChange, DEFAULT_MAX_PER_RULE,
};
pub use shield::{
    FirewallSnapshot, RdpRestrict, RdpRestrictOutcome, RdpState, RestoreReport, RuleState,
    SNAPSHOT_VERSION,
};

#[cfg(windows)]
pub use sys::windows::WindowsFirewall;

/// The real firewall of this machine, guarded. Windows only.
#[cfg(windows)]
pub fn system_firewall() -> FirewallManager<WindowsFirewall> {
    FirewallManager::new(WindowsFirewall::new())
}

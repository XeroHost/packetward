// SPDX-License-Identifier: GPL-3.0-or-later
//! Error types of the firewall layer.

use std::fmt;
use std::net::IpAddr;

use pw_core::Cidr;

use crate::guard::LockoutReason;

/// Blocks a batch operation refused. Returned whole (never one at a time) so the caller can show
/// everything that was wrong in a single message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefusedBlocks {
    /// Blocks that overlap the protected set (or the built-in floor: loopback, link-local, ...).
    pub protected: Vec<Cidr>,
    /// Blocks shorter than the allowed prefix (a /0, a /4, ...), without the override flag.
    pub too_broad: Vec<Cidr>,
}

impl RefusedBlocks {
    pub fn is_empty(&self) -> bool {
        self.protected.is_empty() && self.too_broad.is_empty()
    }
}

fn join<T: fmt::Display>(items: &[T]) -> String {
    const SHOWN: usize = 8;
    let mut out: Vec<String> = items.iter().take(SHOWN).map(ToString::to_string).collect();
    if items.len() > SHOWN {
        out.push(format!("... and {} more", items.len() - SHOWN));
    }
    out.join(", ")
}

impl fmt::Display for RefusedBlocks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "refused to block")?;
        if !self.protected.is_empty() {
            write!(
                f,
                " protected addresses [{}] (nothing was applied)",
                join(&self.protected)
            )?;
        }
        if !self.too_broad.is_empty() {
            if !self.protected.is_empty() {
                write!(f, " and")?;
            }
            write!(f, " ranges that are too broad [{}]", join(&self.too_broad))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FirewallError {
    #[error("invalid name {name:?}: {reason}")]
    InvalidName { name: String, reason: &'static str },
    #[error("invalid rule: {0}")]
    InvalidRule(String),
    #[error("firewall rule not found: {0:?}")]
    NotFound(String),
    #[error("firewall rule already exists: {0:?}")]
    AlreadyExists(String),
    #[error("rule {0:?} is not a PacketWard rule; editing it needs an explicit foreign-edit flag")]
    ForeignRule(String),
    #[error("rule {0:?} belongs to a block batch; use block/unblock/apply_blocklist instead")]
    BatchManaged(String),
    #[error("{0}")]
    Refused(RefusedBlocks),
    #[error("a protected address set is required to create or change block rules")]
    ProtectedSetRequired,
    #[error("typed confirmation required ({reason}) for rule {rule:?}")]
    ConfirmationRequired { reason: LockoutReason, rule: String },
    #[error("the confirmation phrase does not match")]
    BadConfirmation,
    #[error("the RDP allow list would exclude the current client(s): {}", join(.0))]
    RdpClientExcluded(Vec<IpAddr>),
    #[error("refusing to turn the built-in RDP rules off without any known trusted RDP client")]
    NoTrustedClients,
    #[error("the RDP allow list is empty; that would lock everybody out")]
    EmptyAllowList,
    #[error("firewall backend failure in {op}: {message} (code {code:#010x})")]
    Backend {
        op: &'static str,
        code: u32,
        message: String,
    },
}

pub type Result<T> = std::result::Result<T, FirewallError>;

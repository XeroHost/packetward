// SPDX-License-Identifier: GPL-3.0-or-later
use std::io;

use rusqlite::ErrorCode;

/// Everything the store can fail with.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database file was written by a newer PacketWard. It is left untouched (never moved
    /// aside as "corrupt"): the user downgraded, and upgrading again must find their data.
    #[error("database schema version {found} is newer than this build supports ({supported})")]
    SchemaTooNew { found: i64, supported: i64 },

    /// SQLite reported an error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A schema migration failed; its transaction was rolled back and the version did not move.
    #[error("migration to schema version {version} failed: {source}")]
    Migration {
        version: i64,
        #[source]
        source: rusqlite::Error,
    },

    /// The file failed `PRAGMA quick_check`.
    #[error("database integrity check failed: {0}")]
    Corrupt(String),

    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// The caller passed something the store refuses to persist (empty key, bad CIDR...).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// A stored row holds a value this build does not understand.
    #[error("invalid stored data: {0}")]
    InvalidData(String),
}

impl StoreError {
    /// True when the file itself is damaged (as opposed to busy, locked, unreadable or too new).
    /// Only these errors may lead to the file being moved aside.
    pub(crate) fn is_corruption(&self) -> bool {
        fn damaged(e: &rusqlite::Error) -> bool {
            matches!(
                e,
                rusqlite::Error::SqliteFailure(f, _)
                    if matches!(f.code, ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt)
            )
        }
        match self {
            Self::Corrupt(_) => true,
            Self::Sqlite(e) | Self::Migration { source: e, .. } => damaged(e),
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// `u64` -> SQLite integer, refusing values that do not fit instead of wrapping.
pub(crate) fn to_i64(value: u64, what: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| StoreError::InvalidInput(format!("{what} is too large")))
}

/// SQLite integer -> `u64`; a negative value in a column that must not be negative is bad data.
pub(crate) fn to_u64(value: i64, what: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| StoreError::InvalidData(format!("{what} is negative")))
}

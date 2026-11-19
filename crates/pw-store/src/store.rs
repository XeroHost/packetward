// SPDX-License-Identifier: GPL-3.0-or-later
//! The `Store` handle: opening, corruption recovery and the shared connection.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags};

use crate::error::{Result, StoreError};
use crate::schema::{self, MIGRATIONS, SCHEMA_VERSION};

/// Retention and size bounds. The defaults are what the agent uses.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Audit rows older than this (relative to the newest appended row) are pruned. Default 90 days.
    pub audit_retention_ms: i64,
    /// Hard cap on audit rows; the oldest go first. Default 200 000.
    pub audit_max_rows: u64,
    /// Alerts kept; beyond it the oldest *ended* incidents are pruned. Default 5 000.
    pub alerts_keep: u64,
    /// Distinct RDP logon addresses kept (oldest `last_seen` pruned). Default 10 000.
    pub rdp_logons_max: u64,
    /// Intel cache entries kept (soonest-to-expire pruned first). Default 50 000.
    pub cache_max_rows: u64,
    /// Largest JSON value accepted by the intel cache. Default 256 KiB.
    pub cache_max_value_bytes: usize,
    /// The audit log and the cache are pruned every this many appends/puts (amortized, so the
    /// bounds are soft by at most this many rows). Default 256.
    pub prune_every: u64,
    /// How long a statement waits for another writer (another `Store`, another process).
    pub busy_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            audit_retention_ms: 90 * 24 * 3_600 * 1_000,
            audit_max_rows: 200_000,
            alerts_keep: 5_000,
            rdp_logons_max: 10_000,
            cache_max_rows: 50_000,
            cache_max_value_bytes: 256 * 1024,
            prune_every: 256,
            busy_timeout: Duration::from_secs(5),
        }
    }
}

/// A database file that was damaged and replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    /// Where the damaged file went (`<name>.corrupt-<unix>`).
    pub backup: PathBuf,
    /// What was wrong with it.
    pub reason: String,
}

/// Result of opening a file-backed store.
#[derive(Debug)]
pub struct Opened {
    pub store: Store,
    /// `Some` when the previous file was corrupt, moved aside, and a fresh database created. The
    /// engine logs it and shows a banner: blocks, settings and the audit log started empty.
    pub recovery: Option<Recovery>,
}

impl Opened {
    pub fn was_recovered(&self) -> bool {
        self.recovery.is_some()
    }
}

/// SQLite-backed persistence. `Send + Sync`: one connection behind a mutex, every method short.
pub struct Store {
    conn: Mutex<Connection>,
    pub(crate) limits: Limits,
    pub(crate) audit_appends: AtomicU64,
    pub(crate) cache_puts: AtomicU64,
    path: Option<PathBuf>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("path", &self.path).finish()
    }
}

const FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(OpenFlags::SQLITE_OPEN_CREATE)
    .union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

impl Store {
    /// Opens (creating if needed) the database at `path`, migrating it to the current schema.
    ///
    /// * A database from a newer schema fails with [`StoreError::SchemaTooNew`] and is not touched.
    /// * A file that is not a database, or fails `PRAGMA quick_check`, is moved aside as
    ///   `<name>.corrupt-<unix>` (with its `-wal`/`-shm`) and a fresh database is created; see
    ///   [`Opened::recovery`]. Busy/locked/permission/I-O errors are NOT treated as corruption.
    ///
    /// The parent directory must exist; use [`Store::open_private`] to create it.
    pub fn open(path: impl AsRef<Path>) -> Result<Opened> {
        Self::open_with(path, Limits::default())
    }

    /// [`Store::open`] with explicit limits.
    pub fn open_with(path: impl AsRef<Path>, limits: Limits) -> Result<Opened> {
        let path = path.as_ref();
        match Self::attempt(path, &limits) {
            Ok(store) => Ok(Opened {
                store,
                recovery: None,
            }),
            Err(error) if error.is_corruption() => {
                let reason = error.to_string();
                let backup = move_aside(path)?;
                tracing::error!(
                    path = %path.display(),
                    backup = %backup.display(),
                    %reason,
                    "database is corrupt: moved aside, starting a fresh one"
                );
                let store = Self::attempt(path, &limits)?;
                Ok(Opened {
                    store,
                    recovery: Some(Recovery { backup, reason }),
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Creates the parent folder, then [`Store::open`]. **The caller protects the folder**: the
    /// database and its `-wal`/`-shm` files inherit its ACL, and they must not be readable by
    /// non-administrators (the engine applies the admin-only ACL to `%ProgramData%\PacketWard`
    /// before opening). The store itself does not change any permission.
    pub fn open_private(path: impl AsRef<Path>) -> Result<Opened> {
        Self::open_private_with(path, Limits::default())
    }

    /// [`Store::open_private`] with explicit limits.
    pub fn open_private_with(path: impl AsRef<Path>, limits: Limits) -> Result<Opened> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        Self::open_with(path, limits)
    }

    /// A private in-memory database (tests, dry runs). No WAL, no recovery.
    pub fn open_in_memory() -> Result<Self> {
        Self::open_in_memory_with(Limits::default())
    }

    pub fn open_in_memory_with(limits: Limits) -> Result<Self> {
        let mut conn = Connection::open_in_memory()?;
        init(&mut conn, &limits, false)?;
        Ok(Self::from_parts(conn, limits, None))
    }

    fn attempt(path: &Path, limits: &Limits) -> Result<Self> {
        let mut conn = Connection::open_with_flags(path, FLAGS)?;
        // On failure `conn` is dropped here, releasing the file handle before any rename.
        init(&mut conn, limits, true)?;
        Ok(Self::from_parts(
            conn,
            limits.clone(),
            Some(path.to_path_buf()),
        ))
    }

    fn from_parts(conn: Connection, limits: Limits, path: Option<PathBuf>) -> Self {
        Self {
            conn: Mutex::new(conn),
            limits,
            audit_appends: AtomicU64::new(0),
            cache_puts: AtomicU64::new(0),
            path,
        }
    }

    /// The database file, `None` for an in-memory store.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The schema version of the open database (always [`SCHEMA_VERSION`] after a successful open).
    pub fn schema_version(&self) -> Result<i64> {
        self.with(|conn| schema::user_version(conn))
    }

    /// The schema version this build writes.
    pub const fn supported_schema_version() -> i64 {
        SCHEMA_VERSION
    }

    /// Runs `f` with the connection locked. A panic in an earlier holder poisons the mutex; the
    /// connection itself is still sound (open transactions roll back on drop), so we carry on.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut Connection) -> Result<R>) -> Result<R> {
        let mut guard = self.conn.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }
}

/// Everything after `open`: version gate, integrity, pragmas, migrations.
fn init(conn: &mut Connection, limits: &Limits, file_backed: bool) -> Result<()> {
    conn.busy_timeout(limits.busy_timeout)?;
    // The first real statement is what makes SQLite read the header, so "not a database" surfaces
    // here. Reading the version before any write means a newer database is never modified.
    let version = schema::user_version(conn)?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    if file_backed {
        quick_check(conn)?;
        // `journal_mode` answers with a row, so `execute` would fail with "returned results".
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            tracing::warn!(%mode, "SQLite did not enter WAL mode");
        }
    }
    conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")?;
    schema::migrate(conn, MIGRATIONS)
}

fn quick_check(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA quick_check")?;
    let mut rows = stmt.query([])?;
    let mut problems = Vec::new();
    while let Some(row) = rows.next()? {
        let line: String = row.get(0)?;
        if line != "ok" {
            problems.push(line);
            if problems.len() >= 5 {
                break;
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(StoreError::Corrupt(problems.join("; ")))
    }
}

/// Renames the database and its `-wal` / `-shm` to `<name>.corrupt-<unix>[-n]`. The side files must
/// go too: a stale WAL next to a fresh database could be replayed into it.
fn move_aside(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| StoreError::InvalidInput("database path has no file name".into()))?
        .to_string_lossy()
        .into_owned();
    let dir = path.parent().unwrap_or_else(|| Path::new(""));
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut backup_name = format!("{name}.corrupt-{stamp}");
    let mut n = 0u32;
    while dir.join(&backup_name).exists() {
        n += 1;
        backup_name = format!("{name}.corrupt-{stamp}-{n}");
    }
    let backup = dir.join(&backup_name);
    fs::rename(path, &backup)?;
    for suffix in ["-wal", "-shm"] {
        let side = dir.join(format!("{name}{suffix}"));
        match fs::rename(&side, dir.join(format!("{backup_name}{suffix}"))) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                // Moving failed; deleting is acceptable (they belong to a database we gave up on).
                match fs::remove_file(&side) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(backup)
}

/// Truncates to at most `max` bytes on a character boundary.
pub(crate) fn clip(text: &str, max: usize) -> &str {
    if text.len() <= max {
        text
    } else {
        &text[..text.floor_char_boundary(max)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn store_is_send_and_sync() {
        assert_send_sync::<Store>();
    }

    fn corrupt_siblings(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".corrupt-"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn open_private_creates_parent_and_enables_wal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep").join("er").join("pw.db");
        let opened = Store::open_private(&path).unwrap();
        assert!(!opened.was_recovered());
        let store = opened.store;
        assert_eq!(store.path(), Some(path.as_path()));
        let (mode, fk, busy): (String, i64, i64) = store
            .with(|c| {
                Ok((
                    c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?,
                    c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?,
                    c.query_row("PRAGMA busy_timeout", [], |r| r.get(0))?,
                ))
            })
            .unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(fk, 1);
        assert_eq!(busy, 5000);
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn in_memory_store_works() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(store.path().is_none());
    }

    #[test]
    fn data_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        {
            let store = Store::open(&path).unwrap().store;
            store.kv_set("k", &vec![1, 2, 3], 5).unwrap();
        }
        let store = Store::open(&path).unwrap().store;
        assert_eq!(store.kv_get::<Vec<i32>>("k").unwrap(), Some(vec![1, 2, 3]));
    }

    #[test]
    fn newer_schema_is_refused_and_file_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        {
            let store = Store::open(&path).unwrap().store;
            store.kv_set("k", &1, 1).unwrap();
            store
                .with(|c| Ok(c.pragma_update(None, "user_version", SCHEMA_VERSION + 1)?))
                .unwrap();
            // Fold the WAL into the main file so the byte comparison below is meaningful.
            store
                .with(|c| Ok(c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?))
                .unwrap();
        }
        let before = fs::read(&path).unwrap();
        match Store::open(&path) {
            Err(StoreError::SchemaTooNew { found, supported }) => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(fs::read(&path).unwrap(), before, "file was modified");
        assert!(corrupt_siblings(dir.path()).is_empty());
    }

    #[test]
    fn garbage_file_is_moved_aside_and_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        let junk = vec![0xAB_u8; 8192];
        fs::write(&path, &junk).unwrap();
        fs::write(dir.path().join("pw.db-wal"), b"stale wal").unwrap();
        let opened = Store::open(&path).unwrap();
        let recovery = opened.recovery.as_ref().expect("recovery expected");
        assert!(recovery
            .backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("pw.db.corrupt-"));
        assert_eq!(fs::read(&recovery.backup).unwrap(), junk);
        assert!(!recovery.reason.is_empty());
        // The stale WAL must not be replayed into the new database: it either moved aside with
        // the corrupt file or was discarded by SQLite, but is not sitting next to the fresh one.
        let live_wal = dir.path().join("pw.db-wal");
        if live_wal.exists() {
            assert_ne!(fs::read(&live_wal).unwrap(), b"stale wal");
        }
        assert!(!corrupt_siblings(dir.path()).is_empty());
        // The fresh database is usable and empty.
        assert_eq!(opened.store.blocks_count().unwrap(), 0);
        opened.store.kv_set("a", &"b", 1).unwrap();
        drop(opened);
        // And it opens normally next time.
        assert!(!Store::open(&path).unwrap().was_recovered());
    }

    #[test]
    fn move_aside_takes_wal_and_shm_along_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        for round in 0..2 {
            fs::write(&path, format!("db{round}")).unwrap();
            fs::write(dir.path().join("pw.db-wal"), "wal").unwrap();
            fs::write(dir.path().join("pw.db-shm"), "shm").unwrap();
            let backup = move_aside(&path).unwrap();
            assert!(backup.exists());
            assert!(!path.exists());
            assert!(!dir.path().join("pw.db-wal").exists());
            assert!(!dir.path().join("pw.db-shm").exists());
        }
        // Two moves in the same second produce distinct backups: 2 x (db, wal, shm).
        assert_eq!(corrupt_siblings(dir.path()).len(), 6);
    }

    #[test]
    fn short_garbage_file_is_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        fs::write(&path, b"not sqlite").unwrap();
        let opened = Store::open(&path).unwrap();
        assert!(opened.was_recovered());
    }

    #[test]
    fn empty_file_is_a_valid_new_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        fs::write(&path, b"").unwrap();
        let opened = Store::open(&path).unwrap();
        assert!(!opened.was_recovered());
        assert!(corrupt_siblings(dir.path()).is_empty());
    }

    #[test]
    fn damaged_pages_in_a_real_database_are_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        {
            let store = Store::open(&path).unwrap().store;
            for i in 0..200 {
                store
                    .kv_set(&format!("key-{i}"), &"x".repeat(200), i)
                    .unwrap();
            }
            store
                .with(|c| Ok(c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?))
                .unwrap();
        }
        // Keep the header (so the file still looks like SQLite) and trash the rest.
        let mut bytes = fs::read(&path).unwrap();
        assert!(bytes.len() > 8192);
        for b in &mut bytes[4096..] {
            *b = 0xFF;
        }
        fs::write(&path, &bytes).unwrap();
        let opened = Store::open(&path).unwrap();
        assert!(opened.was_recovered());
        assert_eq!(opened.store.kv_get::<String>("key-1").unwrap(), None);
    }

    #[test]
    fn locked_database_is_not_treated_as_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        drop(Store::open(&path).unwrap());
        // Hold an exclusive lock from a second connection; with a tiny busy timeout the open must
        // fail with a plain SQLite error, and nothing may be moved aside.
        let holder = Connection::open(&path).unwrap();
        holder
            .execute_batch("PRAGMA locking_mode=EXCLUSIVE;")
            .unwrap();
        holder
            .execute_batch("BEGIN EXCLUSIVE; CREATE TABLE zz(x);")
            .unwrap();
        let limits = Limits {
            busy_timeout: Duration::from_millis(50),
            ..Limits::default()
        };
        let result = Store::open_with(&path, limits);
        assert!(result.is_err(), "open should fail while locked");
        assert!(corrupt_siblings(dir.path()).is_empty());
        holder.execute_batch("ROLLBACK;").unwrap();
        drop(holder);
        assert!(!Store::open(&path).unwrap().was_recovered());
    }

    #[test]
    fn many_threads_share_one_store() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    for i in 0..100 {
                        store
                            .kv_set(&format!("t{t}-{i}"), &i, i64::from(i))
                            .unwrap();
                        store.kv_set("shared", &t, 0).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        for t in 0..8 {
            for i in 0..100 {
                assert_eq!(store.kv_get::<i32>(&format!("t{t}-{i}")).unwrap(), Some(i));
            }
        }
        assert!(store.kv_get::<i32>("shared").unwrap().is_some());
    }

    #[test]
    fn two_handles_on_one_file_do_not_lose_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        let a = Arc::new(Store::open(&path).unwrap().store);
        let b = Arc::new(Store::open(&path).unwrap().store);
        let handles: Vec<_> = [Arc::clone(&a), Arc::clone(&b)]
            .into_iter()
            .enumerate()
            .map(|(n, store)| {
                thread::spawn(move || {
                    for i in 0..150 {
                        store.kv_set(&format!("h{n}-{i}"), &i, 0).unwrap();
                        store
                            .rdp_logon_record("10.0.0.1".parse().unwrap(), i64::from(i))
                            .unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        for n in 0..2 {
            for i in 0..150 {
                assert_eq!(a.kv_get::<i32>(&format!("h{n}-{i}")).unwrap(), Some(i));
            }
        }
        let logons = b.rdp_logons_since(0).unwrap();
        assert_eq!(logons.len(), 1);
        assert_eq!(logons[0].count, 300);
    }

    #[test]
    fn clip_respects_char_boundaries() {
        assert_eq!(clip("abc", 10), "abc");
        assert_eq!(clip("abcdef", 3), "abc");
        // 'é' is two bytes: cutting at 1 must not split it.
        assert_eq!(clip("éa", 1), "");
        assert_eq!(clip("éa", 2), "é");
    }
}

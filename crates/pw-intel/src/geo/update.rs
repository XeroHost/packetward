// SPDX-License-Identifier: GPL-3.0-or-later
//! Monthly GeoIP database update: pure scheduling helpers plus a download-validate-replace step.
//!
//! DB-IP publishes Lite databases once a month as `dbip-<kind>-lite-YYYY-MM.mmdb.gz`. A download is decompressed with
//! a size cap, opened as a MaxMind DB, checked for sane lookups, and only then written to a temporary file and
//! atomically renamed over the installed one. Any failure leaves the previous database untouched.

use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;

use super::{load_validated, GeoError, GeoKind, MmdbGeo};
use crate::{FetchError, FetchRequest, Fetcher, UnixSecs};

/// Base URL of the DB-IP Lite downloads. Unverified against the live service (see the crate report).
pub const DBIP_DOWNLOAD_BASE: &str = "https://download.db-ip.com/free";
/// Check at most once a month.
pub const CHECK_INTERVAL_SECS: u64 = 30 * 24 * 3600;
/// Cap on the compressed download.
pub const MAX_COMPRESSED_BYTES: usize = 64 * 1024 * 1024;
/// Cap on the decompressed database (guards against a decompression bomb).
pub const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum GeoUpdateError {
    #[error("download failed: {0}")]
    Fetch(#[from] FetchError),
    #[error("the server answered HTTP {0}")]
    HttpStatus(u16),
    #[error("no database is published for the current or the previous month")]
    NotPublished,
    #[error("the download is not a valid gzip file: {0}")]
    Decompress(String),
    #[error("the decompressed database exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("the downloaded database was rejected: {0}")]
    Rejected(#[from] GeoError),
    #[error("cannot write the database: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// A newer database was installed and loaded.
    Updated { build_date: UnixSecs },
    /// The published database is not newer than the installed one; nothing changed.
    UpToDate { build_date: UnixSecs },
}

pub fn download_url(kind: GeoKind, year: i64, month: u32) -> String {
    format!(
        "{DBIP_DOWNLOAD_BASE}/{}-{year:04}-{month:02}.mmdb.gz",
        kind.dbip_name()
    )
}

/// Civil `(year, month)` of a Unix timestamp (UTC).
pub fn civil_from_unix(secs: UnixSecs) -> (i64, u32) {
    // Howard Hinnant's days-to-civil algorithm.
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month as u32)
}

/// The months to try, newest first: the current one (DB-IP publishes at the start of the month, sometimes a day
/// late) and then the previous one.
pub fn candidate_months(now: UnixSecs) -> [(i64, u32); 2] {
    let (year, month) = civil_from_unix(now);
    let previous = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };
    [(year, month), previous]
}

/// Pure: is a monthly check due? `last_check` is the time of the last *attempt* the caller recorded.
pub fn is_check_due(last_check: Option<UnixSecs>, now: UnixSecs, interval_secs: u64) -> bool {
    match last_check {
        None => true,
        // A last check in the future (clock set back) must not block updates.
        Some(last) if last > now => true,
        Some(last) => now - last >= interval_secs,
    }
}

fn gunzip(data: &[u8], limit: usize) -> Result<Vec<u8>, GeoUpdateError> {
    let mut out = Vec::new();
    GzDecoder::new(data)
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| GeoUpdateError::Decompress(e.to_string()))?;
    if out.len() > limit {
        return Err(GeoUpdateError::TooLarge { limit });
    }
    Ok(out)
}

/// Write to a temporary sibling and rename over `target`. On failure the temporary file is removed.
fn replace_atomically(dir: &Path, file_name: &str, bytes: &[u8]) -> Result<(), GeoUpdateError> {
    let io = |e: std::io::Error| GeoUpdateError::Io(e.to_string());
    std::fs::create_dir_all(dir).map_err(io)?;
    let target = dir.join(file_name);
    let temp = dir.join(format!("{file_name}.download"));
    let result = (|| {
        let mut file = std::fs::File::create(&temp)?;
        std::io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
        drop(file);
        // `rename` replaces an existing file on both Windows and Unix.
        std::fs::rename(&temp, &target)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&temp);
        return Err(io(e));
    }
    Ok(())
}

/// Check for and install the newest database of `kind`. Does the file I/O synchronously (a few MB); call it from a
/// background task. On `Updated` the new file is already loaded into `geo`.
pub async fn update_kind<F: Fetcher>(
    fetcher: &F,
    geo: &MmdbGeo,
    kind: GeoKind,
    now: UnixSecs,
) -> Result<UpdateOutcome, GeoUpdateError> {
    let mut compressed = None;
    for (year, month) in candidate_months(now) {
        let url = download_url(kind, year, month);
        let response = fetcher
            .fetch(FetchRequest::get(url, MAX_COMPRESSED_BYTES))
            .await?;
        match response.status {
            404 => continue,
            _ if response.is_success() => {
                compressed = Some(response.body);
                break;
            }
            other => return Err(GeoUpdateError::HttpStatus(other)),
        }
    }
    let compressed = compressed.ok_or(GeoUpdateError::NotPublished)?;
    let bytes = gunzip(&compressed, MAX_DECOMPRESSED_BYTES)?;
    // Everything below happens before the installed file is touched.
    let loaded = load_validated(bytes.clone(), kind)?;
    if let Some(installed) = geo.build_date(kind) {
        if loaded.build_epoch <= installed {
            return Ok(UpdateOutcome::UpToDate {
                build_date: installed,
            });
        }
    }
    replace_atomically(geo.dir(), kind.file_name(), &bytes)?;
    geo.reload();
    tracing::info!(file = kind.file_name(), "GeoIP database updated");
    Ok(UpdateOutcome::Updated {
        build_date: loaded.build_epoch,
    })
}

/// Update both databases. One failing does not stop the other; each failure leaves its previous file in place.
pub async fn update_all<F: Fetcher>(
    fetcher: &F,
    geo: &MmdbGeo,
    now: UnixSecs,
) -> Vec<(GeoKind, Result<UpdateOutcome, GeoUpdateError>)> {
    let mut results = Vec::new();
    for kind in GeoKind::ALL {
        let result = update_kind(fetcher, geo, kind, now).await;
        if let Err(error) = &result {
            tracing::warn!(file = kind.file_name(), %error, "GeoIP update failed; keeping the previous database");
        }
        results.push((kind, result));
    }
    results
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::write::GzEncoder;
    use flate2::Compression;

    use super::super::testdb::*;
    use super::super::{GeoDb, GeoStatus, COUNTRY_FILE};
    use super::*;
    use crate::testing::FakeFetcher;
    use crate::FetchResponse;

    /// 2026-11-19 00:00:00 UTC.
    const NOV_19_2026: u64 = 1_795_046_400;
    const OLD: u64 = 1_790_000_000;
    const NEW: u64 = 1_793_000_000;

    fn gz(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn installed(build: u64) -> (TempDir, MmdbGeo) {
        let dir = TempDir::new();
        std::fs::write(dir.path().join(COUNTRY_FILE), country_fixture(build)).unwrap();
        let geo = MmdbGeo::open(dir.path());
        (dir, geo)
    }

    fn leftovers(dir: &TempDir) -> Vec<String> {
        std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_unix(0), (1970, 1));
        assert_eq!(civil_from_unix(946_684_800), (2000, 1));
        assert_eq!(civil_from_unix(1_709_164_800), (2024, 2)); // 2024-02-29
        assert_eq!(civil_from_unix(1_709_251_200), (2024, 3)); // 2024-03-01
        assert_eq!(civil_from_unix(NOV_19_2026), (2026, 11));
        assert_eq!(civil_from_unix(NOV_19_2026 + 86_400 * 12), (2026, 12));
        assert!((1..=12).contains(&civil_from_unix(u64::MAX).1));
    }

    #[test]
    fn candidates_roll_back_across_a_year_boundary() {
        assert_eq!(candidate_months(NOV_19_2026), [(2026, 11), (2026, 10)]);
        // 2027-01-05
        assert_eq!(candidate_months(1_799_107_200), [(2027, 1), (2026, 12)]);
    }

    #[test]
    fn urls_follow_the_dbip_naming() {
        assert_eq!(
            download_url(GeoKind::Country, 2026, 11),
            "https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz"
        );
        assert_eq!(
            download_url(GeoKind::Asn, 2026, 3),
            "https://download.db-ip.com/free/dbip-asn-lite-2026-03.mmdb.gz"
        );
    }

    #[test]
    fn the_monthly_check_is_pure_and_robust() {
        assert!(is_check_due(None, 100, CHECK_INTERVAL_SECS));
        assert!(!is_check_due(
            Some(1_000),
            1_000 + CHECK_INTERVAL_SECS - 1,
            CHECK_INTERVAL_SECS
        ));
        assert!(is_check_due(
            Some(1_000),
            1_000 + CHECK_INTERVAL_SECS,
            CHECK_INTERVAL_SECS
        ));
        assert!(
            is_check_due(Some(5_000_000), 1_000, CHECK_INTERVAL_SECS),
            "clock set back"
        );
    }

    #[tokio::test]
    async fn a_first_install_falls_back_to_the_previous_month() {
        let dir = TempDir::new();
        let geo = MmdbGeo::open(dir.path());
        assert_eq!(geo.status(), GeoStatus::Missing);
        let fetcher = FakeFetcher::new();
        fetcher.route("2026-11", |_| Ok(FetchResponse::ok("").with_status(404)));
        let body = gz(&country_fixture(NEW));
        fetcher.route("country-lite-2026-10", move |_| {
            Ok(FetchResponse::ok(body.clone()))
        });
        let outcome = update_kind(&fetcher, &geo, GeoKind::Country, NOV_19_2026)
            .await
            .unwrap();
        assert_eq!(outcome, UpdateOutcome::Updated { build_date: NEW });
        assert_eq!(geo.status(), GeoStatus::Ready { build_date: NEW });
        assert_eq!(
            geo.lookup("8.8.8.8".parse().unwrap())
                .country_code
                .as_deref(),
            Some("US")
        );
        assert_eq!(
            leftovers(&dir),
            [COUNTRY_FILE],
            "no temporary file left behind"
        );
        assert_eq!(fetcher.request_count(), 2);
    }

    #[tokio::test]
    async fn a_newer_database_replaces_the_installed_one() {
        let (dir, geo) = installed(OLD);
        let fetcher = FakeFetcher::new();
        let body = gz(&country_fixture(NEW));
        fetcher.route("country-lite-2026-11", move |_| {
            Ok(FetchResponse::ok(body.clone()))
        });
        let outcome = update_kind(&fetcher, &geo, GeoKind::Country, NOV_19_2026)
            .await
            .unwrap();
        assert_eq!(outcome, UpdateOutcome::Updated { build_date: NEW });
        assert_eq!(geo.build_date(GeoKind::Country), Some(NEW));
        // The file on disk is the new one too (a restart sees it).
        assert_eq!(
            MmdbGeo::open(dir.path()).build_date(GeoKind::Country),
            Some(NEW)
        );
        assert_eq!(leftovers(&dir), [COUNTRY_FILE]);
    }

    #[tokio::test]
    async fn an_unchanged_or_older_database_changes_nothing() {
        let (dir, geo) = installed(NEW);
        let before = std::fs::read(dir.path().join(COUNTRY_FILE)).unwrap();
        for build in [NEW, OLD] {
            let fetcher = FakeFetcher::new();
            let body = gz(&country_fixture(build));
            fetcher.route("country-lite", move |_| Ok(FetchResponse::ok(body.clone())));
            let outcome = update_kind(&fetcher, &geo, GeoKind::Country, NOV_19_2026)
                .await
                .unwrap();
            assert_eq!(outcome, UpdateOutcome::UpToDate { build_date: NEW });
        }
        assert_eq!(
            std::fs::read(dir.path().join(COUNTRY_FILE)).unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn every_failure_keeps_the_previous_database() {
        let (dir, geo) = installed(OLD);
        let before = std::fs::read(dir.path().join(COUNTRY_FILE)).unwrap();
        let hollow = build_mmdb(
            &[("203.1.0.0/16", country_record("BR", "Brazil", "SA"))],
            NEW,
            "DBIP-Country-Lite",
        );
        let good = country_fixture(NEW);
        let cases: Vec<(&str, Result<FetchResponse, FetchError>)> = vec![
            ("not gzip", Ok(FetchResponse::ok("<html>blocked</html>"))),
            (
                "gzip of garbage",
                Ok(FetchResponse::ok(gz(b"not a database at all"))),
            ),
            (
                "truncated gzip",
                Ok(FetchResponse::ok(gz(&good)[..40].to_vec())),
            ),
            (
                "truncated database",
                Ok(FetchResponse::ok(gz(&good[..good.len() / 2]))),
            ),
            ("no sane lookup", Ok(FetchResponse::ok(gz(&hollow)))),
            ("server error", Ok(FetchResponse::ok("").with_status(500))),
            ("forbidden", Ok(FetchResponse::ok("").with_status(403))),
            ("timeout", Err(FetchError::Timeout)),
            ("network", Err(FetchError::Network("reset".into()))),
            ("too large", Err(FetchError::TooLarge { limit: 1 })),
        ];
        for (label, response) in cases {
            let fetcher = FakeFetcher::new();
            fetcher.route("dbip", move |_| response.clone());
            let result = update_kind(&fetcher, &geo, GeoKind::Country, NOV_19_2026).await;
            assert!(result.is_err(), "{label}");
            assert_eq!(
                geo.status(),
                GeoStatus::Ready { build_date: OLD },
                "{label}"
            );
            assert_eq!(
                std::fs::read(dir.path().join(COUNTRY_FILE)).unwrap(),
                before,
                "{label}"
            );
            assert_eq!(leftovers(&dir), [COUNTRY_FILE], "{label}");
        }
        // Both months missing.
        let fetcher = FakeFetcher::new();
        fetcher.route("dbip", |_| Ok(FetchResponse::ok("").with_status(404)));
        let error = update_kind(&fetcher, &geo, GeoKind::Country, NOV_19_2026)
            .await
            .unwrap_err();
        assert!(matches!(error, GeoUpdateError::NotPublished));
        assert_eq!(fetcher.request_count(), 2);
    }

    #[test]
    fn a_decompression_bomb_is_refused() {
        // Zeros compress about 1000:1; the output limit stops the read long before memory is a problem.
        let bomb = gz(&vec![0u8; 100_000]);
        assert!(bomb.len() < 1_000);
        assert!(matches!(
            gunzip(&bomb, 1_000),
            Err(GeoUpdateError::TooLarge { limit: 1_000 })
        ));
        assert_eq!(gunzip(&bomb, 100_000).unwrap().len(), 100_000);
    }

    #[tokio::test]
    async fn update_all_handles_each_database_independently() {
        let dir = TempDir::new();
        let geo = MmdbGeo::open(dir.path());
        let fetcher = FakeFetcher::new();
        let body = gz(&asn_fixture(NEW));
        fetcher.route("asn-lite", move |_| Ok(FetchResponse::ok(body.clone())));
        fetcher.route("country-lite", |_| {
            Ok(FetchResponse::ok("").with_status(500))
        });
        let results = update_all(&fetcher, &geo, NOV_19_2026).await;
        assert_eq!(results.len(), 2);
        assert!(results[0].1.is_err());
        assert!(results[1].1.is_ok());
        assert_eq!(
            geo.kind_status(GeoKind::Asn),
            GeoStatus::Ready { build_date: NEW }
        );
        assert_eq!(geo.kind_status(GeoKind::Country), GeoStatus::Missing);
    }
}

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! GeoIP / ASN lookup over DB-IP Lite `.mmdb` files (country + ASN), fully offline.
//!
//! The databases are downloaded at runtime by the user's choice (never bundled in the repository, see
//! `CLAUDE.md`). Without them everything keeps working: lookups return empty [`GeoInfo`] and
//! [`GeoDb::status`] says [`GeoStatus::Missing`].

mod update;

#[cfg(test)]
mod testdb;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use maxminddb::{geoip2, Reader};
use serde::{Deserialize, Serialize};

use crate::net::is_public_ip;
use crate::UnixSecs;

pub use update::{
    candidate_months, civil_from_unix, download_url, is_check_due, update_all, update_kind,
    GeoUpdateError, UpdateOutcome, CHECK_INTERVAL_SECS, DBIP_DOWNLOAD_BASE, MAX_COMPRESSED_BYTES,
    MAX_DECOMPRESSED_BYTES,
};

/// Attribution required by the CC BY 4.0 license of DB-IP Lite; shown in the About page.
pub const DBIP_ATTRIBUTION: &str = "IP geolocation data by DB-IP.com (https://db-ip.com), \
licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).";
pub const DBIP_URL: &str = "https://db-ip.com";
pub const DBIP_LICENSE_URL: &str = "https://creativecommons.org/licenses/by/4.0/";

/// Fixed file names inside the data directory. Updates replace them atomically.
pub const COUNTRY_FILE: &str = "dbip-country-lite.mmdb";
pub const ASN_FILE: &str = "dbip-asn-lite.mmdb";

/// Well-known public addresses used to check that a freshly downloaded database really contains data.
const SANITY_PROBES: &[&str] = &[
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
    "208.67.222.222",
    "2001:4860:4860::8888",
    "2606:4700:4700::1111",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GeoKind {
    Country,
    Asn,
}

impl GeoKind {
    pub const ALL: [GeoKind; 2] = [GeoKind::Country, GeoKind::Asn];

    pub fn file_name(self) -> &'static str {
        match self {
            GeoKind::Country => COUNTRY_FILE,
            GeoKind::Asn => ASN_FILE,
        }
    }

    /// Name used in the DB-IP download URL.
    pub fn dbip_name(self) -> &'static str {
        match self {
            GeoKind::Country => "dbip-country-lite",
            GeoKind::Asn => "dbip-asn-lite",
        }
    }
}

/// What is known about an address. Every field is optional: the databases are independent and incomplete.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2, e.g. `"US"`.
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub continent_code: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
}

impl GeoInfo {
    pub fn is_empty(&self) -> bool {
        *self == GeoInfo::default()
    }
}

/// State of the installed databases, for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeoStatus {
    /// No database installed: "not installed", offer the download.
    Missing,
    /// Usable. `build_date` is the database build time (Unix seconds); with two databases, the older of the two.
    Ready { build_date: UnixSecs },
    /// A database file exists but cannot be used (truncated, wrong format).
    Corrupt,
}

pub trait GeoDb: Send + Sync {
    /// Country and ASN of `ip`. Reserved (private, loopback, …) addresses and addresses without data give an empty
    /// [`GeoInfo`]; this never fails.
    fn lookup(&self, ip: IpAddr) -> GeoInfo;
    fn status(&self) -> GeoStatus;
}

#[derive(Debug, thiserror::Error)]
pub enum GeoError {
    #[error("cannot read the database: {0}")]
    Io(String),
    #[error("not a valid MaxMind DB file: {0}")]
    Invalid(String),
    #[error("the database contains no data for well-known public addresses")]
    NoSaneLookup,
}

struct Loaded {
    reader: Reader<Vec<u8>>,
    build_epoch: u64,
}

enum Slot {
    Missing,
    Ready(Box<Loaded>),
    Corrupt(String),
}

impl Slot {
    fn status(&self) -> GeoStatus {
        match self {
            Slot::Missing => GeoStatus::Missing,
            Slot::Ready(loaded) => GeoStatus::Ready {
                build_date: loaded.build_epoch,
            },
            Slot::Corrupt(_) => GeoStatus::Corrupt,
        }
    }
}

fn first_probe<T>(mut f: impl FnMut(IpAddr) -> Option<T>) -> Option<T> {
    SANITY_PROBES
        .iter()
        .filter_map(|p| p.parse::<IpAddr>().ok())
        .find_map(&mut f)
}

fn lookup_country(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Option<GeoInfo> {
    let result = reader.lookup(ip).ok()?;
    let record: geoip2::Country<'_> = result.decode().ok().flatten()?;
    let info = GeoInfo {
        country_code: record.country.iso_code.map(str::to_owned),
        country_name: record.country.names.english.map(str::to_owned),
        continent_code: record.continent.code.map(str::to_owned),
        ..GeoInfo::default()
    };
    (!info.is_empty()).then_some(info)
}

fn lookup_asn(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Option<(u32, Option<String>)> {
    let result = reader.lookup(ip).ok()?;
    let record: geoip2::Asn<'_> = result.decode().ok().flatten()?;
    let number = record.autonomous_system_number.filter(|n| *n != 0)?;
    Some((
        number,
        record.autonomous_system_organization.map(str::to_owned),
    ))
}

/// Open `bytes` as a database of `kind` and check that it holds sane data. Used when loading from disk and to vet a
/// download before it replaces the installed file.
fn load_validated(bytes: Vec<u8>, kind: GeoKind) -> Result<Loaded, GeoError> {
    let reader = Reader::from_source(bytes).map_err(|e| GeoError::Invalid(e.to_string()))?;
    let build_epoch = reader.metadata().build_epoch;
    let sane = match kind {
        GeoKind::Country => first_probe(|ip| {
            lookup_country(&reader, ip)
                .and_then(|i| i.country_code)
                .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()))
        })
        .is_some(),
        GeoKind::Asn => first_probe(|ip| lookup_asn(&reader, ip)).is_some(),
    };
    if !sane {
        return Err(GeoError::NoSaneLookup);
    }
    Ok(Loaded {
        reader,
        build_epoch,
    })
}

fn load_slot(dir: &Path, kind: GeoKind) -> Slot {
    let path = dir.join(kind.file_name());
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Slot::Missing,
        Err(e) => {
            tracing::warn!(file = kind.file_name(), error = %e, "cannot read the GeoIP database");
            return Slot::Corrupt(e.to_string());
        }
    };
    match load_validated(bytes, kind) {
        Ok(loaded) => Slot::Ready(Box::new(loaded)),
        Err(e) => {
            tracing::warn!(file = kind.file_name(), error = %e, "the GeoIP database is unusable");
            Slot::Corrupt(e.to_string())
        }
    }
}

struct Slots {
    country: Slot,
    asn: Slot,
}

/// DB-IP Lite country + ASN databases in one directory. The files are read into memory (no memory map), so replacing
/// one on disk while the agent runs is safe on Windows.
pub struct MmdbGeo {
    dir: PathBuf,
    slots: RwLock<Slots>,
}

impl MmdbGeo {
    /// Load whatever is installed in `dir`. Never fails: missing or broken files just show up in the status.
    pub fn open(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let slots = Slots {
            country: load_slot(&dir, GeoKind::Country),
            asn: load_slot(&dir, GeoKind::Asn),
        };
        Self {
            dir,
            slots: RwLock::new(slots),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Re-read both files (after an update).
    pub fn reload(&self) {
        let fresh = Slots {
            country: load_slot(&self.dir, GeoKind::Country),
            asn: load_slot(&self.dir, GeoKind::Asn),
        };
        *self.slots.write().unwrap_or_else(|e| e.into_inner()) = fresh;
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Slots> {
        self.slots.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Status of one database.
    pub fn kind_status(&self, kind: GeoKind) -> GeoStatus {
        let slots = self.read();
        match kind {
            GeoKind::Country => slots.country.status(),
            GeoKind::Asn => slots.asn.status(),
        }
    }

    /// Why the database of `kind` is [`GeoStatus::Corrupt`], for the UI details line.
    pub fn corrupt_reason(&self, kind: GeoKind) -> Option<String> {
        let slots = self.read();
        let slot = match kind {
            GeoKind::Country => &slots.country,
            GeoKind::Asn => &slots.asn,
        };
        match slot {
            Slot::Corrupt(reason) => Some(reason.clone()),
            _ => None,
        }
    }

    /// Build time of the installed database of `kind`, if it is usable.
    pub fn build_date(&self, kind: GeoKind) -> Option<UnixSecs> {
        match self.kind_status(kind) {
            GeoStatus::Ready { build_date } => Some(build_date),
            _ => None,
        }
    }
}

impl std::fmt::Debug for MmdbGeo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmdbGeo")
            .field("dir", &self.dir)
            .field("country", &self.kind_status(GeoKind::Country))
            .field("asn", &self.kind_status(GeoKind::Asn))
            .finish()
    }
}

impl GeoDb for MmdbGeo {
    fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let ip = ip.to_canonical();
        if !is_public_ip(ip) {
            return GeoInfo::default();
        }
        let slots = self.read();
        let mut info = match &slots.country {
            Slot::Ready(db) => lookup_country(&db.reader, ip).unwrap_or_default(),
            _ => GeoInfo::default(),
        };
        if let Slot::Ready(db) = &slots.asn {
            if let Some((number, org)) = lookup_asn(&db.reader, ip) {
                info.asn = Some(number);
                info.as_org = org;
            }
        }
        info
    }

    /// Overall state: `Corrupt` if any installed file is unusable, else `Ready` (with the older build date) if at
    /// least one database works, else `Missing`. Use [`MmdbGeo::kind_status`] for the details.
    fn status(&self) -> GeoStatus {
        let slots = self.read();
        let (country, asn) = (slots.country.status(), slots.asn.status());
        match (country, asn) {
            (GeoStatus::Corrupt, _) | (_, GeoStatus::Corrupt) => GeoStatus::Corrupt,
            (GeoStatus::Ready { build_date: a }, GeoStatus::Ready { build_date: b }) => {
                GeoStatus::Ready {
                    build_date: a.min(b),
                }
            }
            (ready @ GeoStatus::Ready { .. }, GeoStatus::Missing)
            | (GeoStatus::Missing, ready @ GeoStatus::Ready { .. }) => ready,
            (GeoStatus::Missing, GeoStatus::Missing) => GeoStatus::Missing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testdb::*;
    use super::*;

    const BUILD: u64 = 1_793_000_000;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn dir_with(country: Option<Vec<u8>>, asn: Option<Vec<u8>>) -> TempDir {
        let dir = TempDir::new();
        if let Some(bytes) = country {
            std::fs::write(dir.path().join(COUNTRY_FILE), bytes).unwrap();
        }
        if let Some(bytes) = asn {
            std::fs::write(dir.path().join(ASN_FILE), bytes).unwrap();
        }
        dir
    }

    #[test]
    fn attribution_names_db_ip_and_the_license() {
        assert!(DBIP_ATTRIBUTION.contains("DB-IP"));
        assert!(DBIP_ATTRIBUTION.contains("CC BY 4.0"));
        assert!(DBIP_ATTRIBUTION.contains("https://db-ip.com"));
    }

    #[test]
    fn no_database_installed_is_a_graceful_state() {
        let dir = dir_with(None, None);
        let geo = MmdbGeo::open(dir.path());
        assert_eq!(geo.status(), GeoStatus::Missing);
        assert_eq!(geo.kind_status(GeoKind::Country), GeoStatus::Missing);
        assert!(geo.lookup(ip("8.8.8.8")).is_empty());
        // A directory that does not even exist is the same state.
        let geo = MmdbGeo::open(dir.path().join("nope"));
        assert_eq!(geo.status(), GeoStatus::Missing);
    }

    #[test]
    fn both_databases_answer_lookups() {
        let dir = dir_with(Some(country_fixture(BUILD)), Some(asn_fixture(BUILD + 100)));
        let geo = MmdbGeo::open(dir.path());
        // The overall build date is the older one.
        assert_eq!(geo.status(), GeoStatus::Ready { build_date: BUILD });
        assert_eq!(geo.build_date(GeoKind::Asn), Some(BUILD + 100));

        let google = geo.lookup(ip("8.8.8.8"));
        assert_eq!(google.country_code.as_deref(), Some("US"));
        assert_eq!(google.country_name.as_deref(), Some("United States"));
        assert_eq!(google.continent_code.as_deref(), Some("NA"));
        assert_eq!(google.asn, Some(15169));
        assert_eq!(google.as_org.as_deref(), Some("Google LLC"));

        let v6 = geo.lookup(ip("2001:4860:4860::8888"));
        assert_eq!(v6.country_code.as_deref(), Some("US"));
        assert_eq!(v6.asn, Some(15169));
        let mapped = geo.lookup(ip("::ffff:8.8.8.8"));
        assert_eq!(mapped.asn, Some(15169));

        let br = geo.lookup(ip("203.1.200.9"));
        assert_eq!(br.country_code.as_deref(), Some("BR"));
        assert_eq!(br.asn, Some(64500));

        // Public but not in the databases: empty, not an error.
        assert!(geo.lookup(ip("9.9.9.9")).is_empty());
    }

    #[test]
    fn reserved_addresses_are_never_looked_up() {
        // Even a database that (wrongly) holds a record for private space is not consulted.
        let bytes = build_mmdb(
            &[
                ("10.0.0.0/8", country_record("ZZ", "Nowhere", "EU")),
                ("8.8.8.0/24", country_record("US", "United States", "NA")),
            ],
            BUILD,
            "DBIP-Country-Lite",
        );
        let dir = dir_with(Some(bytes), None);
        let geo = MmdbGeo::open(dir.path());
        assert!(geo.lookup(ip("10.1.2.3")).is_empty());
        assert!(geo.lookup(ip("127.0.0.1")).is_empty());
        assert!(geo.lookup(ip("fe80::1")).is_empty());
        assert_eq!(
            geo.lookup(ip("8.8.8.8")).country_code.as_deref(),
            Some("US")
        );
    }

    #[test]
    fn a_single_installed_database_gives_partial_results() {
        let dir = dir_with(Some(country_fixture(BUILD)), None);
        let geo = MmdbGeo::open(dir.path());
        assert_eq!(geo.status(), GeoStatus::Ready { build_date: BUILD });
        let info = geo.lookup(ip("8.8.8.8"));
        assert_eq!(info.country_code.as_deref(), Some("US"));
        assert_eq!(info.asn, None);

        let dir = dir_with(None, Some(asn_fixture(BUILD)));
        let geo = MmdbGeo::open(dir.path());
        assert_eq!(geo.status(), GeoStatus::Ready { build_date: BUILD });
        let info = geo.lookup(ip("8.8.8.8"));
        assert_eq!(info.country_code, None);
        assert_eq!(info.asn, Some(15169));
    }

    #[test]
    fn garbage_truncated_and_empty_databases_are_corrupt() {
        let good = country_fixture(BUILD);
        for (label, bytes) in [
            ("garbage", b"this is not a database".to_vec()),
            ("empty", Vec::new()),
            ("truncated", good[..good.len() / 2].to_vec()),
            ("metadata only", good[good.len() - 80..].to_vec()),
        ] {
            let dir = dir_with(Some(bytes), None);
            let geo = MmdbGeo::open(dir.path());
            assert_eq!(geo.status(), GeoStatus::Corrupt, "{label}");
            assert!(geo.lookup(ip("8.8.8.8")).is_empty(), "{label}");
        }
        // A valid database that holds no data for any probe address is refused as well.
        let hollow = build_mmdb(
            &[("203.1.0.0/16", country_record("BR", "Brazil", "SA"))],
            BUILD,
            "DBIP-Country-Lite",
        );
        let dir = dir_with(Some(hollow), None);
        assert_eq!(MmdbGeo::open(dir.path()).status(), GeoStatus::Corrupt);
        // An ASN database installed in the country slot has no usable country data either.
        let dir = dir_with(Some(asn_fixture(BUILD)), None);
        assert_eq!(MmdbGeo::open(dir.path()).status(), GeoStatus::Corrupt);
    }

    #[test]
    fn one_corrupt_file_marks_the_overall_status_corrupt_but_the_other_still_works() {
        let dir = dir_with(Some(b"junk".to_vec()), Some(asn_fixture(BUILD)));
        let geo = MmdbGeo::open(dir.path());
        assert_eq!(geo.status(), GeoStatus::Corrupt);
        assert_eq!(
            geo.kind_status(GeoKind::Asn),
            GeoStatus::Ready { build_date: BUILD }
        );
        assert_eq!(geo.lookup(ip("8.8.8.8")).asn, Some(15169));
    }

    #[test]
    fn reload_picks_up_a_new_file() {
        let dir = dir_with(None, None);
        let geo = MmdbGeo::open(dir.path());
        assert_eq!(geo.status(), GeoStatus::Missing);
        std::fs::write(dir.path().join(COUNTRY_FILE), country_fixture(BUILD)).unwrap();
        geo.reload();
        assert_eq!(geo.status(), GeoStatus::Ready { build_date: BUILD });
    }
}

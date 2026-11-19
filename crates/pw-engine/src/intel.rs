// SPDX-License-Identifier: GPL-3.0-or-later
//! Threat intelligence service (M8): GeoIP/ASN lookups, blocklists applied through the firewall, and
//! the optional AbuseIPDB reputation check. Wraps `pw-intel`; every download goes through a
//! `Fetcher`, so tests never touch the network and a build without the HTTP feature simply cannot
//! download (the local database and cached lists keep working offline).

use std::collections::BTreeMap;
use std::fs;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pw_core::{Cidr, CidrSet};
use pw_intel::abuseipdb::{AbuseConfig, AbuseError, AbuseIpdbClient, AbuseState, MemoryAbuseCache};
use pw_intel::blocklist::{
    build_list, BlocklistManager, ListConfig, ListSnapshot, ParseLimits, ScheduleState,
};
use pw_intel::geo::{update_all, GeoDb, GeoStatus, MmdbGeo, DBIP_ATTRIBUTION};
use pw_intel::net::is_public_ip;
use pw_intel::secret::ABUSEIPDB_KEY_NAME;
use pw_intel::{
    Clock, FetchError, FetchRequest, FetchResponse, Fetcher, Secret, SecretStore, SystemClock,
};
use pw_proto::{
    AbuseCheckRequest, AbuseCheckView, AbuseKeyRequest, AbuseStatusView, BlocklistsView, ErrorCode,
    ErrorPayload, GeoEntry, GeoLookupRequest, GeoLookupResult, GeoStatusView, ListEnableRequest,
    ListRefreshRequest, ListStatusView,
};
use serde::{Deserialize, Serialize};

use crate::defense::Defense;

const MAX_LOOKUP: usize = 500;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, ErrorPayload>> + Send + 'a>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::BadRequest, message)
}

fn internal(message: impl ToString) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::Internal, message.to_string())
}

/// What the engine needs from the intel service.
pub trait IntelApi: Send + Sync {
    fn geo_status(&self) -> GeoStatusView;
    fn lookup(&self, request: &GeoLookupRequest) -> Result<GeoLookupResult, ErrorPayload>;
    /// Local lookup of one address, for enriching traceroute hops. Never touches the network.
    fn lookup_one(&self, ip: IpAddr) -> Option<(Option<u32>, Option<String>, Option<String>)>;
    fn geo_update(&self) -> Result<GeoStatusView, ErrorPayload>;
    fn lists(&self) -> BlocklistsView;
    fn set_list_enabled(&self, request: ListEnableRequest) -> BoxFut<'_, BlocklistsView>;
    fn refresh_list(&self, request: ListRefreshRequest) -> BoxFut<'_, BlocklistsView>;
    /// Refreshes the lists that are due and re-applies them (called periodically).
    fn tick(&self) -> BoxFut<'_, ()>;
    fn abuse_status(&self) -> AbuseStatusView;
    fn set_abuse_key(&self, request: AbuseKeyRequest) -> Result<AbuseStatusView, ErrorPayload>;
    fn abuse_check(&self, request: AbuseCheckRequest) -> BoxFut<'_, AbuseCheckView>;
}

/// A fetcher for builds and tests with no network: every request fails with a clear message.
pub struct OfflineFetcher;

impl Fetcher for OfflineFetcher {
    async fn fetch(&self, _: FetchRequest) -> Result<FetchResponse, FetchError> {
        Err(FetchError::Network(
            "this build has no network transport".to_owned(),
        ))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct SavedList {
    enabled: bool,
    refresh_interval_secs: u64,
    last_attempt: Option<u64>,
    last_success: Option<u64>,
    consecutive_failures: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    lists: BTreeMap<String, SavedList>,
}

pub struct IntelService<F: Fetcher + 'static> {
    fetcher: Arc<F>,
    geo: Arc<MmdbGeo>,
    clock: Arc<dyn Clock>,
    lists: tokio::sync::Mutex<BlocklistManager>,
    defense: Arc<Defense>,
    dir: Option<PathBuf>,
    secrets: Arc<dyn SecretStore>,
    abuse: AbuseIpdbClient<Arc<F>>,
    updating: Arc<AtomicBool>,
    geo_error: Arc<Mutex<Option<String>>>,
}

impl<F: Fetcher + 'static> IntelService<F> {
    /// `dir` holds `geoip/`, `lists/` and `intel.json` (`None`: nothing is persisted).
    pub fn new(
        fetcher: F,
        secrets: Arc<dyn SecretStore>,
        dir: Option<PathBuf>,
        defense: Arc<Defense>,
    ) -> Self {
        Self::with_clock(fetcher, secrets, dir, defense, Arc::new(SystemClock))
    }

    pub fn with_clock(
        fetcher: F,
        secrets: Arc<dyn SecretStore>,
        dir: Option<PathBuf>,
        defense: Arc<Defense>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let fetcher = Arc::new(fetcher);
        let geo = Arc::new(MmdbGeo::open(
            dir.as_ref()
                .map_or_else(|| PathBuf::from("geoip-unavailable"), |d| d.join("geoip")),
        ));
        let mut manager = BlocklistManager::with_builtin_sources(Arc::clone(&clock));
        if let Some(dir) = &dir {
            restore_lists(&mut manager, dir, &defense.protected_set());
        }
        let abuse = AbuseIpdbClient::new(
            Arc::clone(&fetcher),
            Arc::clone(&secrets),
            Arc::new(MemoryAbuseCache::new()),
            Arc::clone(&clock),
            AbuseConfig::default(),
        );
        Self {
            fetcher,
            geo,
            clock,
            lists: tokio::sync::Mutex::new(manager),
            defense,
            dir,
            secrets,
            abuse,
            updating: Arc::new(AtomicBool::new(false)),
            geo_error: Arc::new(Mutex::new(None)),
        }
    }

    fn view(
        status: &pw_intel::blocklist::ListStatus,
        manager: &BlocklistManager,
    ) -> ListStatusView {
        let source = manager.source(&status.id);
        ListStatusView {
            id: status.id.clone(),
            name: source.map_or_else(|| status.id.clone(), |s| s.name.to_owned()),
            description: source.map_or_else(String::new, |s| s.description.to_owned()),
            signed: source.is_some_and(pw_intel::blocklist::ListSource::is_signed),
            enabled: status.enabled,
            refresh_interval_secs: status.refresh_interval_secs,
            last_success: status.last_success,
            last_error: status.last_error.clone(),
            entries: status.entries as u64,
            unavailable: status.unavailable.clone(),
        }
    }

    fn lists_view(manager: &BlocklistManager) -> BlocklistsView {
        let mut lists: Vec<ListStatusView> = manager
            .statuses()
            .iter()
            .map(|s| Self::view(s, manager))
            .collect();
        lists.sort_by(|a, b| b.signed.cmp(&a.signed).then(a.id.cmp(&b.id)));
        BlocklistsView { lists }
    }

    fn save(&self, manager: &BlocklistManager) {
        let Some(dir) = &self.dir else { return };
        let mut saved = Saved::default();
        for status in manager.statuses() {
            saved.lists.insert(
                status.id.clone(),
                SavedList {
                    enabled: status.enabled,
                    refresh_interval_secs: status.refresh_interval_secs,
                    last_attempt: status.last_attempt,
                    last_success: status.last_success,
                    consecutive_failures: status.consecutive_failures,
                },
            );
            if let Some(snapshot) = manager.snapshot(&status.id) {
                let text: String = snapshot
                    .public_blocks
                    .iter()
                    .map(|b| format!("{}\n", pw_firewall::addr::format_cidr(b)))
                    .collect();
                let lists = dir.join("lists");
                if fs::create_dir_all(&lists).is_ok() {
                    let _ = fs::write(lists.join(format!("{}.txt", status.id)), text);
                }
            }
        }
        if let Ok(json) = serde_json::to_vec_pretty(&saved) {
            let _ = fs::create_dir_all(dir);
            let tmp = dir.join("intel.json.tmp");
            if fs::write(&tmp, json).is_ok() {
                let _ = fs::rename(tmp, dir.join("intel.json"));
            }
        }
    }

    /// Makes the firewall match the enabled lists (and clears the batches of disabled ones).
    async fn apply(&self, manager: &BlocklistManager) {
        let protected = self.defense.protected_set();
        let active: BTreeMap<String, Vec<Cidr>> =
            manager.active_blocks(&protected).into_iter().collect();
        let ids = manager.ids();
        let defense = Arc::clone(&self.defense);
        let job = tokio::task::spawn_blocking(move || {
            for id in ids {
                match active.get(&id) {
                    Some(blocks) => defense.apply_list(&id, blocks),
                    None => defense.clear_list(&id),
                }
            }
        });
        if let Err(err) = job.await {
            tracing::error!(%err, "applying the blocklists failed");
        }
    }
}

fn restore_lists(manager: &mut BlocklistManager, dir: &std::path::Path, protected: &CidrSet) {
    let saved: Saved = fs::read_to_string(dir.join("intel.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    for (id, list) in saved.lists {
        let snapshot = fs::read(dir.join("lists").join(format!("{id}.txt")))
            .ok()
            .and_then(|data| {
                let limits = ParseLimits {
                    allow_empty: true,
                    ..ParseLimits::default()
                };
                build_list(&data, &limits, protected).ok()
            })
            .map(|built| ListSnapshot {
                id: id.clone(),
                fetched_at: list.last_success.unwrap_or(0),
                public_blocks: built.public_blocks,
                effective_blocks: built.effective_blocks,
                report: built.report,
            });
        let _ = manager.restore(
            &id,
            ListConfig {
                enabled: list.enabled,
                refresh_interval_secs: list.refresh_interval_secs,
            },
            ScheduleState {
                last_attempt: list.last_attempt,
                last_success: list.last_success,
                consecutive_failures: list.consecutive_failures,
            },
            snapshot,
        );
    }
}

fn geo_entry(addr: &str, geo: &MmdbGeo) -> GeoEntry {
    let empty = GeoEntry {
        addr: addr.to_owned(),
        country_code: None,
        country_name: None,
        asn: None,
        as_org: None,
        reserved: false,
    };
    let Ok(ip) = addr.trim().parse::<IpAddr>() else {
        return empty;
    };
    let ip = ip.to_canonical();
    if !is_public_ip(ip) {
        return GeoEntry {
            reserved: true,
            ..empty
        };
    }
    let info = geo.lookup(ip);
    GeoEntry {
        country_code: info.country_code,
        country_name: info.country_name,
        asn: info.asn,
        as_org: info.as_org,
        ..empty
    }
}

impl<F: Fetcher + 'static> IntelApi for IntelService<F> {
    fn geo_status(&self) -> GeoStatusView {
        let (state, build_date) = match self.geo.status() {
            GeoStatus::Missing => ("missing", None),
            GeoStatus::Ready { build_date } => ("ready", Some(build_date)),
            GeoStatus::Corrupt => ("corrupt", None),
        };
        GeoStatusView {
            state: state.to_owned(),
            build_date,
            updating: self.updating.load(Ordering::Relaxed),
            last_error: lock(&self.geo_error).clone(),
            attribution: DBIP_ATTRIBUTION.to_owned(),
        }
    }

    fn lookup(&self, request: &GeoLookupRequest) -> Result<GeoLookupResult, ErrorPayload> {
        if request.addrs.len() > MAX_LOOKUP {
            return Err(bad_request(format!(
                "at most {MAX_LOOKUP} addresses per call"
            )));
        }
        Ok(GeoLookupResult {
            entries: request
                .addrs
                .iter()
                .map(|a| geo_entry(a, &self.geo))
                .collect(),
        })
    }

    fn lookup_one(&self, ip: IpAddr) -> Option<(Option<u32>, Option<String>, Option<String>)> {
        let ip = ip.to_canonical();
        if !is_public_ip(ip) {
            return None;
        }
        let info = self.geo.lookup(ip);
        (info.asn.is_some() || info.country_code.is_some()).then_some((
            info.asn,
            info.as_org,
            info.country_code,
        ))
    }

    fn geo_update(&self) -> Result<GeoStatusView, ErrorPayload> {
        if self.updating.swap(true, Ordering::SeqCst) {
            return Err(ErrorPayload::new(
                ErrorCode::Busy,
                "the database is already being updated",
            ));
        }
        *lock(&self.geo_error) = None;
        let fetcher = Arc::clone(&self.fetcher);
        let geo = Arc::clone(&self.geo);
        let now = self.clock.now();
        let updating = Arc::clone(&self.updating);
        let error = Arc::clone(&self.geo_error);
        tokio::spawn(async move {
            let results = update_all(&*fetcher, &geo, now).await;
            let failures: Vec<String> = results
                .into_iter()
                .filter_map(|(kind, result)| result.err().map(|e| format!("{kind:?}: {e}")))
                .collect();
            *lock(&error) = (!failures.is_empty()).then(|| failures.join("; "));
            updating.store(false, Ordering::SeqCst);
        });
        Ok(self.geo_status())
    }

    fn lists(&self) -> BlocklistsView {
        match self.lists.try_lock() {
            Ok(manager) => Self::lists_view(&manager),
            // A refresh is running: report the last state it left (the lock is held for seconds at most).
            Err(_) => BlocklistsView::default(),
        }
    }

    fn set_list_enabled(&self, request: ListEnableRequest) -> BoxFut<'_, BlocklistsView> {
        Box::pin(async move {
            let mut manager = self.lists.lock().await;
            manager
                .set_enabled(&request.id, request.enabled)
                .map_err(|e| bad_request(e.to_string()))?;
            self.save(&manager);
            self.apply(&manager).await;
            Ok(Self::lists_view(&manager))
        })
    }

    fn refresh_list(&self, request: ListRefreshRequest) -> BoxFut<'_, BlocklistsView> {
        Box::pin(async move {
            let protected = self.defense.protected_set();
            let mut manager = self.lists.lock().await;
            let outcome = manager
                .refresh(&request.id, &*self.fetcher, &protected)
                .await;
            self.save(&manager);
            self.apply(&manager).await;
            let view = Self::lists_view(&manager);
            // The failure is part of the list's status (and keeps the last good list in force).
            if let Err(err) = outcome {
                tracing::info!(list = %request.id, %err, "blocklist refresh failed");
            }
            Ok(view)
        })
    }

    fn tick(&self) -> BoxFut<'_, ()> {
        Box::pin(async move {
            let protected = self.defense.protected_set();
            let mut manager = self.lists.lock().await;
            let results = manager.refresh_due(&*self.fetcher, &protected).await;
            if !results.is_empty() {
                self.save(&manager);
            }
            // Re-applied every pass: a newly protected address must come out of a list at once.
            self.apply(&manager).await;
            Ok(())
        })
    }

    fn abuse_status(&self) -> AbuseStatusView {
        match self.abuse.state() {
            Ok(AbuseState::Ready) => AbuseStatusView {
                configured: true,
                state: "ready".to_owned(),
                paused_until: None,
            },
            Ok(AbuseState::RateLimited { until }) => AbuseStatusView {
                configured: true,
                state: "rate_limited".to_owned(),
                paused_until: Some(until),
            },
            _ => AbuseStatusView {
                configured: false,
                state: "not_configured".to_owned(),
                paused_until: None,
            },
        }
    }

    fn set_abuse_key(&self, request: AbuseKeyRequest) -> Result<AbuseStatusView, ErrorPayload> {
        match request.key.as_deref().map(str::trim) {
            Some(key) if !key.is_empty() => {
                if key.len() > 256 || key.chars().any(char::is_control) {
                    return Err(bad_request("that is not an API key"));
                }
                self.secrets
                    .set(ABUSEIPDB_KEY_NAME, &Secret::new(key))
                    .map_err(|e| internal(e.to_string()))?;
            }
            _ => self
                .secrets
                .delete(ABUSEIPDB_KEY_NAME)
                .map_err(|e| internal(e.to_string()))?,
        }
        Ok(self.abuse_status())
    }

    fn abuse_check(&self, request: AbuseCheckRequest) -> BoxFut<'_, AbuseCheckView> {
        Box::pin(async move {
            let ip: IpAddr = request
                .addr
                .trim()
                .parse()
                .map_err(|_| bad_request("that is not an IP address"))?;
            let check = self.abuse.check(ip).await.map_err(|e| match e {
                AbuseError::NotConfigured => bad_request("no AbuseIPDB key is configured"),
                AbuseError::NotPublic => bad_request(
                    "private and reserved addresses are never sent to an external service",
                ),
                other => internal(other.to_string()),
            })?;
            let r = check.report;
            Ok(AbuseCheckView {
                addr: ip.to_string(),
                score: r.abuse_confidence_score,
                country_code: r.country_code,
                usage_type: r.usage_type,
                isp: r.isp,
                domain: r.domain,
                total_reports: r.total_reports,
                last_reported_at: r.last_reported_at,
                from_cache: check.from_cache,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use pw_firewall::fake::FakeFirewall;
    use pw_firewall::{BatchId, Firewall, FirewallManager};
    use pw_intel::testing::FakeFetcher;
    use pw_intel::MemorySecretStore;
    use pw_netstat::NetworkContext;

    use super::*;
    use crate::defense::MemoryPersistence;
    use crate::trust::TrustState;

    const GATEWAY: &str = "1.10.16.1";
    const V4_LIST: &str = "; Spamhaus DROP\n1.10.16.0/20 ; SBL1\n5.6.0.0/16\n10.0.0.0/8\n";
    const V6_LIST: &str = "; v6\n2a00:1234::/32 ; SBL2\n";

    struct Rig {
        service: IntelService<FakeFetcher>,
        firewall: Arc<FirewallManager<FakeFirewall>>,
        defense: Arc<Defense>,
        broken: Arc<AtomicBool>,
    }

    fn new_defense() -> (Arc<FirewallManager<FakeFirewall>>, Arc<Defense>) {
        let firewall = Arc::new(FirewallManager::new(FakeFirewall::windows_defaults()));
        let context = Arc::new(RwLock::new(NetworkContext {
            gateways: vec![GATEWAY.parse().unwrap()],
            dns_servers: vec![],
        }));
        let defense = Arc::new(Defense::new(
            Arc::clone(&firewall) as Arc<dyn Firewall>,
            Arc::new(MemoryPersistence::default()),
            context,
            TrustState::new(30),
        ));
        (firewall, defense)
    }

    fn rig_in(dir: Option<PathBuf>) -> Rig {
        let (firewall, defense) = new_defense();
        let broken = Arc::new(AtomicBool::new(false));
        let fetcher = FakeFetcher::new();
        let flag = Arc::clone(&broken);
        fetcher.route("drop.txt", move |_| {
            Ok(FetchResponse::ok(if flag.load(Ordering::SeqCst) {
                "<html>\n<body>\nerror\n</body>\n</html>\n"
            } else {
                V4_LIST
            }))
        });
        fetcher.route("dropv6.txt", |_| Ok(FetchResponse::ok(V6_LIST)));
        Rig {
            service: IntelService::new(
                fetcher,
                Arc::new(MemorySecretStore::new()),
                dir,
                Arc::clone(&defense),
            ),
            firewall,
            defense,
            broken,
        }
    }

    fn blocked(firewall: &FirewallManager<FakeFirewall>, id: &str) -> Vec<String> {
        let mut blocks: Vec<String> = firewall
            .list_blocks(&BatchId::list(id).unwrap())
            .unwrap()
            .iter()
            .map(pw_firewall::addr::format_cidr)
            .collect();
        blocks.sort();
        blocks
    }

    fn enable(id: &str) -> ListEnableRequest {
        ListEnableRequest {
            id: id.to_owned(),
            enabled: true,
        }
    }

    fn refresh(id: &str) -> ListRefreshRequest {
        ListRefreshRequest { id: id.to_owned() }
    }

    #[tokio::test]
    async fn every_list_starts_disabled_and_the_xerohost_list_fails_closed() {
        let rig = rig_in(None);
        let lists = rig.service.lists();
        assert!(lists.lists.len() >= 3 && lists.lists.iter().all(|l| !l.enabled));
        let xerohost = lists.lists.iter().find(|l| l.signed).unwrap();
        assert!(xerohost.unavailable.is_some(), "no pinned key yet");
        let err = rig
            .service
            .set_list_enabled(enable(&xerohost.id))
            .await
            .unwrap_err();
        assert!(matches!(err.code, ErrorCode::BadRequest));
    }

    #[tokio::test]
    async fn an_enabled_list_is_applied_without_private_or_protected_addresses() {
        let rig = rig_in(None);
        rig.service
            .set_list_enabled(enable("spamhaus-drop"))
            .await
            .unwrap();
        let view = rig
            .service
            .refresh_list(refresh("spamhaus-drop"))
            .await
            .unwrap();
        let list = view.lists.iter().find(|l| l.id == "spamhaus-drop").unwrap();
        assert!(
            list.enabled && list.last_error.is_none() && list.entries >= 2,
            "{list:?}"
        );
        let applied = blocked(&rig.firewall, "spamhaus-drop");
        assert!(applied.contains(&"5.6.0.0/16".to_owned()), "{applied:?}");
        assert!(
            applied.contains(&"2a00:1234::/32".to_owned()),
            "{applied:?}"
        );
        assert!(!applied.iter().any(|b| b.starts_with("10.")), "{applied:?}");
        // The gateway lives inside 1.10.16.0/20: that block must not be applied whole.
        assert!(!applied.contains(&"1.10.16.0/20".to_owned()), "{applied:?}");
        assert!(rig
            .defense
            .protected_set()
            .contains(GATEWAY.parse().unwrap()));
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_last_good_list_and_says_why() {
        let rig = rig_in(None);
        rig.service
            .set_list_enabled(enable("spamhaus-drop"))
            .await
            .unwrap();
        rig.service
            .refresh_list(refresh("spamhaus-drop"))
            .await
            .unwrap();
        let before = blocked(&rig.firewall, "spamhaus-drop");
        assert!(!before.is_empty());
        rig.broken.store(true, Ordering::SeqCst);
        let view = rig
            .service
            .refresh_list(refresh("spamhaus-drop"))
            .await
            .unwrap();
        let list = view.lists.iter().find(|l| l.id == "spamhaus-drop").unwrap();
        assert!(list.last_error.is_some(), "{list:?}");
        assert_eq!(blocked(&rig.firewall, "spamhaus-drop"), before);
    }

    #[tokio::test]
    async fn disabling_a_list_removes_its_rules() {
        let rig = rig_in(None);
        rig.service
            .set_list_enabled(enable("spamhaus-drop"))
            .await
            .unwrap();
        rig.service
            .refresh_list(refresh("spamhaus-drop"))
            .await
            .unwrap();
        assert!(!blocked(&rig.firewall, "spamhaus-drop").is_empty());
        rig.service
            .set_list_enabled(ListEnableRequest {
                id: "spamhaus-drop".to_owned(),
                enabled: false,
            })
            .await
            .unwrap();
        assert!(blocked(&rig.firewall, "spamhaus-drop").is_empty());
    }

    #[tokio::test]
    async fn lists_survive_a_restart_and_keep_working_offline() {
        let dir = tempfile::tempdir().unwrap();
        {
            let rig = rig_in(Some(dir.path().to_path_buf()));
            rig.service
                .set_list_enabled(enable("spamhaus-drop"))
                .await
                .unwrap();
            rig.service
                .refresh_list(refresh("spamhaus-drop"))
                .await
                .unwrap();
        }
        // A new agent with no network at all: the cached list is still in force.
        let (firewall, defense) = new_defense();
        let offline = IntelService::new(
            OfflineFetcher,
            Arc::new(MemorySecretStore::new()),
            Some(dir.path().to_path_buf()),
            defense,
        );
        let view = offline.lists();
        let list = view.lists.iter().find(|l| l.id == "spamhaus-drop").unwrap();
        assert!(list.enabled && list.entries >= 2, "{list:?}");
        offline.tick().await.unwrap();
        assert!(!blocked(&firewall, "spamhaus-drop").is_empty());
    }

    #[tokio::test]
    async fn geo_lookups_are_local_and_reserved_addresses_are_flagged() {
        let rig = rig_in(None);
        let result = rig
            .service
            .lookup(&GeoLookupRequest {
                addrs: vec![
                    "10.0.0.5".into(),
                    "8.8.8.8".into(),
                    "not an ip".into(),
                    "::ffff:192.168.1.1".into(),
                ],
            })
            .unwrap();
        assert!(result.entries[0].reserved);
        assert!(!result.entries[1].reserved && result.entries[1].country_code.is_none());
        assert!(!result.entries[2].reserved);
        assert!(result.entries[3].reserved, "mapped private address");
        let status = rig.service.geo_status();
        assert_eq!(status.state, "missing");
        assert!(status.attribution.contains("DB-IP"));
        assert!(rig.service.lookup_one("8.8.8.8".parse().unwrap()).is_none());
        let too_many = GeoLookupRequest {
            addrs: vec!["8.8.8.8".to_owned(); MAX_LOOKUP + 1],
        };
        assert!(rig.service.lookup(&too_many).is_err());
    }

    #[tokio::test]
    async fn the_abuseipdb_key_is_optional_and_private_addresses_never_leave() {
        let rig = rig_in(None);
        assert!(!rig.service.abuse_status().configured);
        let err = rig
            .service
            .abuse_check(AbuseCheckRequest {
                addr: "8.8.8.8".into(),
            })
            .await
            .unwrap_err();
        assert!(err.message.contains("no AbuseIPDB key"), "{}", err.message);
        assert!(rig
            .service
            .set_abuse_key(AbuseKeyRequest {
                key: Some("x\u{0}y".into())
            })
            .is_err());
        let status = rig
            .service
            .set_abuse_key(AbuseKeyRequest {
                key: Some("a".repeat(80)),
            })
            .unwrap();
        assert!(status.configured);
        let private = rig
            .service
            .abuse_check(AbuseCheckRequest {
                addr: "192.168.0.1".into(),
            })
            .await
            .unwrap_err();
        assert!(
            private.message.contains("never sent"),
            "{}",
            private.message
        );
        assert!(
            !rig.service
                .set_abuse_key(AbuseKeyRequest { key: None })
                .unwrap()
                .configured
        );
    }
}

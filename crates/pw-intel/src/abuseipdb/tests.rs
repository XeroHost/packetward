// SPDX-License-Identifier: GPL-3.0-or-later
//! Client behaviour with a fake fetcher, fake clock and in-memory secret store: no network is ever touched.

use std::net::IpAddr;
use std::sync::Arc;

use super::*;
use crate::testing::{FakeFetcher, LogCapture, ManualClock};
use crate::{FetchResponse, HttpMethod, MemorySecretStore, Secret};

const T0: u64 = 1_800_000_000;
const KEY: &str = "SUPERSECRETKEY-0123456789abcdef";

struct Rig {
    client: AbuseIpdbClient<Arc<FakeFetcher>>,
    fetcher: Arc<FakeFetcher>,
    secrets: Arc<MemorySecretStore>,
    cache: Arc<MemoryAbuseCache>,
    clock: ManualClock,
}

fn rig(with_key: bool) -> Rig {
    let fetcher = Arc::new(FakeFetcher::new());
    let secrets = Arc::new(MemorySecretStore::new());
    if with_key {
        secrets.set(ABUSEIPDB_KEY_NAME, &Secret::new(KEY)).unwrap();
    }
    let cache = Arc::new(MemoryAbuseCache::new());
    let clock = ManualClock::new(T0);
    let client = AbuseIpdbClient::new(
        Arc::clone(&fetcher),
        secrets.clone(),
        cache.clone(),
        Arc::new(clock.clone()),
        AbuseConfig::default(),
    );
    Rig {
        client,
        fetcher,
        secrets,
        cache,
        clock,
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn body(score: u64) -> String {
    format!(
        r#"{{"data":{{"ipAddress":"8.8.8.8","isPublic":true,"ipVersion":4,"isWhitelisted":false,
        "abuseConfidenceScore":{score},"countryCode":"US","usageType":"Data Center/Web Hosting/Transit",
        "isp":"Google LLC","domain":"google.com","hostnames":["dns.google"],"isTor":false,
        "totalReports":12,"numDistinctUsers":5,"lastReportedAt":"2026-11-18T10:00:00+00:00"}}}}"#
    )
}

fn ok(score: u64) -> Result<FetchResponse, FetchError> {
    Ok(FetchResponse::ok(body(score)))
}

fn rate_limited(retry_after: Option<&str>) -> Result<FetchResponse, FetchError> {
    let mut response = FetchResponse::ok("{}").with_status(429);
    if let Some(value) = retry_after {
        response = response.with_header("Retry-After", value);
    }
    Ok(response)
}

#[tokio::test]
async fn not_configured_means_no_requests_and_a_clear_state() {
    let rig = rig(false);
    assert_eq!(rig.client.state().unwrap(), AbuseState::NotConfigured);
    assert!(matches!(
        rig.client.check(ip("8.8.8.8")).await,
        Err(AbuseError::NotConfigured)
    ));
    // A blank key counts as not configured.
    rig.secrets
        .set(ABUSEIPDB_KEY_NAME, &Secret::new("   "))
        .unwrap();
    assert_eq!(rig.client.state().unwrap(), AbuseState::NotConfigured);
    assert_eq!(rig.fetcher.request_count(), 0);
    // Storing a key flips the state with no restart.
    rig.secrets
        .set(ABUSEIPDB_KEY_NAME, &Secret::new(KEY))
        .unwrap();
    assert_eq!(rig.client.state().unwrap(), AbuseState::Ready);
}

#[tokio::test]
async fn private_and_reserved_addresses_are_never_sent_anywhere() {
    let rig = rig(true);
    rig.fetcher.push(ok(1));
    for text in [
        "10.0.0.1",
        "192.168.1.10",
        "172.16.5.5",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.9",
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.251",
        "192.0.2.1",
        "::1",
        "fe80::1",
        "fd12:3456::1",
        "ff02::1",
        "2001:db8::5",
        "::ffff:10.1.2.3",
    ] {
        assert!(
            matches!(rig.client.check(ip(text)).await, Err(AbuseError::NotPublic)),
            "{text}"
        );
        let report = ManualReport {
            ip: ip(text),
            categories: vec![18],
            comment: "ssh brute force".to_owned(),
        };
        assert!(
            matches!(rig.client.report(&report).await, Err(AbuseError::NotPublic)),
            "report {text}"
        );
    }
    assert_eq!(rig.fetcher.request_count(), 0, "nothing left the machine");
    assert!(rig.cache.is_empty());
}

#[tokio::test]
async fn a_check_sends_the_key_only_in_the_header_and_maps_the_answer() {
    let rig = rig(true);
    rig.fetcher.push(ok(87).map(|r| {
        r.with_header("X-RateLimit-Limit", "1000")
            .with_header("X-RateLimit-Remaining", "999")
    }));
    let check = rig.client.check(ip("8.8.8.8")).await.unwrap();
    assert!(!check.from_cache);
    assert_eq!(check.fetched_at, T0);
    let report = &check.report;
    assert_eq!(report.abuse_confidence_score, 87);
    assert_eq!(report.country_code.as_deref(), Some("US"));
    assert_eq!(report.isp.as_deref(), Some("Google LLC"));
    assert_eq!(report.total_reports, 12);
    assert_eq!(report.num_distinct_users, 5);
    assert_eq!(report.is_tor, Some(false));
    assert_eq!(report.ip, Some(ip("8.8.8.8")));
    assert_eq!(
        rig.client.rate_limit(),
        RateLimitInfo {
            limit: Some(1000),
            remaining: Some(999)
        }
    );

    let request = &rig.fetcher.requests()[0];
    assert_eq!(request.method, HttpMethod::Get);
    assert_eq!(
        request.url,
        "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90"
    );
    assert!(
        !request.url.contains(KEY),
        "the key is never part of the URL"
    );
    assert_eq!(request.header_value("Key"), Some(KEY));
    assert_eq!(request.header_value("Accept"), Some("application/json"));
    assert!(request.url.starts_with("https://"));
}

#[tokio::test]
async fn results_are_cached_for_24_hours() {
    let rig = rig(true);
    rig.fetcher.push(ok(10));
    rig.fetcher.push(ok(20));
    rig.fetcher.push(ok(30));

    let first = rig.client.check(ip("8.8.8.8")).await.unwrap();
    assert_eq!(first.report.abuse_confidence_score, 10);

    rig.clock.advance(DEFAULT_CACHE_TTL_SECS - 1);
    let second = rig.client.check(ip("8.8.8.8")).await.unwrap();
    assert!(second.from_cache);
    assert_eq!(second.report.abuse_confidence_score, 10);
    assert_eq!(second.fetched_at, T0);
    assert_eq!(rig.fetcher.request_count(), 1);

    rig.clock.advance(1);
    let third = rig.client.check(ip("8.8.8.8")).await.unwrap();
    assert!(!third.from_cache);
    assert_eq!(third.report.abuse_confidence_score, 20);
    assert_eq!(rig.fetcher.request_count(), 2);

    // The mapped form of the same address shares the cache entry.
    let mapped = rig.client.check(ip("::ffff:8.8.8.8")).await.unwrap();
    assert!(mapped.from_cache);
    assert_eq!(rig.fetcher.request_count(), 2);

    // A clock that went backwards never serves a "future" entry as fresh.
    rig.clock.set(T0 - 1_000);
    assert!(!rig.client.check(ip("8.8.8.8")).await.unwrap().from_cache);
    assert_eq!(rig.fetcher.request_count(), 3);
}

#[tokio::test]
async fn a_custom_ttl_is_honoured() {
    let mut rig = rig(true);
    rig.client = AbuseIpdbClient::new(
        Arc::clone(&rig.fetcher),
        rig.secrets.clone(),
        rig.cache.clone(),
        Arc::new(rig.clock.clone()),
        AbuseConfig {
            cache_ttl_secs: 60,
            max_age_days: 30,
        },
    );
    rig.fetcher.push(ok(1));
    rig.fetcher.push(ok(2));
    rig.client.check(ip("8.8.8.8")).await.unwrap();
    assert!(rig.fetcher.requests()[0].url.ends_with("maxAgeInDays=30"));
    rig.clock.advance(61);
    assert!(!rig.client.check(ip("8.8.8.8")).await.unwrap().from_cache);
}

#[tokio::test]
async fn a_429_pauses_the_client_without_any_request_until_retry_after() {
    let rig = rig(true);
    rig.fetcher.push(rate_limited(Some("120")));
    rig.fetcher.push(ok(5));

    let error = rig.client.check(ip("8.8.8.8")).await.unwrap_err();
    assert!(matches!(error, AbuseError::RateLimited { until } if until == T0 + 120));
    assert_eq!(
        rig.client.state().unwrap(),
        AbuseState::RateLimited { until: T0 + 120 }
    );

    // While paused: no network, even for other addresses.
    rig.clock.advance(119);
    for target in ["8.8.8.8", "1.1.1.1"] {
        assert!(matches!(
            rig.client.check(ip(target)).await,
            Err(AbuseError::RateLimited { .. })
        ));
    }
    assert_eq!(rig.fetcher.request_count(), 1);

    // Deadline reached: lookups resume.
    rig.clock.advance(1);
    assert_eq!(rig.client.state().unwrap(), AbuseState::Ready);
    let check = rig.client.check(ip("8.8.8.8")).await.unwrap();
    assert_eq!(check.report.abuse_confidence_score, 5);
    assert_eq!(rig.fetcher.request_count(), 2);
}

#[tokio::test]
async fn cached_answers_are_still_served_while_rate_limited() {
    let rig = rig(true);
    rig.fetcher.push(ok(42));
    rig.fetcher.push(rate_limited(Some("600")));
    rig.client.check(ip("8.8.8.8")).await.unwrap();
    assert!(rig.client.check(ip("1.1.1.1")).await.is_err());
    let cached = rig.client.check(ip("8.8.8.8")).await.unwrap();
    assert!(cached.from_cache);
    assert_eq!(cached.report.abuse_confidence_score, 42);
}

#[tokio::test]
async fn repeated_429_without_a_header_backs_off_exponentially_and_success_resets() {
    let rig = rig(true);
    for _ in 0..3 {
        rig.fetcher.push(rate_limited(None));
    }
    rig.fetcher.push(ok(1));
    rig.fetcher.push(rate_limited(None));

    let mut waits = Vec::new();
    for _ in 0..3 {
        let AbuseError::RateLimited { until } = rig.client.check(ip("8.8.8.8")).await.unwrap_err()
        else {
            panic!("expected a rate limit");
        };
        waits.push(until - rig.clock.now());
        rig.clock.set(until);
    }
    assert_eq!(waits, [60, 120, 240]);

    // A success resets the streak: the next 429 starts again at the base delay.
    rig.client.check(ip("8.8.8.8")).await.unwrap();
    rig.clock.advance(DEFAULT_CACHE_TTL_SECS);
    let AbuseError::RateLimited { until } = rig.client.check(ip("8.8.8.8")).await.unwrap_err()
    else {
        panic!("expected a rate limit");
    };
    assert_eq!(until - rig.clock.now(), 60);
}

#[tokio::test]
async fn the_backoff_is_capped_and_a_huge_retry_after_is_bounded() {
    assert_eq!(backoff_secs(1), 60);
    assert_eq!(backoff_secs(7), 3_600);
    assert_eq!(backoff_secs(500), 3_600);
    let rig = rig(true);
    rig.fetcher.push(rate_limited(Some("99999999999")));
    let AbuseError::RateLimited { until } = rig.client.check(ip("8.8.8.8")).await.unwrap_err()
    else {
        panic!("expected a rate limit");
    };
    assert_eq!(until, T0 + MAX_WAIT_SECS);
}

#[tokio::test]
async fn an_exhausted_quota_pauses_until_the_reset() {
    // Epoch-style reset header.
    let rig_a = rig(true);
    rig_a.fetcher.push(ok(1).map(|r| {
        r.with_header("X-RateLimit-Remaining", "0")
            .with_header("X-RateLimit-Reset", &(T0 + 500).to_string())
    }));
    rig_a.client.check(ip("8.8.8.8")).await.unwrap();
    assert_eq!(
        rig_a.client.state().unwrap(),
        AbuseState::RateLimited { until: T0 + 500 }
    );
    assert!(matches!(
        rig_a.client.check(ip("1.1.1.1")).await,
        Err(AbuseError::RateLimited { .. })
    ));
    assert_eq!(rig_a.fetcher.request_count(), 1);

    // Delay-style reset header.
    let rig_b = rig(true);
    rig_b.fetcher.push(ok(1).map(|r| {
        r.with_header("X-RateLimit-Remaining", "0")
            .with_header("X-RateLimit-Reset", "90")
    }));
    rig_b.client.check(ip("8.8.8.8")).await.unwrap();
    assert_eq!(
        rig_b.client.state().unwrap(),
        AbuseState::RateLimited { until: T0 + 90 }
    );

    // No reset header: the daily quota resets at the next UTC midnight.
    let rig_c = rig(true);
    rig_c
        .fetcher
        .push(ok(1).map(|r| r.with_header("X-RateLimit-Remaining", "0")));
    rig_c.client.check(ip("8.8.8.8")).await.unwrap();
    let midnight = T0 - T0 % 86_400 + 86_400;
    assert_eq!(
        rig_c.client.state().unwrap(),
        AbuseState::RateLimited { until: midnight }
    );
    rig_c.clock.set(midnight);
    assert_eq!(rig_c.client.state().unwrap(), AbuseState::Ready);
}

#[tokio::test]
async fn other_failures_do_not_pause_the_client() {
    let rig = rig(true);
    let cases: Vec<(Result<FetchResponse, FetchError>, &str)> = vec![
        (Ok(FetchResponse::ok("{}").with_status(401)), "invalid key"),
        (Ok(FetchResponse::ok("{}").with_status(403)), "invalid key"),
        (Ok(FetchResponse::ok("{}").with_status(422)), "rejected"),
        (Ok(FetchResponse::ok("{}").with_status(503)), "server"),
        (Ok(FetchResponse::ok("<html>")), "bad response"),
        (Ok(FetchResponse::ok(r#"{"data":"nope"}"#)), "bad response"),
        (Err(FetchError::Timeout), "timeout"),
        (Err(FetchError::Network("reset".into())), "network"),
    ];
    for (response, label) in cases {
        rig.fetcher.push(response);
        let error = rig.client.check(ip("8.8.8.8")).await.unwrap_err();
        match (label, &error) {
            ("invalid key", AbuseError::InvalidKey)
            | ("rejected", AbuseError::Rejected(422))
            | ("server", AbuseError::Server(503))
            | ("bad response", AbuseError::BadResponse(_))
            | ("timeout" | "network", AbuseError::Fetch(_)) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(rig.client.state().unwrap(), AbuseState::Ready, "{label}");
    }
    assert!(rig.cache.is_empty(), "failures are never cached");
}

#[tokio::test]
async fn out_of_range_numbers_are_clamped() {
    let rig = rig(true);
    rig.fetcher.push(ok(150));
    let check = rig.client.check(ip("8.8.8.8")).await.unwrap();
    assert_eq!(check.report.abuse_confidence_score, 100);
}

#[tokio::test]
async fn a_manual_report_is_a_post_with_an_encoded_form_body() {
    let rig = rig(true);
    rig.fetcher.push(ok(10));
    rig.client.check(ip("45.33.32.156")).await.unwrap();
    assert_eq!(rig.cache.len(), 1);

    rig.fetcher.push(Ok(FetchResponse::ok(
        r#"{"data":{"ipAddress":"45.33.32.156","abuseConfidenceScore":55}}"#,
    )));
    let ack = rig
        .client
        .report(&ManualReport {
            ip: ip("45.33.32.156"),
            categories: vec![18, 22],
            comment: "RDP brute force & scans, 100% sure".to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(ack.abuse_confidence_score, 55);
    assert!(rig.cache.is_empty(), "the stale cached result is dropped");

    let request = &rig.fetcher.requests()[1];
    assert_eq!(request.method, HttpMethod::Post);
    assert_eq!(request.url, REPORT_URL);
    assert_eq!(request.header_value("Key"), Some(KEY));
    assert_eq!(
        request.header_value("Content-Type"),
        Some("application/x-www-form-urlencoded")
    );
    let form = String::from_utf8(request.body.clone().unwrap()).unwrap();
    assert_eq!(
        form,
        "ip=45.33.32.156&categories=18%2C22&comment=RDP%20brute%20force%20%26%20scans%2C%20100%25%20sure"
    );
    assert!(!form.contains(KEY));
}

#[tokio::test]
async fn invalid_reports_are_refused_before_any_request() {
    let rig = rig(true);
    let base = ManualReport {
        ip: ip("45.33.32.156"),
        categories: vec![18],
        comment: String::new(),
    };
    for (label, report) in [
        (
            "no categories",
            ManualReport {
                categories: vec![],
                ..base.clone()
            },
        ),
        (
            "category 0",
            ManualReport {
                categories: vec![0],
                ..base.clone()
            },
        ),
        (
            "category 24",
            ManualReport {
                categories: vec![24],
                ..base.clone()
            },
        ),
        (
            "too many",
            ManualReport {
                categories: (1..=11).collect(),
                ..base.clone()
            },
        ),
        (
            "long comment",
            ManualReport {
                comment: "x".repeat(1025),
                ..base.clone()
            },
        ),
    ] {
        assert!(
            matches!(
                rig.client.report(&report).await,
                Err(AbuseError::InvalidReport(_))
            ),
            "{label}"
        );
    }
    assert_eq!(rig.fetcher.request_count(), 0);
    // Exactly at the limits is fine.
    rig.fetcher.push(Ok(FetchResponse::ok(
        r#"{"data":{"abuseConfidenceScore":1}}"#,
    )));
    let ok_report = ManualReport {
        categories: (1..=10).collect(),
        comment: "é".repeat(1024),
        ..base
    };
    assert!(rig.client.report(&ok_report).await.is_ok());
}

#[tokio::test]
async fn reporting_requires_a_key_and_respects_the_rate_limit() {
    let report = ManualReport {
        ip: ip("45.33.32.156"),
        categories: vec![18],
        comment: String::new(),
    };
    let rig_a = rig(false);
    assert!(matches!(
        rig_a.client.report(&report).await,
        Err(AbuseError::NotConfigured)
    ));
    assert_eq!(rig_a.fetcher.request_count(), 0);

    let rig_b = rig(true);
    rig_b.fetcher.push(rate_limited(Some("300")));
    assert!(matches!(
        rig_b.client.report(&report).await,
        Err(AbuseError::RateLimited { .. })
    ));
    assert!(matches!(
        rig_b.client.report(&report).await,
        Err(AbuseError::RateLimited { .. })
    ));
    assert_eq!(rig_b.fetcher.request_count(), 1);
}

#[tokio::test]
async fn checks_never_report() {
    // `report` is a separate, explicit entry point: a pile of lookups, failures and rate limits never POSTs.
    let rig = rig(true);
    rig.fetcher.push(ok(99));
    rig.fetcher.push(rate_limited(Some("1")));
    rig.fetcher
        .push(Ok(FetchResponse::ok("{}").with_status(500)));
    for target in ["8.8.8.8", "1.1.1.1", "8.8.8.8", "9.9.9.9"] {
        let _ = rig.client.check(ip(target)).await;
        rig.clock.advance(5);
    }
    assert!(rig
        .fetcher
        .requests()
        .iter()
        .all(|r| r.method == HttpMethod::Get && !r.url.contains("/report")));
}

#[test]
fn form_encoding() {
    assert_eq!(form_encode("a-b_c.d~E9"), "a-b_c.d~E9");
    assert_eq!(form_encode("a b&c=d"), "a%20b%26c%3Dd");
    assert_eq!(form_encode("é"), "%C3%A9");
    assert_eq!(form_encode(""), "");
}

#[tokio::test(flavor = "current_thread")]
async fn the_api_key_never_appears_in_logs_errors_or_debug_output() {
    let (capture, _guard) = LogCapture::install();
    let rig = rig(true);
    rig.fetcher.push(ok(10));
    rig.fetcher
        .push(Ok(FetchResponse::ok("{}").with_status(401)));
    rig.fetcher.push(rate_limited(Some("30")));
    rig.fetcher
        .push(Ok(FetchResponse::ok("{}").with_status(500)));
    rig.fetcher.push(Ok(FetchResponse::ok("{}")
        .with_status(429)
        .with_header("X-RateLimit-Remaining", "0")));

    let mut rendered = String::new();
    let targets = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "4.4.4.4"];
    for target in targets {
        match rig.client.check(ip(target)).await {
            Ok(check) => rendered.push_str(&format!("{check:?}")),
            Err(error) => rendered.push_str(&format!("{error} {error:?}")),
        }
        rig.clock.advance(31);
    }
    let _ = rig
        .client
        .report(&ManualReport {
            ip: ip("45.33.32.156"),
            categories: vec![18],
            comment: String::new(),
        })
        .await;
    rendered.push_str(&format!("{:?} {:?}", rig.client, rig.secrets));
    rendered.push_str(&format!("{:?}", rig.fetcher.requests()));
    rendered.push_str(&format!(
        "{:?}",
        rig.secrets.get(ABUSEIPDB_KEY_NAME).unwrap()
    ));

    assert!(
        !rendered.contains(KEY),
        "key leaked into Debug/Display output"
    );
    let logs = capture.contents();
    assert!(
        logs.contains("AbuseIPDB"),
        "the test must actually have captured something: {logs:?}"
    );
    assert!(!logs.contains(KEY), "key leaked into the logs: {logs}");
    assert!(!logs.contains("SUPERSECRET"));
}

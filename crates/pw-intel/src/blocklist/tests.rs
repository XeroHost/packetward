// SPDX-License-Identifier: GPL-3.0-or-later
//! Manager-level tests: signed list end to end, fail-closed behaviour, keep-last-good, scheduling.

use std::net::IpAddr;
use std::sync::Arc;

use pw_core::CidrSet;

use super::verify::test_keys::TestKey;
use super::*;
use crate::testing::{FakeFetcher, ManualClock};
use crate::{FetchError, FetchResponse};

const T0: u64 = 1_800_000_000;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn manager(verifier: Verifier) -> (BlocklistManager, ManualClock) {
    let clock = ManualClock::new(T0);
    let manager = BlocklistManager::new(builtin_sources(), verifier, Arc::new(clock.clone()));
    (manager, clock)
}

fn signed_fetcher(key: &TestKey, content: &str) -> FakeFetcher {
    let fetcher = FakeFetcher::new();
    let signature = key.sign(content.as_bytes());
    let body = content.to_owned();
    fetcher.route("/blocklist.txt.minisig", move |_| {
        Ok(FetchResponse::ok(signature.clone()))
    });
    fetcher.route("/blocklist.txt", move |_| {
        Ok(FetchResponse::ok(body.clone()))
    });
    fetcher
}

fn contains(snapshot: &ListSnapshot, addr: &str) -> bool {
    snapshot
        .effective_blocks
        .iter()
        .any(|b| b.contains(ip(addr)))
}

#[test]
fn builtin_sources_are_well_formed_and_disabled() {
    let sources = builtin_sources();
    assert_eq!(sources.len(), 3);
    for source in &sources {
        assert!(!source.default_enabled, "{}", source.id);
        assert!(
            source
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "{} must be safe in a firewall rule name",
            source.id
        );
        assert!(source.urls.iter().all(|u| u.starts_with("https://")));
        assert_eq!(source.is_signed(), source.signature_url.is_some());
        assert!(source.default_refresh_secs >= MIN_REFRESH_SECS);
    }
    let xerohost = sources.iter().find(|s| s.id == XEROHOST_LIST_ID).unwrap();
    assert!(xerohost.is_signed());
    assert!(xerohost.urls[0].contains(XEROHOST_REPO));
    assert!(xerohost
        .signature_url
        .unwrap()
        .ends_with("blocklist.txt.minisig"));
}

#[tokio::test]
async fn xerohost_list_fails_closed_without_a_pinned_key() {
    let (mut manager, _clock) = manager(Verifier::without_key());
    let error = manager.set_enabled(XEROHOST_LIST_ID, true).unwrap_err();
    assert_eq!(error, BlocklistError::Verify(VerifyError::NoPinnedKey));
    assert!(error.to_string().contains("no pinned key configured"));
    let status = manager.status(XEROHOST_LIST_ID).unwrap();
    assert!(!status.enabled);
    assert!(status
        .unavailable
        .unwrap()
        .contains("no pinned key configured"));

    // A saved "enabled" flag from an older config cannot switch it on either.
    manager
        .restore(
            XEROHOST_LIST_ID,
            ListConfig {
                enabled: true,
                refresh_interval_secs: 3600,
            },
            ScheduleState::default(),
            None,
        )
        .unwrap();
    assert!(!manager.status(XEROHOST_LIST_ID).unwrap().enabled);

    // No refresh is possible and nothing is ever downloaded.
    let fetcher = FakeFetcher::new();
    let refused = manager
        .refresh(XEROHOST_LIST_ID, &fetcher, &CidrSet::new())
        .await;
    assert_eq!(refused.unwrap_err(), BlocklistError::Disabled);
    let source = manager.source(XEROHOST_LIST_ID).unwrap().clone();
    let direct = download(&fetcher, &source, &Verifier::without_key(), MAX_LIST_BYTES).await;
    assert_eq!(
        direct.unwrap_err(),
        BlocklistError::Verify(VerifyError::NoPinnedKey)
    );
    assert_eq!(
        fetcher.request_count(),
        0,
        "no network traffic without a key"
    );
    assert!(manager.due().is_empty());
}

#[tokio::test]
async fn public_lists_do_not_need_a_key() {
    let (mut manager, _clock) = manager(Verifier::without_key());
    manager.set_enabled("firehol-level1", true).unwrap();
    assert!(manager
        .status("firehol-level1")
        .unwrap()
        .unavailable
        .is_none());
}

#[tokio::test]
async fn a_signed_list_is_downloaded_verified_and_sanitised() {
    let key = TestKey::generate();
    let (mut manager, _clock) = manager(Verifier::with_key(key.public_base64()));
    manager.set_enabled(XEROHOST_LIST_ID, true).unwrap();
    let content =
        "# XeroHost list\n45.33.32.0/24\n45.33.33.0/24\n10.0.0.0/8\n203.1.0.0/16\n198.1.2.9\n";
    let fetcher = signed_fetcher(&key, content);
    let mut protected = CidrSet::new();
    protected.insert_str("198.1.2.9").unwrap();
    protected.insert_str("203.1.77.0/24").unwrap();

    let snapshot = manager
        .refresh(XEROHOST_LIST_ID, &fetcher, &protected)
        .await
        .unwrap();
    assert!(contains(&snapshot, "45.33.32.1"));
    assert!(contains(&snapshot, "45.33.33.200"));
    assert!(!contains(&snapshot, "10.1.1.1"), "private space dropped");
    assert!(
        !contains(&snapshot, "198.1.2.9"),
        "protected host never listed"
    );
    assert!(
        !contains(&snapshot, "203.1.77.5"),
        "protected block carved out"
    );
    assert!(contains(&snapshot, "203.1.78.5"));
    // The two /24s aggregated into a /23.
    assert!(snapshot
        .public_blocks
        .iter()
        .any(|b| b.to_string() == "45.33.32.0/23"));

    let status = manager.status(XEROHOST_LIST_ID).unwrap();
    assert_eq!(status.last_success, Some(T0));
    assert!(status.last_error.is_none());
    assert_eq!(status.entries, snapshot.public_blocks.len());
    assert_eq!(fetcher.request_count(), 2); // list + signature

    // A protected address learned later is carved out without downloading again.
    let mut later = protected.clone();
    later.insert_str("45.33.32.77").unwrap();
    let active = manager.active_blocks(&later);
    assert_eq!(active.len(), 1);
    assert!(!active[0].1.iter().any(|b| b.contains(ip("45.33.32.77"))));
    assert!(active[0].1.iter().any(|b| b.contains(ip("45.33.32.78"))));
    assert_eq!(fetcher.request_count(), 2);
}

#[tokio::test]
async fn a_signed_list_may_be_empty_but_a_public_one_may_not() {
    let key = TestKey::generate();
    let (mut manager, _clock) = manager(Verifier::with_key(key.public_base64()));
    manager.set_enabled(XEROHOST_LIST_ID, true).unwrap();
    let fetcher = signed_fetcher(&key, "# nothing to block today\n");
    let snapshot = manager
        .refresh(XEROHOST_LIST_ID, &fetcher, &CidrSet::new())
        .await
        .unwrap();
    assert!(snapshot.public_blocks.is_empty());

    manager.set_enabled("firehol-level1", true).unwrap();
    let public = FakeFetcher::new();
    public.push(Ok(FetchResponse::ok("# empty\n")));
    let error = manager
        .refresh("firehol-level1", &public, &CidrSet::new())
        .await
        .unwrap_err();
    assert_eq!(error, BlocklistError::Parse(ParseError::Empty));
}

#[tokio::test]
async fn tampered_wrong_key_and_missing_signature_are_rejected_and_the_good_list_is_kept() {
    let key = TestKey::generate();
    let (mut manager, clock) = manager(Verifier::with_key(key.public_base64()));
    manager.set_enabled(XEROHOST_LIST_ID, true).unwrap();
    let good = "45.33.32.0/24\n";
    let first = manager
        .refresh(
            XEROHOST_LIST_ID,
            &signed_fetcher(&key, good),
            &CidrSet::new(),
        )
        .await
        .unwrap();
    assert_eq!(first.public_blocks.len(), 1);

    // 1. Content altered after signing.
    clock.advance(10);
    let fetcher = FakeFetcher::new();
    let signature = key.sign(good.as_bytes());
    fetcher.route("/blocklist.txt.minisig", move |_| {
        Ok(FetchResponse::ok(signature.clone()))
    });
    fetcher.route("/blocklist.txt", |_| {
        Ok(FetchResponse::ok("45.33.32.0/24\n0.0.0.0/1\n1.2.3.4\n"))
    });
    let error = manager
        .refresh(XEROHOST_LIST_ID, &fetcher, &CidrSet::new())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        BlocklistError::Verify(VerifyError::SignatureMismatch)
    );

    // 2. Signed by somebody else.
    let attacker = TestKey::generate();
    let error = manager
        .refresh(
            XEROHOST_LIST_ID,
            &signed_fetcher(&attacker, "6.6.6.0/24\n"),
            &CidrSet::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error, BlocklistError::Verify(VerifyError::WrongKey));

    // 3. Signature file missing (404) and empty (200).
    let fetcher = FakeFetcher::new();
    fetcher.route("/blocklist.txt.minisig", |_| {
        Ok(FetchResponse::ok("").with_status(404))
    });
    fetcher.route("/blocklist.txt", |_| Ok(FetchResponse::ok("6.6.6.0/24\n")));
    let error = manager
        .refresh(XEROHOST_LIST_ID, &fetcher, &CidrSet::new())
        .await
        .unwrap_err();
    assert_eq!(error, BlocklistError::Verify(VerifyError::MissingSignature));
    let fetcher = FakeFetcher::new();
    fetcher.route("/blocklist.txt.minisig", |_| Ok(FetchResponse::ok("")));
    fetcher.route("/blocklist.txt", |_| Ok(FetchResponse::ok("6.6.6.0/24\n")));
    let error = manager
        .refresh(XEROHOST_LIST_ID, &fetcher, &CidrSet::new())
        .await
        .unwrap_err();
    assert_eq!(error, BlocklistError::Verify(VerifyError::MissingSignature));

    // Through all of that the last good snapshot is still the active list, untouched.
    let kept = manager.snapshot(XEROHOST_LIST_ID).unwrap();
    assert_eq!(kept.public_blocks, first.public_blocks);
    assert_eq!(
        manager.active_blocks(&CidrSet::new())[0].1,
        first.public_blocks
    );
    let status = manager.status(XEROHOST_LIST_ID).unwrap();
    assert_eq!(status.consecutive_failures, 4);
    assert_eq!(status.last_success, Some(T0));
    assert!(status.last_error.is_some());
}

#[tokio::test]
async fn failures_keep_the_last_good_list_and_back_off() {
    let (mut manager, clock) = manager(Verifier::without_key());
    manager.set_enabled("spamhaus-drop", true).unwrap();
    assert_eq!(manager.due(), ["spamhaus-drop"]);

    let ok = FakeFetcher::new();
    ok.route("drop.txt", |_| {
        Ok(FetchResponse::ok("; Spamhaus\n1.10.16.0/20 ; SBL256894\n"))
    });
    ok.route("dropv6.txt", |_| {
        Ok(FetchResponse::ok("; v6\n2a00:1234::/32 ; SBL1\n"))
    });
    let snapshot = manager
        .refresh("spamhaus-drop", &ok, &CidrSet::new())
        .await
        .unwrap();
    assert_eq!(snapshot.public_blocks.len(), 2, "both files are merged");
    assert!(manager.due().is_empty());

    // Not due again until the interval passes.
    let interval = manager
        .status("spamhaus-drop")
        .unwrap()
        .refresh_interval_secs;
    clock.advance(interval - 1);
    assert!(manager.due().is_empty());
    clock.advance(1);
    assert_eq!(manager.due(), ["spamhaus-drop"]);

    // Server error, timeout, garbage page, oversized body: each fails and keeps the old list.
    let attempts: Vec<Result<FetchResponse, FetchError>> = vec![
        Ok(FetchResponse::ok("oops").with_status(503)),
        Err(FetchError::Timeout),
        Ok(FetchResponse::ok(
            "<html>\n<body>\nblocked\n</body>\n</html>\n",
        )),
        Ok(FetchResponse::ok(vec![b'#'; MAX_LIST_BYTES + 1])),
    ];
    let mut expected_failures = 0;
    for attempt in attempts {
        let fetcher = FakeFetcher::new();
        let attempt = Arc::new(attempt);
        fetcher.route("spamhaus.org", move |_| (*attempt).clone());
        let result = manager
            .refresh("spamhaus-drop", &fetcher, &CidrSet::new())
            .await;
        assert!(result.is_err());
        expected_failures += 1;
        let status = manager.status("spamhaus-drop").unwrap();
        assert_eq!(status.consecutive_failures, expected_failures);
        assert_eq!(status.entries, 2, "last good list still in place");
        assert!(status.last_error.is_some());
        assert_eq!(manager.active_blocks(&CidrSet::new())[0].1.len(), 2);
    }
    // After the failures the retry is scheduled by the backoff, not the full interval.
    let status = manager.status("spamhaus-drop").unwrap();
    let retry_at = status.next_attempt.unwrap();
    assert!(retry_at < status.last_attempt.unwrap() + interval);
    assert!(manager.due().is_empty());
    clock.set(retry_at);
    assert_eq!(manager.due(), ["spamhaus-drop"]);

    // A success clears the error and the failure streak.
    let snapshot = manager
        .refresh("spamhaus-drop", &ok, &CidrSet::new())
        .await
        .unwrap();
    assert_eq!(snapshot.fetched_at, retry_at);
    let status = manager.status("spamhaus-drop").unwrap();
    assert_eq!(status.consecutive_failures, 0);
    assert!(status.last_error.is_none());
}

#[tokio::test]
async fn disabled_lists_are_not_applied_or_refreshed() {
    let (mut manager, _clock) = manager(Verifier::without_key());
    manager.set_enabled("firehol-level1", true).unwrap();
    let fetcher = FakeFetcher::new();
    // FireHOL level 1 really contains bogons: they must vanish.
    fetcher.push(Ok(FetchResponse::ok(
        "#\n# firehol_level1\n0.0.0.0/8\n10.0.0.0/8\n100.64.0.0/10\n127.0.0.0/8\n169.254.0.0/16\n172.16.0.0/12\n\
         192.168.0.0/16\n224.0.0.0/3\n185.220.0.0/16\n",
    )));
    let snapshot = manager
        .refresh("firehol-level1", &fetcher, &CidrSet::new())
        .await
        .unwrap();
    assert_eq!(
        snapshot
            .public_blocks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["185.220.0.0/16"]
    );
    assert_eq!(snapshot.report.reserved_dropped, 7);
    assert_eq!(snapshot.report.too_broad, 1);

    manager.set_enabled("firehol-level1", false).unwrap();
    assert!(manager.active_blocks(&CidrSet::new()).is_empty());
    assert!(manager.due().is_empty());
    let none = FakeFetcher::new();
    assert_eq!(
        manager
            .refresh("firehol-level1", &none, &CidrSet::new())
            .await
            .unwrap_err(),
        BlocklistError::Disabled
    );
    assert_eq!(none.request_count(), 0);
    assert!(matches!(
        manager.set_enabled("nope", true),
        Err(BlocklistError::UnknownList(_))
    ));
}

#[tokio::test]
async fn refresh_due_only_touches_enabled_due_lists() {
    let (mut manager, clock) = manager(Verifier::without_key());
    manager.set_enabled("firehol-level1", true).unwrap();
    let fetcher = FakeFetcher::new();
    fetcher.route("firehol", |_| Ok(FetchResponse::ok("185.220.0.0/16\n")));
    let results = manager.refresh_due(&fetcher, &CidrSet::new()).await;
    assert_eq!(results.len(), 1);
    assert!(results[0].1.is_ok());
    assert!(manager
        .refresh_due(&fetcher, &CidrSet::new())
        .await
        .is_empty());
    assert_eq!(fetcher.request_count(), 1);
    clock.advance(25 * 3600);
    assert_eq!(
        manager.refresh_due(&fetcher, &CidrSet::new()).await.len(),
        1
    );
    // Interval changes are clamped to the allowed range.
    manager.set_refresh_interval("firehol-level1", 5).unwrap();
    assert_eq!(
        manager
            .status("firehol-level1")
            .unwrap()
            .refresh_interval_secs,
        MIN_REFRESH_SECS
    );
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Live runs against a public host (1.1.1.1), a handful of packets each. Ignored by default and
//! gated by environment variables so nothing leaves the machine unless asked:
//!
//! ```text
//! PW_DIAG_LIVE=1 cargo test -p pw-diag --test live -- --ignored --nocapture live_icmp
//! PW_DIAG_LIVE_CAPTURE=1 cargo test -p pw-diag --test live -- --ignored --nocapture live_udp_tcp
//! ```
//!
//! The second one needs administrator rights (raw-socket capture backend) or Npcap and prints what
//! it saw instead of asserting: whether inbound replies are visible depends on the machine.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use pw_capture::{CaptureBackend, RawSocketBackend};
use pw_diag::mtr_adv::export::{support_report, to_csv};
use pw_diag::mtr_adv::{
    mtr_with, AdvMtrOptions, AdvMtrSnapshot, EnrichCache, MtrError, NoEnrich, ProbeMode,
    SystemProbeTransport,
};
use pw_diag::{CancelToken, NameCache, NullSink, ReportContext};

fn enabled(var: &str) -> bool {
    std::env::var(var).is_ok_and(|v| v == "1")
}

async fn trace(
    transport: SystemProbeTransport,
    options: AdvMtrOptions,
) -> Result<AdvMtrSnapshot, MtrError> {
    let target: IpAddr = "1.1.1.1".parse().unwrap();
    mtr_with(
        Arc::new(transport),
        target,
        &options,
        &NameCache::disabled(),
        &EnrichCache::new(NoEnrich),
        &CancelToken::new(),
        &mut NullSink,
    )
    .await
}

fn print(snapshot: &AdvMtrSnapshot) {
    let ctx = ReportContext {
        source_public_ip: None,
        generated_at: SystemTime::now(),
        target: "1.1.1.1".to_owned(),
    };
    println!("{}", support_report(snapshot, &ctx));
    println!("{}", to_csv(snapshot));
}

#[tokio::test]
#[ignore = "sends ICMP towards the internet; set PW_DIAG_LIVE=1"]
async fn live_icmp() {
    if !enabled("PW_DIAG_LIVE") {
        eprintln!("PW_DIAG_LIVE=1 not set, skipping");
        return;
    }
    let options = AdvMtrOptions {
        mode: ProbeMode::Icmp,
        cycles: 5,
        max_hops: 20,
        ..AdvMtrOptions::default()
    };
    let snapshot = trace(SystemProbeTransport::new(None), options)
        .await
        .unwrap();
    print(&snapshot);
    assert_eq!(snapshot.cycle, 5);
    assert!(
        snapshot.destination_reached,
        "1.1.1.1 should answer ICMP echo"
    );
}

#[tokio::test]
#[ignore = "sends UDP / TCP probes towards the internet and opens a raw capture; set PW_DIAG_LIVE_CAPTURE=1"]
async fn live_udp_tcp() {
    if !enabled("PW_DIAG_LIVE_CAPTURE") {
        eprintln!("PW_DIAG_LIVE_CAPTURE=1 not set, skipping");
        return;
    }
    let backend: Arc<dyn CaptureBackend> = Arc::new(RawSocketBackend::new());
    for mode in [ProbeMode::Udp, ProbeMode::TcpSyn { port: 443 }] {
        let transport = SystemProbeTransport::new(Some(Arc::clone(&backend)));
        let options = AdvMtrOptions {
            mode,
            cycles: 2,
            max_hops: 10,
            ..AdvMtrOptions::default()
        };
        match trace(transport, options).await {
            Ok(snapshot) => print(&snapshot),
            Err(MtrError::ModeUnavailable(m)) => println!("{m}"),
            Err(e) => println!("{mode}: failed: {e}"),
        }
    }
}

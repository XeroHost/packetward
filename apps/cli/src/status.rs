// SPDX-License-Identifier: GPL-3.0-or-later
//! `pwctl status`.
//!
//! Exit codes (stable, for scripts): 0 reachable · 1 other failure · 2 agent not running ·
//! 3 access denied · 4 version mismatch.

use std::io;
use std::process::ExitCode;

use pw_ipc::access::{self, AccessProblem};
use pw_ipc::pipe::{self, OPERATORS_GROUP, PIPE_NAME};
use pw_ipc::{Client, ClientError};
use pw_proto::{method, topic, AuditState, ClientKind, LiveStats, SystemInfo, TrustFeed};

const EXIT_OTHER: u8 = 1;
const EXIT_NOT_RUNNING: u8 = 2;
const EXIT_DENIED: u8 = 3;
const EXIT_VERSION: u8 = 4;

pub async fn run() -> ExitCode {
    let stream = match pipe::connect(PIPE_NAME).await {
        Ok(stream) => stream,
        Err(err) => return connect_failed(&err),
    };
    let client = match Client::connect(stream, ClientKind::Pwctl, env!("CARGO_PKG_VERSION")).await {
        Ok(client) => client,
        Err(ClientError::AgentOutdated(agent)) => {
            eprintln!(
                "The agent ({}) is older than this pwctl and cannot talk to it. Update PacketWard.",
                agent.agent_version
            );
            return ExitCode::from(EXIT_VERSION);
        }
        Err(ClientError::ClientOutdated(agent)) => {
            eprintln!(
                "This pwctl is older than the agent ({}). Update PacketWard.",
                agent.agent_version
            );
            return ExitCode::from(EXIT_VERSION);
        }
        Err(err) => {
            eprintln!("Could not talk to the agent: {err}");
            return ExitCode::from(EXIT_OTHER);
        }
    };
    let info: SystemInfo = match client.request(method::SYSTEM_INFO, &()).await {
        Ok(info) => info,
        Err(err) => {
            eprintln!("The agent did not answer system.info: {err}");
            return ExitCode::from(EXIT_OTHER);
        }
    };
    println!(
        "Agent:     running ({})",
        if info.service_mode {
            "service"
        } else {
            "console"
        }
    );
    println!("Version:   {}", info.agent_version);
    println!("Protocol:  {}.{}", info.protocol_major, info.protocol_minor);
    println!(
        "Host:      {} ({}), pid {}",
        info.hostname, info.os_family, info.pid
    );
    println!("Uptime:    {}s", info.uptime_secs);
    print_traffic(&client).await;
    ExitCode::SUCCESS
}

fn connect_failed(err: &io::Error) -> ExitCode {
    match err.kind() {
        io::ErrorKind::NotFound => {
            eprintln!("Agent not running (pipe {PIPE_NAME} does not exist).");
            eprintln!("Start it from an elevated shell: packetward-agent start");
            ExitCode::from(EXIT_NOT_RUNNING)
        }
        io::ErrorKind::PermissionDenied => {
            eprintln!("Access to the agent was denied.");
            match access::diagnose() {
                Ok(AccessProblem::GroupMissing) => eprintln!(
                    "The '{OPERATORS_GROUP}' group does not exist. An administrator must run: packetward-agent repair"
                ),
                Ok(AccessProblem::NotMember) => eprintln!(
                    "Your account is not in '{OPERATORS_GROUP}'. An administrator must run: packetward-agent repair --operator-sid <your SID>"
                ),
                Ok(AccessProblem::SignOutRequired) => eprintln!(
                    "You were added to '{OPERATORS_GROUP}' but this session predates it. Sign out and sign back in \
                     (disconnecting and reconnecting RDP is not enough)."
                ),
                Ok(AccessProblem::Unexplained) => eprintln!(
                    "You are in '{OPERATORS_GROUP}' and the session has it, yet access was denied. Check the agent log."
                ),
                Err(diagnosis) => eprintln!("(Could not work out why: {diagnosis})"),
            }
            ExitCode::from(EXIT_DENIED)
        }
        _ => {
            eprintln!("Could not open the agent pipe: {err}");
            ExitCode::from(EXIT_OTHER)
        }
    }
}

/// One `live.stats` snapshot, if the agent publishes it (older agents do not) and answers in time.
async fn print_traffic(client: &Client) {
    let Ok(mut stats) = client.subscribe(topic::LIVE_STATS).await else {
        return;
    };
    let Ok(Some(stats)) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stats.recv_as::<LiveStats>(),
    )
    .await
    else {
        return;
    };
    let mbps = |bps: f64| bps / 1_000_000.0;
    println!(
        "Traffic:   in {:.2} Mbps, out {:.2} Mbps",
        mbps(stats.totals.in_bps),
        mbps(stats.totals.out_bps)
    );
    let c = &stats.connections;
    println!(
        "Conns:     {} established, {} total ({} listening, {} time-wait, {} udp)",
        c.established, c.total, c.listen, c.time_wait, c.udp
    );
    if !stats.rdp_peers.is_empty() {
        println!(
            "RDP peers: {} (port {})",
            stats.rdp_peers.join(", "),
            stats.rdp_port
        );
    }
    print_rdp_trust(&stats);
}

/// Logon-audit warnings and the addresses trusted because of a successful RDP logon.
fn print_rdp_trust(stats: &LiveStats) {
    let trust = &stats.rdp_trust;
    let audit = |state: AuditState| match state {
        AuditState::Enabled => "on",
        AuditState::Disabled => "OFF",
        AuditState::Unknown => "unknown",
    };
    println!(
        "Logon audit: success {}, failure {}",
        audit(trust.audit.success),
        audit(trust.audit.failure)
    );
    if trust.audit.success != AuditState::Enabled {
        println!(
            "  WARNING: successful logons are not audited (or the policy could not be read), so"
        );
        println!("  PacketWard cannot learn which RDP clients are legitimate and the Guardian cannot protect them.");
    }
    if trust.audit.failure != AuditState::Enabled {
        println!(
            "  WARNING: failed logons are not audited (or the policy could not be read), so RDP"
        );
        println!("  brute-force detection cannot work.");
    }
    if trust.audit.success != AuditState::Enabled || trust.audit.failure != AuditState::Enabled {
        println!("  Enable both with an administrator shell: auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable");
    }
    let feed = match trust.feed {
        TrustFeed::Loading => "loading",
        TrustFeed::Ready => "ready",
        TrustFeed::Unavailable => "UNAVAILABLE (cannot read the Security event log)",
    };
    println!(
        "RDP trusted: {} address(es) with a successful logon in the last {} days (event feed {feed})",
        trust.addresses.len(),
        trust.window_days
    );
    for address in trust.addresses.iter().take(5) {
        println!("  {}", address.addr);
    }
}

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! `pwctl rdp`: look at Remote Desktop exposure and, above all, get it back to factory state when a
//! change went wrong. `reset` works through the agent when it is running and on its own when it is
//! not (it needs an elevated shell then).

use std::path::PathBuf;
use std::process::ExitCode;

use pw_firewall::{Confirmation, Firewall, FirewallError, RuleOptions, CONFIRMATION_PHRASE};
use pw_netstat::rdp_control::{RdpControl, DEFAULT_PORT};
use pw_proto::{method, RdpAudit, RdpConfirmRequest};

use crate::status::connect_client;

fn fail(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(1)
}

fn print_audit(audit: &RdpAudit) {
    println!(
        "Remote Desktop: {} on port {}, NLA {}, security layer {}",
        if audit.enabled { "enabled" } else { "disabled" },
        audit.port,
        if audit.nla_required {
            "required"
        } else {
            "NOT required"
        },
        audit.security_layer
    );
    println!(
        "Firewall:       {}{}",
        if audit.open_to_any {
            "open to any address"
        } else {
            "not open to everybody"
        },
        if audit.restricted {
            format!(
                " - restricted by PacketWard to {} entries",
                audit.allowed.len()
            )
        } else {
            String::new()
        }
    );
    println!(
        "Lockout:        {}",
        if audit.lockout_threshold == 0 {
            "off".to_owned()
        } else {
            format!(
                "after {} failures ({} min window, {} min lock)",
                audit.lockout_threshold, audit.lockout_window_mins, audit.lockout_duration_mins
            )
        }
    );
    println!(
        "Attempt limit:  {} failures in {} s",
        audit.attempts.threshold, audit.attempts.window_secs
    );
    for finding in &audit.findings {
        println!(
            "  [{:?}] {}{}",
            finding.severity,
            finding.id,
            finding
                .value
                .as_deref()
                .map(|v| format!(" ({v})"))
                .unwrap_or_default()
        );
    }
    if let Some(pending) = &audit.pending {
        println!(
            "PENDING #{}: {} - confirm it from a NEW connection with `pwctl rdp confirm {}` or it will be reverted.",
            pending.id, pending.description, pending.id
        );
    }
}

pub async fn status() -> ExitCode {
    let client = match connect_client().await {
        Ok(client) => client,
        Err(code) => return code,
    };
    match client.request::<_, RdpAudit>(method::RDP_AUDIT, &()).await {
        Ok(audit) => {
            print_audit(&audit);
            ExitCode::SUCCESS
        }
        Err(err) => fail(format!("The agent refused: {err}")),
    }
}

pub async fn confirm(id: u64, cancel: bool) -> ExitCode {
    let client = match connect_client().await {
        Ok(client) => client,
        Err(code) => return code,
    };
    let name = if cancel {
        method::RDP_CANCEL
    } else {
        method::RDP_CONFIRM
    };
    match client
        .request::<_, RdpAudit>(name, &RdpConfirmRequest { id })
        .await
    {
        Ok(_) => {
            println!("{}", if cancel { "Reverted." } else { "Confirmed." });
            ExitCode::SUCCESS
        }
        Err(err) => fail(format!("The agent refused: {err}")),
    }
}

/// Factory reset: port 3389, built-in rules enabled, no PacketWard restriction. NLA is left alone.
pub async fn reset(offline: bool) -> ExitCode {
    if !offline {
        if let Ok(client) = connect_client().await {
            return match client.request::<_, RdpAudit>(method::RDP_RESET, &()).await {
                Ok(audit) => {
                    println!("Remote Desktop is back to factory settings.");
                    print_audit(&audit);
                    ExitCode::SUCCESS
                }
                Err(err) => fail(format!("The agent could not finish the reset: {err}\nTry `pwctl rdp reset --offline` from an elevated shell.")),
            };
        }
        eprintln!("The agent is not reachable: resetting directly (needs an elevated shell).");
    }
    match tokio::task::spawn_blocking(offline_reset).await {
        Ok(Ok(report)) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Ok(Err(message)) => fail(message),
        Err(err) => fail(err),
    }
}

fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("PacketWard")
}

fn offline_reset() -> Result<String, String> {
    let control = pw_netstat::WindowsRdpControl;
    let firewall = pw_firewall::system_firewall();
    let mut done = Vec::new();
    let config = control
        .read()
        .map_err(|e| format!("cannot read the RDP settings: {e}"))?;
    if config.port != DEFAULT_PORT {
        control
            .set_port(DEFAULT_PORT)
            .and_then(|()| control.restart_service())
            .map_err(|e| format!("cannot restore port {DEFAULT_PORT}: {e}"))?;
        done.push(format!("port {} -> {DEFAULT_PORT}", config.port));
    }
    let confirmation = Confirmation::from_phrase(CONFIRMATION_PHRASE).map_err(|e| e.to_string())?;
    let opts = RuleOptions::default().confirmed(&confirmation);
    firewall
        .set_builtin_rdp_enabled(true, &opts)
        .map_err(|e| format!("cannot re-enable the built-in Remote Desktop rules: {e}"))?;
    done.push("built-in Remote Desktop rules enabled".to_owned());
    for name in ["PW-RDP-Allow", "PW-RDP-Allow-UDP"] {
        match firewall.remove_rule(name, &opts) {
            Ok(()) => done.push(format!("removed rule {name}")),
            Err(FirewallError::NotFound(_)) => {}
            Err(err) => return Err(format!("cannot remove {name}: {err}")),
        }
    }
    // A change that was waiting for confirmation must not be "reverted" over this reset later.
    let state = data_dir().join("rdp_shield.json");
    if state.exists() {
        std::fs::remove_file(&state)
            .map_err(|e| format!("cannot clear {}: {e}", state.display()))?;
        done.push("pending changes forgotten".to_owned());
    }
    Ok(format!(
        "Remote Desktop is back to factory settings:\n  {}",
        done.join("\n  ")
    ))
}

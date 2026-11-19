// SPDX-License-Identifier: GPL-3.0-or-later
//! `pwctl` commands for the firewall manager and the Guardian: emergency recovery first
//! (`unblock --all`, `firewall purge`, `guardian off`), plus manual blocks and status.

use std::process::ExitCode;

use pw_proto::{
    method, BlockList, BlockRequest, BlockResult, GuardianMode, GuardianPolicy, GuardianStatus,
    PurgeRequest, PurgeResult, SetGuardianPolicy, UnblockRequest,
};

use crate::status::connect_client;

fn fail(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(1)
}

/// `pwctl unblock <targets…>` or `pwctl unblock --all`.
pub async fn unblock(targets: Vec<String>, all: bool) -> ExitCode {
    let client = match connect_client().await {
        Ok(client) => client,
        Err(code) => return code,
    };
    let result: Result<BlockList, _> = if all {
        client.request(method::FIREWALL_UNBLOCK_ALL, &()).await
    } else if targets.is_empty() {
        return fail("Give the addresses to unblock, or --all to remove every block.");
    } else {
        client
            .request(method::FIREWALL_UNBLOCK, &UnblockRequest { targets })
            .await
    };
    match result {
        Ok(list) => {
            println!("Done. {} block(s) remain.", list.blocks.len());
            ExitCode::SUCCESS
        }
        Err(err) => fail(format!("The agent refused: {err}")),
    }
}

/// `pwctl block <targets…> [--minutes N] [--reason text]`.
pub async fn block(targets: Vec<String>, minutes: Option<u64>, reason: String) -> ExitCode {
    let client = match connect_client().await {
        Ok(client) => client,
        Err(code) => return code,
    };
    let request = BlockRequest {
        targets,
        ttl_secs: minutes.map(|m| m * 60),
        reason,
        allow_broad: false,
    };
    match client
        .request::<_, BlockResult>(method::FIREWALL_BLOCK, &request)
        .await
    {
        Ok(result) => {
            for item in &result.blocked {
                println!("Blocked   {item}");
            }
            for item in &result.refused_protected {
                println!("REFUSED   {} (protected: {})", item.target, item.reason);
            }
            for item in &result.refused_broad {
                println!("REFUSED   {item} (range too wide)");
            }
            if result.blocked.is_empty() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => fail(format!("The agent refused: {err}")),
    }
}

/// `pwctl firewall list` (blocks).
pub async fn list_blocks() -> ExitCode {
    let client = match connect_client().await {
        Ok(client) => client,
        Err(code) => return code,
    };
    match client
        .request::<_, BlockList>(method::FIREWALL_BLOCKS, &())
        .await
    {
        Ok(list) => {
            if list.blocks.is_empty() {
                println!("No blocks.");
            }
            for block in &list.blocks {
                let until = block.expires_unix_ms.map_or_else(
                    || "until removed".to_owned(),
                    |ms| format!("until {}", ms / 1000),
                );
                println!(
                    "{:<40} {:?}  {until}  {}",
                    block.cidr, block.source, block.reason
                );
            }
            println!("{} firewall rule(s) used.", list.rules_used);
            ExitCode::SUCCESS
        }
        Err(err) => fail(format!("The agent refused: {err}")),
    }
}

/// `pwctl firewall purge [--confirm "<phrase>"]`: removes every PacketWard rule.
pub async fn purge(confirmation: Option<String>) -> ExitCode {
    let client = match connect_client().await {
        Ok(client) => client,
        Err(code) => return code,
    };
    match client
        .request::<_, PurgeResult>(method::FIREWALL_PURGE, &PurgeRequest { confirmation })
        .await
    {
        Ok(result) => {
            println!("Removed {} PacketWard rule(s).", result.removed_rules.len());
            for name in &result.removed_rules {
                println!("  {name}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail(format!("The agent refused: {err}")),
    }
}

/// `pwctl guardian [off|monitor|active] [--yes]`; without a mode it prints the status.
pub async fn guardian(mode: Option<GuardianMode>, yes: bool) -> ExitCode {
    let client = match connect_client().await {
        Ok(client) => client,
        Err(code) => return code,
    };
    let status: GuardianStatus = match client.request(method::GUARDIAN_STATUS, &()).await {
        Ok(status) => status,
        Err(err) => return fail(format!("The agent did not answer: {err}")),
    };
    let status = match mode {
        Some(mode) => {
            let policy = GuardianPolicy {
                mode,
                ..status.policy.clone()
            };
            match client
                .request::<_, GuardianStatus>(
                    method::GUARDIAN_SET_POLICY,
                    &SetGuardianPolicy {
                        policy,
                        confirm_active: yes,
                    },
                )
                .await
            {
                Ok(status) => status,
                Err(err) => {
                    return fail(format!(
                    "{err}\nTo switch to Active, review the Monitor report first and pass --yes."
                ))
                }
            }
        }
        None => status,
    };
    println!("Guardian:  {:?}", status.policy.mode);
    println!(
        "Circuit:   {} ({} automatic blocks in the last hour, limit {})",
        if status.circuit_open {
            "OPEN"
        } else {
            "closed"
        },
        status.blocks_last_hour,
        status.policy.max_blocks_per_hour
    );
    println!(
        "Would have blocked (24 h, Monitor): {} address(es)",
        status.would_block_24h
    );
    println!("Never blocked ({} entries):", status.protected.len());
    for entry in &status.protected {
        println!("  {:<24} {}", entry.cidr, entry.reason);
    }
    for decision in status.decisions.iter().take(10) {
        println!("  {:<20} {}", decision.outcome, decision.why);
    }
    ExitCode::SUCCESS
}

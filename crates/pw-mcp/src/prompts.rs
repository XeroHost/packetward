// SPDX-License-Identifier: GPL-3.0-or-later
//! The three MCP prompts of ARCHITECTURE §6.14.
//!
//! Each prompt names the tools to read, says what conclusion to draw, and ends with the
//! untrusted-fields reminder. They never instruct the AI to execute an action: the risky tools need
//! the owner's approval and the prompts only propose.

use serde_json::{Map, Value};

use crate::envelope::NOTICE;

/// One argument of a prompt.
pub struct PromptArgumentSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub required: bool,
}

/// One prompt, with the template that builds its text.
pub struct PromptSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub arguments: &'static [PromptArgumentSpec],
    build: fn(&Map<String, Value>) -> String,
}

impl PromptSpec {
    /// The prompt text for the client's arguments (unknown arguments are ignored).
    pub fn render(&self, arguments: Option<&Map<String, Value>>) -> String {
        static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
        (self.build)(arguments.unwrap_or(&EMPTY))
    }
}

fn text_argument<'a>(arguments: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The three prompts, in the order of §6.14.
pub static PROMPTS: &[PromptSpec] = &[
    PromptSpec {
        name: "analyze-attack",
        description: "Review the current alerts and Guardian decisions, identify the attacking sources and propose a bounded block (never execute it).",
        arguments: &[
            PromptArgumentSpec {
                name: "address",
                description: "Focus on one source address (optional).",
                required: false,
            },
            PromptArgumentSpec {
                name: "time_window",
                description: "Only consider this time window, for example `last 2 hours` (optional).",
                required: false,
            },
        ],
        build: analyze_attack,
    },
    PromptSpec {
        name: "diagnose-latency",
        description: "Trace the route to a host, compare it with ping and local counters, and say where the loss or latency starts.",
        arguments: &[PromptArgumentSpec {
            name: "host",
            description: "Host name or IP address to diagnose.",
            required: true,
        }],
        build: diagnose_latency,
    },
    PromptSpec {
        name: "rdp-security-review",
        description: "Review Remote Desktop exposure, failed logons and trusted clients, and give recommendations only.",
        arguments: &[],
        build: |_arguments| {
            format!(
                "Review the Remote Desktop security of this Windows Server. Work in this order:\n\
                 1. Call `rdp_audit` and list every finding with its severity and value (NLA, port, \
                 security layer, lockout policy, rule scope, pending change).\n\
                 2. Call `live_stats` and describe the trusted RDP clients, the current peers of the RDP \
                 port and the audit-policy state.\n\
                 3. Call `alerts` and `guardian_decisions` and summarise the failed-logon (RDP brute \
                 force) incidents and whether the Guardian blocked or would block them.\n\
                 4. Call `firewall_rules` with `managed_only: true` and check the PacketWard rules that \
                 allow or restrict the RDP port.\n\
                 Then give recommendations in plain words, ordered by risk. Do not change anything and \
                 do not call an execution tool: the owner performs the changes in PacketWard, where the \
                 RDP Shield asks for confirmations and reverts a change that is not confirmed in time.\n\n\
                 {NOTICE}"
            )
        },
    },
];

/// One prompt by name.
pub fn prompt(name: &str) -> Option<&'static PromptSpec> {
    PROMPTS.iter().find(|prompt| prompt.name == name)
}

fn analyze_attack(arguments: &Map<String, Value>) -> String {
    let address = text_argument(arguments, "address");
    let window = text_argument(arguments, "time_window");

    let mut scope = String::new();
    if let Some(address) = address {
        scope.push_str(&format!("Focus on the source address {address}. "));
    }
    if let Some(window) = window {
        scope.push_str(&format!("Only consider the time window: {window}. "));
    }

    format!(
        "Analyse whether this Windows Server is being attacked. {scope}Work in this order:\n\
         1. Call `alerts` and group the incidents by source, kind and severity; note which incidents are \
         still running and which sources are marked protected.\n\
         2. Call `top_remote_ips` and `live_stats` and say whether the inbound rate is close to the link \
         speed (if it is, only upstream mitigation helps).\n\
         3. Call `guardian_decisions` and say what the Guardian blocked, would block, or skipped, and why.\n\
         4. Call `ip_lookup` for the main sources to add country and network owner.\n\
         5. If useful, call `port_check` for the exposed service and `audit_log` with a search for the \
         source address.\n\
         Conclude with: the likely attack type, the top sources and volumes, whether the machine or the \
         route is at fault, and a proposal. If a block is justified, propose the exact `block_ip` call \
         (address and TTL, at most 7 days) but DO NOT execute it: the owner decides. Never suggest \
         disabling the firewall, purging rules, changing the Guardian policy or any RDP Shield action.\n\n\
         {NOTICE}"
    )
}

fn diagnose_latency(arguments: &Map<String, Value>) -> String {
    let host = text_argument(arguments, "host").unwrap_or("the host the owner named");
    format!(
        "Diagnose the latency and packet loss to {host}. Work in this order:\n\
         1. Call `mtr` with `host: \"{host}\"`, a few cycles and at most 20 hops; identify the first hop \
         where loss or latency appears and whether it continues to the destination.\n\
         2. Call `ping` to {host} and compare its loss and round-trip statistics with the trace.\n\
         3. Call `port_check` on the relevant port (TCP) and note an inconclusive UDP result as such.\n\
         4. Call `live_stats` and `captures_summary` to read the interface counters, link speed and \
         whether the capture is blind to inbound packets.\n\
         Say where the loss starts and whether the problem is on this machine (interface saturation, \
         local firewall, capture trouble), on the route (a middle hop), or at the destination. Do not \
         change any setting.\n\n\
         {NOTICE}"
    )
}

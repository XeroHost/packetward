// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Catalog, envelope, schema, prompt and end-to-end tests (fake agent over the in-memory pipe).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use pw_ipc::{Client, EventReceiver, Handler};
use pw_proto::{
    method, topic, ClientKind, ErrorCode, ErrorPayload, HelloResponse, PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
};
use rmcp::model::ContentBlock;
use rmcp::ServerHandler;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::catalog::{self, ToolGroup, ToolLevel};
use crate::envelope::{self, NOTICE};
use crate::prompts;
use crate::server::McpServer;

fn tool_spec(name: &str) -> &'static catalog::ToolSpec {
    catalog::tool(name).expect("catalog entry must exist")
}

#[test]
fn the_catalog_lists_every_exposed_tool_once() {
    let names: Vec<&str> = catalog::tools().iter().map(|tool| tool.name).collect();
    let expected_read = [
        "live_stats",
        "connections",
        "top_remote_ips",
        "alerts",
        "guardian_decisions",
        "captures_summary",
        "mtr",
        "ping",
        "dns_lookup",
        "port_check",
        "ip_lookup",
        "firewall_rules",
        "rdp_audit",
        "audit_log",
        "action_status",
    ];
    let expected_execution = [
        "block_ip",
        "start_capture",
        "speed_test",
        "support_bundle",
        "unblock_ip",
        "set_guardian_mode",
        "create_firewall_rule",
        "delete_firewall_rule",
    ];
    assert_eq!(names.len(), expected_read.len() + expected_execution.len());

    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "duplicate tool name: {names:?}");

    for name in expected_read {
        assert_eq!(
            tool_spec(name).group,
            ToolGroup::Read,
            "{name} must be a read tool"
        );
        assert_eq!(tool_spec(name).level, ToolLevel::Read);
    }
    for name in expected_execution {
        assert_eq!(
            tool_spec(name).group,
            ToolGroup::Execution,
            "{name} must be an execution tool"
        );
        assert_ne!(
            tool_spec(name).level,
            ToolLevel::Read,
            "{name} must have an execution level class"
        );
    }
}

#[test]
fn approval_only_is_exactly_the_four_risky_tools() {
    let mut names: Vec<&str> = catalog::approval_only().collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "create_firewall_rule",
            "delete_firewall_rule",
            "set_guardian_mode",
            "unblock_ip"
        ]
    );
    for name in names {
        assert_eq!(tool_spec(name).level, ToolLevel::Approval);
    }
}

#[test]
fn no_tool_maps_to_a_never_exposed_method() {
    let forbidden = [
        method::FIREWALL_PURGE,
        method::FIREWALL_UNBLOCK_ALL,
        method::FIREWALL_RULE_UPDATE,
        method::FIREWALL_RULE_ENABLE,
        method::RDP_RESTRICT,
        method::RDP_UNRESTRICT,
        method::RDP_PORT,
        method::RDP_NLA,
        method::RDP_LOCKOUT,
        method::RDP_ATTEMPTS,
        method::RDP_CONFIRM,
        method::RDP_CANCEL,
        method::RDP_RESET,
        method::RDP_END_SESSION,
        method::RDP_COUNTRY_GET,
        method::RDP_COUNTRY_SET,
        method::GUARDIAN_ALLOWLIST,
        method::GUARDIAN_SET_ALLOWLIST,
        method::SETTINGS_GET,
        method::SETTINGS_SET_PROXY,
        method::SETTINGS_SET_CAPTURE_ON_START,
        method::MCP_SETTINGS_GET,
        method::MCP_SETTINGS_SET,
        method::MCP_APPROVE,
        method::MCP_REJECT,
        method::INTEL_LIST_ENABLE,
        method::INTEL_LIST_REFRESH,
        method::CAPTURE_STOP,
        method::CAPTURE_START,
        method::CAPTURE_RECORD_STOP,
        method::CAPTURE_FILES_DELETE,
        method::ALERTS_CLEAR,
        method::SUPPORT_READ,
        method::SUPPORT_PREVIEW,
        method::SUPPORT_DISCARD,
    ];
    for tool in catalog::tools() {
        assert!(
            !forbidden.contains(&tool.method),
            "tool `{}` maps to the never-exposed method `{}`",
            tool.name,
            tool.method
        );
    }
}

#[test]
fn every_description_repeats_the_data_rule() {
    for tool in catalog::tools() {
        assert!(
            tool.description().contains(catalog::DATA_RULE),
            "tool `{}` lacks the data rule",
            tool.name
        );
    }
}

#[test]
fn every_tool_has_an_object_schema() {
    for tool in catalog::tools() {
        let schema = (tool.schema)();
        assert_eq!(
            schema.get("type").and_then(Value::as_str),
            Some("object"),
            "tool `{}` has no object schema",
            tool.name
        );
        assert!(
            schema.get("properties").is_some(),
            "tool `{}` schema lacks properties",
            tool.name
        );
        if let Some(untrusted) = schema.get("required") {
            assert!(untrusted.is_array());
        }
    }
}

#[test]
fn block_ip_requires_a_bounded_ttl_and_an_address() {
    let schema = (tool_spec("block_ip").schema)();
    let required = schema["required"].as_array().expect("required list");
    assert!(required.iter().any(|value| value == "ttl_secs"));
    assert!(required.iter().any(|value| value == "ip"));
    assert_eq!(schema["properties"]["ttl_secs"]["maximum"], json!(604800));
    assert_eq!(schema["properties"]["ttl_secs"]["minimum"], json!(1));

    let args: catalog::BlockIpArgs = serde_json::from_value(json!({
        "ip": " 203.0.113.9 ",
        "ttl_secs": 3600
    }))
    .expect("sample arguments must parse");
    let request = args.to_proto().expect("valid block");
    assert_eq!(request.targets, ["203.0.113.9"]);
    assert_eq!(request.ttl_secs, Some(3600));
    assert!(!request.allow_broad);

    let too_long: catalog::BlockIpArgs =
        serde_json::from_value(json!({ "ip": "203.0.113.9", "ttl_secs": 604801 }))
            .expect("shape parses; the bound is enforced by the mapper");
    assert!(too_long.to_proto().is_err());
}

#[test]
fn start_capture_forces_headers_only_and_a_short_recording() {
    let args: catalog::StartCaptureArgs = serde_json::from_value(json!({
        "duration_secs": 30,
        "filter": "tcp and port 3389"
    }))
    .expect("sample arguments must parse");
    let request: pw_proto::RecordStartRequest = args.to_proto().expect("valid recording");
    assert_eq!(request.payload, pw_proto::PayloadView::Headers);
    assert_eq!(request.mode, pw_proto::RecordModeView::Timed);
    assert_eq!(request.duration_secs, Some(30));
    assert!(!request.confirm_full_payload);

    let too_long: catalog::StartCaptureArgs =
        serde_json::from_value(json!({ "duration_secs": 61 })).expect("shape parses");
    assert!(too_long.to_proto().is_err());
}

#[test]
fn the_other_execution_args_map_to_their_pw_proto_requests() {
    let speed: catalog::SpeedTestArgs =
        serde_json::from_value(json!({ "kind": "bin1", "provider": "hetzner" }))
            .expect("sample arguments must parse");
    let request: pw_proto::SpeedRequest = speed.to_proto();
    assert_eq!(request.kind, pw_proto::SpeedKind::Bin1);
    assert_eq!(request.provider.as_deref(), Some("hetzner"));
    assert!(!request.confirm_large);

    let support: catalog::SupportBundleArgs = serde_json::from_value(json!({
        "anonymize_local_ips": true,
        "capture_secs": 60,
        "include_logs": false
    }))
    .expect("sample arguments must parse");
    let request: pw_proto::SupportBundleRequest = support.to_proto().expect("valid bundle");
    assert!(request.anonymize_local_ips);
    assert_eq!(request.capture_secs, 60);

    let rule: catalog::CreateFirewallRuleArgs = serde_json::from_value(json!({
        "name": "Allow lab SSH",
        "direction": "inbound",
        "action": "allow",
        "protocol": "tcp",
        "local_ports": "2222",
        "remote_ports": "*",
        "local_addresses": "*",
        "remote_addresses": "198.51.100.0/24"
    }))
    .expect("sample arguments must parse");
    let edit: pw_proto::FirewallRuleEdit = rule.to_edit().expect("valid rule");
    assert_eq!(edit.rule.group, "PacketWard");
    assert!(edit.rule.managed);
    assert_eq!(edit.rule.direction, pw_proto::RuleDirection::Inbound);
    assert_eq!(edit.rule.action, pw_proto::RuleAction::Allow);
    assert!(!edit.allow_foreign_edit);

    let unblock: catalog::UnblockIpArgs =
        serde_json::from_value(json!({ "ip": "203.0.113.9" })).expect("sample parses");
    let request: pw_proto::UnblockRequest = unblock.to_proto().expect("valid unblock");
    assert_eq!(request.targets, ["203.0.113.9"]);

    let guardian: catalog::SetGuardianModeArgs =
        serde_json::from_value(json!({ "mode": "monitor" })).expect("sample parses");
    assert_eq!(
        pw_proto::GuardianMode::from(guardian.mode),
        pw_proto::GuardianMode::Monitor
    );

    let mtr: catalog::MtrArgs = serde_json::from_value(json!({
        "target": "1.1.1.1",
        "mode": "tcp",
        "port": 443,
        "cycles": 5
    }))
    .expect("sample parses");
    let request: pw_proto::MtrStartRequest = mtr.to_proto();
    assert_eq!(request.target, "1.1.1.1");
    assert_eq!(request.mode, Some(pw_proto::MtrModeView::Tcp));
    assert_eq!(request.port, Some(443));

    let ping: catalog::PingArgs =
        serde_json::from_value(json!({ "target": "1.1.1.1", "count": 3 })).expect("sample parses");
    let request: pw_proto::PingStartRequest = ping.to_proto();
    assert_eq!(request.count, Some(3));

    let dns: catalog::DnsLookupArgs = serde_json::from_value(json!({
        "name": "example.com",
        "record_type": "a",
        "resolver": "system"
    }))
    .expect("sample parses");
    let request: pw_proto::DnsLookupRequest = dns.to_proto();
    assert_eq!(request.record_type, "A");

    let port: catalog::PortCheckArgs = serde_json::from_value(json!({
        "host": "1.1.1.1",
        "port": 443,
        "protocol": "TCP"
    }))
    .expect("sample parses");
    let request: pw_proto::PortCheckRequest = port.to_proto();
    assert_eq!(request.protocol, "tcp");

    let lookup: catalog::IpLookupArgs =
        serde_json::from_value(json!({ "addrs": ["1.1.1.1"] })).expect("sample parses");
    assert_eq!(lookup.to_proto().addrs, ["1.1.1.1"]);

    let rules: catalog::FirewallRulesArgs =
        serde_json::from_value(json!({ "managed_only": true, "direction": "inbound" }))
            .expect("sample parses");
    let request: pw_proto::FirewallRulesRequest = rules.to_proto();
    assert!(request.managed_only);
    assert_eq!(request.direction, Some(pw_proto::RuleDirection::Inbound));

    let audit: catalog::AuditLogArgs =
        serde_json::from_value(json!({ "limit": 50, "search": "mcp" })).expect("sample parses");
    let query: pw_proto::AuditQuery = audit.to_proto();
    assert_eq!(query.limit, Some(50));
    assert_eq!(query.search.as_deref(), Some("mcp"));

    let status: catalog::ActionStatusArgs =
        serde_json::from_value(json!({ "id": 7 })).expect("sample parses");
    assert_eq!(status.to_proto().id, 7);
}

#[test]
fn sanitize_removes_control_characters_and_caps_the_length() {
    assert_eq!(envelope::sanitize("a\u{0}b\u{1f}c\u{7f}d\u{85}e"), "abcde");

    let long = "a".repeat(300);
    assert_eq!(envelope::sanitize(&long).chars().count(), 256);

    let multibyte = "é".repeat(300);
    let short = envelope::sanitize(&multibyte);
    assert_eq!(short.chars().count(), 256);
    assert_eq!(short.len(), 512);
    assert!(std::str::from_utf8(short.as_bytes()).is_ok());
}

#[test]
fn the_envelope_lists_and_sanitizes_the_untrusted_paths() {
    let data = json!({
        "connections": [
            { "process": "evil\u{0}name", "local_addr": "10.0.0.1" },
            { "process": "x".repeat(300) }
        ],
        "processes": { "4": "Sys\u{1f}tem" },
        "safe": "keep\u{0}me"
    });
    let wrapped = envelope::wrap_paths(data, &["connections[].process", "processes.*"]);
    assert_eq!(wrapped["notice"], NOTICE);
    assert_eq!(wrapped["untrusted_fields"][0], "connections[].process");
    assert_eq!(
        wrapped["data"]["connections"][0]["process"],
        json!("evilname")
    );
    assert_eq!(
        wrapped["data"]["connections"][1]["process"]
            .as_str()
            .expect("string")
            .chars()
            .count(),
        256
    );
    assert_eq!(wrapped["data"]["processes"]["4"], json!("System"));
    // A path that is not listed is untouched.
    assert_eq!(wrapped["data"]["safe"], json!("keep\u{0}me"));
}

#[test]
fn a_container_path_sanitizes_every_string_inside_it() {
    // `entries[].detail` is a JSON object: nested strings (audit reasons, hostnames) are untrusted too.
    let mut data = json!({
        "entries": [
            { "detail": { "args": "block\u{0} 203.0.113.9", "nested": { "why": "x".repeat(300) } } }
        ]
    });
    envelope::sanitize_path(&mut data, "entries[].detail");
    let detail = &data["entries"][0]["detail"];
    assert_eq!(detail["args"], json!("block 203.0.113.9"));
    assert_eq!(
        detail["nested"]["why"]
            .as_str()
            .expect("string")
            .chars()
            .count(),
        256
    );
}

#[test]
fn action_status_marks_the_approved_result_untrusted() {
    let spec = catalog::tool("action_status").expect("the tool exists");
    assert!(
        spec.untrusted.contains(&"result"),
        "an approved result carries the tool's own untrusted output"
    );
}

#[test]
fn every_tool_is_wrapped_with_its_own_paths() {
    for tool in catalog::tools() {
        let wrapped = envelope::wrap(tool, json!({ "data": true }));
        assert_eq!(wrapped["notice"], NOTICE);
        assert_eq!(
            wrapped["untrusted_fields"],
            json!(tool.untrusted),
            "tool `{}` lists different paths",
            tool.name
        );
    }
}

#[test]
fn all_three_prompts_end_with_the_reminder() {
    let names: Vec<&str> = prompts::PROMPTS.iter().map(|prompt| prompt.name).collect();
    assert_eq!(
        names,
        ["analyze-attack", "diagnose-latency", "rdp-security-review"]
    );
    for spec in prompts::PROMPTS {
        let text = spec.render(None);
        assert!(text.ends_with(NOTICE), "`{}` lacks the reminder", spec.name);
        assert!(!spec.description.is_empty());
    }

    let attack = prompts::prompt("analyze-attack").expect("prompt");
    let text = attack.render(Some(
        &json!({
            "address": "203.0.113.9",
            "time_window": "last 2 hours"
        })
        .as_object()
        .expect("object")
        .clone(),
    ));
    assert!(text.contains("203.0.113.9"));
    assert!(text.contains("last 2 hours"));
    assert!(text.contains("DO NOT execute"));

    let latency = prompts::prompt("diagnose-latency").expect("prompt");
    assert!(latency.render(None).contains("the host the owner named"));
    let arguments = json!({ "host": "1.1.1.1" });
    let rendered = latency.render(arguments.as_object());
    assert!(rendered.contains("1.1.1.1"));
}

// ---- End-to-end with a fake agent -------------------------------------------------------------

#[derive(Default)]
struct FakeAgent {
    calls: Mutex<Vec<String>>,
    ran: Mutex<Vec<String>>,
    forced_forbidden: AtomicBool,
}

impl FakeAgent {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls lock").clone()
    }

    fn ran(&self) -> Vec<String> {
        self.ran.lock().expect("ran lock").clone()
    }

    fn record_call(&self, method_name: &str) {
        self.calls
            .lock()
            .expect("calls lock")
            .push(method_name.to_owned());
    }

    fn record_ran(&self, method_name: &str) {
        self.ran
            .lock()
            .expect("ran lock")
            .push(method_name.to_owned());
    }
}

impl Handler for FakeAgent {
    fn hello(&self) -> HelloResponse {
        HelloResponse {
            agent_version: "fake".into(),
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
        }
    }

    async fn handle(
        &self,
        _ctx: pw_ipc::ConnCtx,
        method_name: &str,
        _payload: Value,
    ) -> Result<Value, ErrorPayload> {
        self.record_call(method_name);
        if self.forced_forbidden.load(Ordering::SeqCst) {
            return Err(ErrorPayload::new(
                ErrorCode::Forbidden,
                "the MCP master switch is off",
            ));
        }
        match method_name {
            method::NETSTAT_CONNECTIONS => {
                self.record_ran(method_name);
                Ok(json!({
                    "connections": [],
                    "processes": { "4": "Sys\u{0}tem" },
                    "total": 0,
                    "truncated": false,
                    "sampled_unix_ms": 1
                }))
            }
            method::FIREWALL_UNBLOCK => {
                // Approval level: the action does NOT run; the agent queues it.
                Ok(json!({
                    "id": 42,
                    "status": "pending"
                }))
            }
            other => Err(ErrorPayload::new(
                ErrorCode::UnknownMethod,
                format!("no such method {other}"),
            )),
        }
    }

    async fn subscribe(
        &self,
        _ctx: pw_ipc::ConnCtx,
        topic_name: &str,
    ) -> Result<EventReceiver, ErrorPayload> {
        match topic_name {
            topic::DIAG_PROGRESS | topic::SPEED_PROGRESS => {
                let (_tx, rx) = mpsc::channel(1);
                Ok(rx)
            }
            other => Err(ErrorPayload::new(
                ErrorCode::UnknownTopic,
                format!("no such topic {other}"),
            )),
        }
    }
}

/// Starts a fake agent and an MCP server. The connector must stay alive: when it is dropped, the
/// in-memory listener treats it as "no more clients" and shuts the accepted connections down.
async fn server_with(fake: Arc<FakeAgent>) -> (McpServer, pw_ipc::memory::MemoryConnector) {
    let (listener, connector) = pw_ipc::memory::memory_pair();
    let _ipc = tokio::spawn(pw_ipc::serve(
        listener,
        Arc::clone(&fake),
        std::future::pending::<()>(),
    ));
    let stream = connector.connect().await.expect("connect");
    let client = Client::connect(stream, ClientKind::Mcp, "test")
        .await
        .expect("handshake");
    (McpServer::new(client), connector)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_tools_returns_the_full_catalog() {
    let fake = Arc::new(FakeAgent::default());
    let (server, _connector) = server_with(fake).await;
    let result = server.list_tools_result();
    assert_eq!(result.tools.len(), catalog::tools().len());
    let names: Vec<&str> = result.tools.iter().map(|tool| tool.name.as_ref()).collect();
    for spec in catalog::tools() {
        assert!(names.contains(&spec.name), "{} missing", spec.name);
    }
    for tool in &result.tools {
        assert!(tool
            .description
            .as_deref()
            .is_some_and(|text| text.contains(catalog::DATA_RULE)));
    }
    assert!(server.get_tool("block_ip").is_some());
    assert!(server.get_tool("firewall_purge").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_call_forwards_the_method_and_wraps_the_reply() {
    let fake = Arc::new(FakeAgent::default());
    let (server, _connector) = server_with(Arc::clone(&fake)).await;
    let result = server
        .call_tool_value(
            "connections",
            Some(json!({ "limit": 5 }).as_object().expect("object").clone()),
        )
        .await
        .expect("a known tool is not a protocol error");
    assert_eq!(result.is_error, Some(false));
    let envelope = result.structured_content.expect("structured envelope");
    assert_eq!(envelope["notice"], NOTICE);
    assert_eq!(envelope["untrusted_fields"], json!(["processes.*"]));
    assert_eq!(envelope["data"]["processes"]["4"], json!("System"));
    assert_eq!(fake.calls(), [method::NETSTAT_CONNECTIONS]);
    assert_eq!(fake.ran(), [method::NETSTAT_CONNECTIONS]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approval_call_returns_pending_approval_and_does_not_execute() {
    let fake = Arc::new(FakeAgent::default());
    let (server, _connector) = server_with(Arc::clone(&fake)).await;
    let result = server
        .call_tool_value(
            "unblock_ip",
            Some(
                json!({ "ip": "203.0.113.9" })
                    .as_object()
                    .expect("object")
                    .clone(),
            ),
        )
        .await
        .expect("known tool");
    assert_eq!(result.is_error, Some(false));
    let envelope = result.structured_content.expect("structured envelope");
    let data = &envelope["data"];
    assert_eq!(data["status"], json!("pending_approval"));
    assert_eq!(data["id"], json!(42));
    assert_eq!(data["expires_in_secs"], json!(300));

    assert_eq!(fake.calls(), [method::FIREWALL_UNBLOCK]);
    assert!(
        fake.ran().is_empty(),
        "an approval-level action must not run before the owner approves it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forbidden_reply_becomes_a_tool_error_with_the_agent_message() {
    let fake = Arc::new(FakeAgent::default());
    fake.forced_forbidden.store(true, Ordering::SeqCst);
    let (server, _connector) = server_with(Arc::clone(&fake)).await;
    let result = server
        .call_tool_value("alerts", None)
        .await
        .expect("a refused known tool is a tool result, not a protocol error");
    assert_eq!(result.is_error, Some(true));
    let text = result
        .content
        .iter()
        .find_map(|block| match block {
            ContentBlock::Text(text) => Some(text.text.clone()),
            _ => None,
        })
        .expect("error text");
    assert!(text.contains("the MCP master switch is off"), "{text}");
    assert!(text.contains("Forbidden"), "{text}");
}

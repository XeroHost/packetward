// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The MCP server over stdio (rmcp 3.11), forwarding every tool call to the agent.
//!
//! [`serve`] is the entry point the CLI calls with an already handshaken [`pw_ipc::Client`]. The tool
//! list is the full [`crate::catalog`]; the agent decides at call time whether a tool is allowed
//! (`Forbidden` when the master switch is off or the tool is disabled).
//!
//! Job tools (`ping`, `mtr`, `speed_test`) subscribe to the progress topic **before** starting the
//! job, filter the events by job id, wait for the terminal event with a timeout and cancel the job on
//! timeout. Subscriptions are serialized with a mutex because `pw-ipc` keeps one subscription per
//! topic.

use std::sync::Arc;
use std::time::Duration;

use pw_ipc::Client;
use pw_proto::{
    method, topic, AlertList, AuditQuery, BlockResult, CaptureStatus, ConnectionsRequest,
    ConnectionsResponse, DiagEvent, DiagJobRequest, DiagStartResponse, DnsLookupRequest,
    FirewallRuleAction, FirewallRuleEdit, FirewallRules, FirewallRulesRequest, GeoLookupRequest,
    GeoLookupResult, GuardianMode, GuardianStatus, LiveStats, McpActionStatus, McpActionStatusView,
    MtrStartRequest, MtrView, PingStartRequest, PortCheckRequest, PortCheckView,
    RecordStartRequest, SetGuardianPolicy, SpeedEvent, SpeedRequest, SpeedStarted,
    SupportBundleInfo, SupportBundleRequest, UnblockRequest,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, GetPromptRequestParams,
    GetPromptResponse, GetPromptResult, Implementation, JsonObject, ListPromptsResult,
    ListToolsResult, PaginatedRequestParams, Prompt, PromptArgument, PromptMessage, Role,
    ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as RpcError, RoleServer, ServerHandler, ServiceExt};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;

use crate::catalog::{self, ToolSpec};
use crate::envelope;
use crate::prompts;
use crate::McpError;

const PING_DEADLINE: Duration = Duration::from_secs(30);
const MTR_DEADLINE: Duration = Duration::from_secs(180);
const SPEED_DEADLINE: Duration = Duration::from_secs(600);

/// The MCP server handler. Cheap to share: one IPC client and one job mutex.
pub struct McpServer {
    client: Client,
    job_lock: Mutex<()>,
}

impl McpServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            job_lock: Mutex::new(()),
        }
    }

    /// The tool list sent to the client: the full catalog.
    pub fn list_tools_result(&self) -> ListToolsResult {
        ListToolsResult::with_all_items(
            catalog::tools()
                .iter()
                .copied()
                .map(tool_definition)
                .collect(),
        )
    }

    /// The prompt list sent to the client.
    pub fn list_prompts_result(&self) -> ListPromptsResult {
        ListPromptsResult::with_all_items(
            prompts::PROMPTS
                .iter()
                .map(|spec| {
                    Prompt::new(
                        spec.name,
                        Some(spec.description),
                        Some(
                            spec.arguments
                                .iter()
                                .map(|argument| {
                                    PromptArgument::new(argument.name)
                                        .with_description(argument.description)
                                        .with_required(argument.required)
                                })
                                .collect(),
                        ),
                    )
                })
                .collect(),
        )
    }

    /// Renders one prompt, or an invalid-params error for an unknown name.
    pub fn get_prompt_result(
        &self,
        name: &str,
        arguments: Option<&Map<String, Value>>,
    ) -> Result<GetPromptResult, RpcError> {
        let spec = prompts::prompt(name)
            .ok_or_else(|| RpcError::invalid_params(format!("unknown prompt `{name}`"), None))?;
        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            Role::User,
            spec.render(arguments),
        )])
        .with_description(spec.description))
    }

    /// Executes one tool. Only an unknown tool is a protocol error; everything else (agent refusal,
    /// bad arguments, timeout) is a tool-level error the AI and its user can read.
    pub async fn call_tool_value(
        &self,
        name: &str,
        arguments: Option<JsonObject>,
    ) -> Result<CallToolResult, RpcError> {
        let Some(spec) = catalog::tool(name) else {
            return Err(RpcError::invalid_params(
                format!("unknown tool `{name}`"),
                None,
            ));
        };
        let args = Value::Object(arguments.unwrap_or_default());
        match self.dispatch(spec, args).await {
            Ok(data) => Ok(CallToolResult::structured(envelope::wrap(spec, data))),
            Err(err) => Ok(tool_error(name, &err)),
        }
    }

    async fn dispatch(&self, spec: &'static ToolSpec, args: Value) -> Result<Value, McpError> {
        match spec.name {
            // ---- Read ---------------------------------------------------------------------
            "live_stats" => {
                let _: catalog::NoArgs = parse(&args)?;
                let stats: LiveStats = self
                    .client
                    .request(method::LIVE_STATS_GET, &json!({}))
                    .await?;
                to_value(&stats)
            }
            "connections" => {
                let request: catalog::ConnectionsArgs = parse(&args)?;
                let request = ConnectionsRequest {
                    limit: request.limit,
                };
                let response: ConnectionsResponse = self
                    .client
                    .request(method::NETSTAT_CONNECTIONS, &request)
                    .await?;
                to_value(&response)
            }
            "top_remote_ips" => {
                let request: catalog::TopRemoteIpsArgs = parse(&args)?;
                let limit = request.limit.unwrap_or(10).clamp(1, 100) as usize;
                let stats: LiveStats = self
                    .client
                    .request(method::LIVE_STATS_GET, &json!({}))
                    .await?;
                let remote: Vec<_> = stats.top_remote.into_iter().take(limit).collect();
                to_value(&json!({ "remote": remote }))
            }
            "alerts" => {
                let request: catalog::AlertsArgs = parse(&args)?;
                let limit = request.limit.unwrap_or(200).clamp(1, 500) as usize;
                let list: AlertList = self.client.request(method::ALERTS_LIST, &json!({})).await?;
                let alerts: Vec<_> = list.alerts.into_iter().take(limit).collect();
                to_value(&json!({
                    "alerts": alerts,
                    "dropped": list.dropped,
                }))
            }
            "guardian_decisions" => {
                let request: catalog::DecisionsArgs = parse(&args)?;
                let limit = request.limit.unwrap_or(50).clamp(1, 500) as usize;
                let status: GuardianStatus = self
                    .client
                    .request(method::GUARDIAN_STATUS, &json!({}))
                    .await?;
                let decisions: Vec<_> = status.decisions.into_iter().take(limit).collect();
                to_value(&json!({
                    "decisions": decisions,
                    "circuit_open": status.circuit_open,
                    "would_block_24h": status.would_block_24h,
                }))
            }
            "captures_summary" => {
                let _: catalog::NoArgs = parse(&args)?;
                let status: CaptureStatus = self
                    .client
                    .request(method::CAPTURE_STATUS, &json!({}))
                    .await?;
                to_value(&status)
            }
            "mtr" => {
                let request: catalog::MtrArgs = parse(&args)?;
                let request: MtrStartRequest = request.to_proto();
                self.run_mtr(request).await
            }
            "ping" => {
                let request: catalog::PingArgs = parse(&args)?;
                let request: PingStartRequest = request.to_proto();
                self.run_ping(request).await
            }
            "dns_lookup" => {
                let request: catalog::DnsLookupArgs = parse(&args)?;
                let request: DnsLookupRequest = request.to_proto();
                let view = self
                    .client
                    .request::<_, pw_proto::DnsLookupView>(method::DIAG_DNS_LOOKUP, &request)
                    .await?;
                to_value(&view)
            }
            "port_check" => {
                let request: catalog::PortCheckArgs = parse(&args)?;
                let request: PortCheckRequest = request.to_proto();
                let view: PortCheckView = self
                    .client
                    .request(method::DIAG_PORT_CHECK, &request)
                    .await?;
                to_value(&view)
            }
            "ip_lookup" => {
                let request: catalog::IpLookupArgs = parse(&args)?;
                let request: GeoLookupRequest = request.to_proto();
                let result: GeoLookupResult =
                    self.client.request(method::INTEL_LOOKUP, &request).await?;
                to_value(&result)
            }
            "firewall_rules" => {
                let request: catalog::FirewallRulesArgs = parse(&args)?;
                let request: FirewallRulesRequest = request.to_proto();
                let rules: FirewallRules = self
                    .client
                    .request(method::FIREWALL_RULES, &request)
                    .await?;
                to_value(&rules)
            }
            "rdp_audit" => {
                let _: catalog::NoArgs = parse(&args)?;
                let audit = self
                    .client
                    .request::<_, pw_proto::RdpAudit>(method::RDP_AUDIT, &json!({}))
                    .await?;
                to_value(&audit)
            }
            "audit_log" => {
                let request: catalog::AuditLogArgs = parse(&args)?;
                let query: AuditQuery = request.to_proto();
                let view = self
                    .client
                    .request::<_, pw_proto::AuditView>(method::LOGS_AUDIT, &query)
                    .await?;
                to_value(&view)
            }
            "action_status" => {
                let request: catalog::ActionStatusArgs = parse(&args)?;
                let view: McpActionStatusView = self
                    .client
                    .request(method::MCP_ACTION_STATUS, &request.to_proto())
                    .await?;
                to_value(&view)
            }

            // ---- Execution, automatic allowed ---------------------------------------------
            "block_ip" => {
                let request: catalog::BlockIpArgs = parse(&args)?;
                let request = request.to_proto()?;
                let result: BlockResult = self
                    .client
                    .request(method::FIREWALL_BLOCK, &request)
                    .await?;
                to_value(&result)
            }
            "start_capture" => {
                let request: catalog::StartCaptureArgs = parse(&args)?;
                let request: RecordStartRequest = request.to_proto()?;
                let status: CaptureStatus = self
                    .client
                    .request(method::CAPTURE_RECORD_START, &request)
                    .await?;
                to_value(&status)
            }
            "speed_test" => {
                let request: catalog::SpeedTestArgs = parse(&args)?;
                let request: SpeedRequest = request.to_proto();
                self.run_speed(request).await
            }
            "support_bundle" => {
                let request: catalog::SupportBundleArgs = parse(&args)?;
                let request: SupportBundleRequest = request.to_proto()?;
                let info: SupportBundleInfo = self
                    .client
                    .request(method::SUPPORT_CREATE, &request)
                    .await?;
                // The manifest never carries `sample`: the AI gets names and sizes, never contents.
                let manifest: Vec<Value> = info
                    .items
                    .iter()
                    .map(|item| {
                        json!({
                            "name": item.name,
                            "description": item.description,
                            "bytes": item.bytes,
                        })
                    })
                    .collect();
                to_value(&json!({
                    "path": support_path(&info.name),
                    "manifest": manifest,
                    "id": info.id,
                    "bytes": info.bytes,
                }))
            }

            // ---- Execution, always approval ----------------------------------------------
            "unblock_ip" => {
                let request: catalog::UnblockIpArgs = parse(&args)?;
                let request: UnblockRequest = request.to_proto()?;
                self.approval_call(method::FIREWALL_UNBLOCK, &request).await
            }
            "set_guardian_mode" => {
                let request: catalog::SetGuardianModeArgs = parse(&args)?;
                let mode: GuardianMode = request.mode.into();
                // Read the current policy first and change ONLY the mode.
                let status: GuardianStatus = self
                    .client
                    .request(method::GUARDIAN_STATUS, &json!({}))
                    .await?;
                let mut policy = status.policy;
                policy.mode = mode;
                let update = SetGuardianPolicy {
                    policy,
                    // Switching to active needs the owner's confirmation; the desktop approval is it.
                    confirm_active: mode == GuardianMode::Active,
                };
                self.approval_call(method::GUARDIAN_SET_POLICY, &update)
                    .await
            }
            "create_firewall_rule" => {
                let request: catalog::CreateFirewallRuleArgs = parse(&args)?;
                let edit: FirewallRuleEdit = request.to_edit()?;
                self.approval_call(method::FIREWALL_RULE_ADD, &edit).await
            }
            "delete_firewall_rule" => {
                let request: catalog::DeleteFirewallRuleArgs = parse(&args)?;
                let action: FirewallRuleAction = request.to_proto()?;
                // Only PacketWard rules may be deleted: read the rules and check the group first.
                let rules: FirewallRules = self
                    .client
                    .request(
                        method::FIREWALL_RULES,
                        &FirewallRulesRequest {
                            text: Some(action.name.clone()),
                            ..FirewallRulesRequest::default()
                        },
                    )
                    .await?;
                let found = rules
                    .rules
                    .iter()
                    .find(|rule| rule.name.eq_ignore_ascii_case(&action.name));
                match found {
                    None => Err(McpError::Args(format!(
                        "no firewall rule named `{}`",
                        action.name
                    ))),
                    Some(rule) if rule.group != "PacketWard" => Err(McpError::Args(format!(
                        "rule `{}` belongs to group `{}`; only PacketWard rules can be deleted",
                        rule.name, rule.group
                    ))),
                    Some(_) => {
                        self.approval_call(method::FIREWALL_RULE_REMOVE, &action)
                            .await
                    }
                }
            }
            other => Err(McpError::Args(format!("tool `{other}` has no mapping"))),
        }
    }

    /// An approval-level action: the agent either queues it (and answers `pending`) or reports why it
    /// could not (switch off, rate limit, protected address).
    async fn approval_call<Req: Serialize>(
        &self,
        method_name: &str,
        request: &Req,
    ) -> Result<Value, McpError> {
        let view: McpActionStatusView = self.client.request(method_name, request).await?;
        match view.status {
            McpActionStatus::Pending => Ok(envelope::pending_approval(view.id)),
            McpActionStatus::Approved => Ok(view.result.unwrap_or(Value::Null)),
            McpActionStatus::Rejected => Err(McpError::Args(format!(
                "the owner rejected action {}",
                view.id
            ))),
            McpActionStatus::Expired => Err(McpError::Args(format!(
                "action {} expired before the owner approved it",
                view.id
            ))),
            McpActionStatus::Failed => Err(McpError::Job(
                view.error
                    .unwrap_or_else(|| format!("action {} failed", view.id)),
            )),
        }
    }

    async fn run_ping(&self, request: PingStartRequest) -> Result<Value, McpError> {
        let _job = self.job_lock.lock().await;
        let mut subscription = self.client.subscribe(topic::DIAG_PROGRESS).await?;
        let started: DiagStartResponse =
            match self.client.request(method::DIAG_PING_START, &request).await {
                Ok(started) => started,
                Err(err) => {
                    let _ = self.client.unsubscribe(topic::DIAG_PROGRESS).await;
                    return Err(err.into());
                }
            };
        let job_id = started.job_id;
        let outcome = tokio::time::timeout(PING_DEADLINE, async {
            while let Some(event) = subscription.recv_as::<DiagEvent>().await {
                match event {
                    DiagEvent::PingDone {
                        job_id: id,
                        summary,
                    } if id == job_id => {
                        return encode(&summary);
                    }
                    DiagEvent::Failed {
                        job_id: id,
                        message,
                    } if id == job_id => {
                        return Err(McpError::Job(message));
                    }
                    _ => {}
                }
            }
            Err(McpError::Job(
                "the agent closed the event stream".to_owned(),
            ))
        })
        .await;
        let _ = self.client.unsubscribe(topic::DIAG_PROGRESS).await;
        self.finish_diag(outcome, job_id).await
    }

    async fn run_mtr(&self, request: MtrStartRequest) -> Result<Value, McpError> {
        let _job = self.job_lock.lock().await;
        let mut subscription = self.client.subscribe(topic::DIAG_PROGRESS).await?;
        let started: DiagStartResponse =
            match self.client.request(method::DIAG_MTR_START, &request).await {
                Ok(started) => started,
                Err(err) => {
                    let _ = self.client.unsubscribe(topic::DIAG_PROGRESS).await;
                    return Err(err.into());
                }
            };
        let job_id = started.job_id;
        let outcome = tokio::time::timeout(MTR_DEADLINE, async {
            let mut last: Option<MtrView> = None;
            while let Some(event) = subscription.recv_as::<DiagEvent>().await {
                match event {
                    DiagEvent::MtrSnapshot {
                        job_id: id,
                        snapshot,
                    } if id == job_id => {
                        last = Some(snapshot);
                    }
                    DiagEvent::MtrDone {
                        job_id: id,
                        cancelled,
                    } if id == job_id => {
                        if cancelled {
                            return Err(McpError::Job("the trace was cancelled".to_owned()));
                        }
                        return match last {
                            Some(snapshot) => encode(&snapshot),
                            None => {
                                Err(McpError::Job("the trace returned no hop table".to_owned()))
                            }
                        };
                    }
                    DiagEvent::Failed {
                        job_id: id,
                        message,
                    } if id == job_id => {
                        return Err(McpError::Job(message));
                    }
                    _ => {}
                }
            }
            Err(McpError::Job(
                "the agent closed the event stream".to_owned(),
            ))
        })
        .await;
        let _ = self.client.unsubscribe(topic::DIAG_PROGRESS).await;
        self.finish_diag(outcome, job_id).await
    }

    async fn run_speed(&self, request: SpeedRequest) -> Result<Value, McpError> {
        let _job = self.job_lock.lock().await;
        let mut subscription = self.client.subscribe(topic::SPEED_PROGRESS).await?;
        let started: SpeedStarted = match self.client.request(method::SPEED_START, &request).await {
            Ok(started) => started,
            Err(err) => {
                let _ = self.client.unsubscribe(topic::SPEED_PROGRESS).await;
                return Err(err.into());
            }
        };
        let job_id = started.job_id;
        let outcome = tokio::time::timeout(SPEED_DEADLINE, async {
            while let Some(event) = subscription.recv_as::<SpeedEvent>().await {
                match event {
                    SpeedEvent::Done { job_id: id, result } if id == job_id => {
                        return encode(&*result);
                    }
                    SpeedEvent::Failed {
                        job_id: id,
                        code,
                        message,
                        ..
                    } if id == job_id => {
                        return Err(McpError::Job(format!("{code}: {message}")));
                    }
                    _ => {}
                }
            }
            Err(McpError::Job(
                "the agent closed the event stream".to_owned(),
            ))
        })
        .await;
        let _ = self.client.unsubscribe(topic::SPEED_PROGRESS).await;
        match outcome {
            Ok(result) => result,
            Err(_) => {
                let _ = self
                    .client
                    .request::<_, Value>(method::SPEED_CANCEL, &json!({ "job_id": job_id }))
                    .await;
                Err(McpError::Timeout)
            }
        }
    }

    /// A diag job that ran out of time is cancelled so the agent is not left probing.
    async fn finish_diag(
        &self,
        outcome: Result<Result<Value, McpError>, tokio::time::error::Elapsed>,
        job_id: u64,
    ) -> Result<Value, McpError> {
        match outcome {
            Ok(result) => result,
            Err(_) => {
                let _ = self
                    .client
                    .request::<_, Value>(method::DIAG_CANCEL, &DiagJobRequest { job_id })
                    .await;
                Err(McpError::Timeout)
            }
        }
    }
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new(
            "packetward-mcp",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions(
            "PacketWard network defense for this Windows Server. Read tools report live state; \
             execution tools are limited by the owner's MCP policy and the Guardian's protected set. \
             Approval-only tools return pending_approval: call action_status with the id for the outcome.",
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, RpcError> {
        Ok(self.list_tools_result())
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        catalog::tool(name).copied().map(tool_definition)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, RpcError> {
        Ok(self
            .call_tool_value(request.name.as_ref(), request.arguments)
            .await?
            .into())
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, RpcError> {
        Ok(self.list_prompts_result())
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, RpcError> {
        Ok(self
            .get_prompt_result(&request.name, request.arguments.as_ref())?
            .into())
    }
}

/// Serves the MCP protocol over stdin/stdout. The client must already be handshaken with the agent.
pub async fn serve(client: Client) -> Result<(), McpError> {
    let running = McpServer::new(client)
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|err| McpError::Transport(err.to_string()))?;
    running
        .waiting()
        .await
        .map_err(|err| McpError::Transport(err.to_string()))?;
    Ok(())
}

fn tool_definition(spec: ToolSpec) -> Tool {
    let schema = (spec.schema)();
    Tool::new(spec.name, spec.description(), Arc::new(schema))
}

fn parse<T: DeserializeOwned>(args: &Value) -> Result<T, McpError> {
    serde_json::from_value(args.clone()).map_err(|err| McpError::Args(err.to_string()))
}

fn encode<T: Serialize>(value: &T) -> Result<Value, McpError> {
    serde_json::to_value(value).map_err(|err| McpError::Encode(err.to_string()))
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, McpError> {
    encode(value)
}

fn tool_error(name: &str, err: &McpError) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(format!(
        "{name}: {}",
        err.message()
    ))])
}

/// Where the agent keeps the support zip (readable by administrators only, deleted after an hour).
fn support_path(name: &str) -> String {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_owned());
    format!("{base}\\PacketWard\\support\\{name}")
}

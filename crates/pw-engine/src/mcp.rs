// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! MCP enforcement inside the agent (ARCHITECTURE 6.14, milestone M11).
//!
//! `pwctl mcp` connects through the named pipe with `ClientKind::Mcp`; this module holds the
//! authoritative catalog, the policy (`mcp.json`), the rate limiters, the pending-approval queue
//! and the audit of every MCP call. Enforcement is here, not in `pwctl mcp`: a modified client hits
//! the same checks.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use pw_proto::{
    method, topic, BlockRequest, ErrorCode, ErrorPayload, FirewallRuleAction, FirewallRuleEdit,
    FirewallRulesRequest, GuardianMode, GuardianPolicy, McpActionStatus, McpActionStatusRequest,
    McpActionStatusView, McpPendingAction, McpPendingList, McpSettingsSetRequest, McpSettingsView,
    McpToolLevel, McpToolSetting, PayloadView, RecordModeView, RecordStartRequest,
    SetGuardianPolicy, SpeedKind, SpeedRequest, SupportBundleRequest, UnblockRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

use crate::defense::Defense;
use crate::Engine;

const FILE: &str = "mcp.json";
/// The default cap on execution tool calls per minute.
pub const DEFAULT_WRITE_LIMIT: u32 = 6;
pub const MIN_WRITE_LIMIT: u32 = 1;
pub const MAX_WRITE_LIMIT: u32 = 60;
/// Probe tools share this budget: MTR, ping, DNS lookup and port check all send traffic.
pub const PROBE_LIMIT_PER_MIN: u32 = 12;
/// A pending approval lives this long (5 minutes).
pub const APPROVAL_TTL_NS: u64 = 300 * 1_000_000_000;
/// Completed outcomes kept for `mcp.action.status` (nothing survives a restart).
pub const MAX_OUTCOMES: usize = 256;
/// `block_ip` may block for at most seven days.
pub const MAX_BLOCK_SECS: u64 = 7 * 24 * 60 * 60;
/// A capture started through MCP never runs longer than a minute.
pub const MAX_CAPTURE_SECS: u32 = 60;

const WINDOW_NS: u64 = 60 * 1_000_000_000;
const CHANGE_QUEUE: usize = 16;

/// Read tools and the IPC method each one is allowed to call.
pub const READ_TOOLS: [(&str, &str); 15] = [
    ("live_stats", method::LIVE_STATS_GET),
    ("connections", method::NETSTAT_CONNECTIONS),
    ("top_remote_ips", method::NETSTAT_CONNECTIONS),
    ("alerts", method::ALERTS_LIST),
    ("guardian_decisions", method::GUARDIAN_STATUS),
    ("captures_summary", method::CAPTURE_STATUS),
    ("mtr", method::DIAG_MTR_START),
    ("ping", method::DIAG_PING_START),
    ("dns_lookup", method::DIAG_DNS_LOOKUP),
    ("port_check", method::DIAG_PORT_CHECK),
    ("ip_lookup", method::INTEL_LOOKUP),
    ("firewall_rules", method::FIREWALL_RULES),
    ("rdp_audit", method::RDP_AUDIT),
    ("audit_log", method::LOGS_AUDIT),
    ("action_status", method::MCP_ACTION_STATUS),
];

/// Execution tools and the IPC method each one runs.
pub const EXECUTION_TOOLS: [(&str, &str); 8] = [
    ("block_ip", method::FIREWALL_BLOCK),
    ("start_capture", method::CAPTURE_RECORD_START),
    ("speed_test", method::SPEED_START),
    ("support_bundle", method::SUPPORT_CREATE),
    ("unblock_ip", method::FIREWALL_UNBLOCK),
    ("set_guardian_mode", method::GUARDIAN_SET_POLICY),
    ("create_firewall_rule", method::FIREWALL_RULE_ADD),
    ("delete_firewall_rule", method::FIREWALL_RULE_REMOVE),
];

/// Tools that can never run without the owner's approval.
pub const APPROVAL_ONLY_TOOLS: [&str; 4] = [
    "unblock_ip",
    "set_guardian_mode",
    "create_firewall_rule",
    "delete_firewall_rule",
];

/// Methods that send traffic and therefore share the probe limiter.
pub const PROBE_METHODS: [&str; 4] = [
    method::DIAG_MTR_START,
    method::DIAG_PING_START,
    method::DIAG_DNS_LOOKUP,
    method::DIAG_PORT_CHECK,
];

/// The only topics an MCP connection may subscribe to.
pub const MCP_TOPICS: [&str; 2] = [topic::DIAG_PROGRESS, topic::SPEED_PROGRESS];

pub fn read_tool_for(method_name: &str) -> Option<&'static str> {
    READ_TOOLS
        .iter()
        .find(|(_, allowed)| *allowed == method_name)
        .map(|(tool, _)| *tool)
}

pub fn execution_tool_for(method_name: &str) -> Option<&'static str> {
    EXECUTION_TOOLS
        .iter()
        .find(|(_, allowed)| *allowed == method_name)
        .map(|(tool, _)| *tool)
}

pub fn is_approval_only(tool: &str) -> bool {
    APPROVAL_ONLY_TOOLS.contains(&tool)
}

pub fn is_execution_tool(tool: &str) -> bool {
    EXECUTION_TOOLS.iter().any(|(name, _)| *name == tool)
}

pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn forbidden(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::Forbidden, message)
}

fn rate_limited(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::RateLimited, message)
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::BadRequest, message)
}

fn parse<T: serde::de::DeserializeOwned>(payload: Value) -> Result<T, ErrorPayload> {
    serde_json::from_value(payload)
        .map_err(|err| ErrorPayload::new(ErrorCode::BadRequest, err.to_string()))
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, ErrorPayload> {
    serde_json::to_value(value)
        .map_err(|err| ErrorPayload::new(ErrorCode::Internal, err.to_string()))
}

/// A bounded, control-character-free rendering of arguments for the audit log and the UI.
pub fn clip_text(text: &str, max_chars: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect()
}

fn args_summary(payload: &Value) -> String {
    if payload.is_null() {
        "-".to_owned()
    } else {
        clip_text(&payload.to_string(), 200)
    }
}

fn mode_name(mode: GuardianMode) -> &'static str {
    match mode {
        GuardianMode::Off => "off",
        GuardianMode::Monitor => "monitor",
        GuardianMode::Active => "active",
    }
}

/// The single audit path for every MCP call, reads and refusals included.
pub fn audit_call(
    defense: &Defense,
    action: &str,
    target: &str,
    outcome: &str,
    approval_id: Option<u64>,
) {
    let target = clip_text(target, 200);
    let mut detail = serde_json::json!({ "args": target, "outcome": outcome });
    if let Some(id) = approval_id {
        detail["approval_id"] = serde_json::json!(id);
    }
    let action = if action.is_empty() { "-" } else { action };
    defense.audit_entry("mcp", action, &target, &detail.to_string(), outcome);
}

// ---- policy --------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    enabled: bool,
    write_limit_per_min: u32,
    tools: Vec<McpToolSetting>,
}

impl Default for Saved {
    fn default() -> Self {
        Self {
            enabled: false,
            write_limit_per_min: DEFAULT_WRITE_LIMIT,
            tools: EXECUTION_TOOLS
                .iter()
                .map(|(tool, _)| McpToolSetting {
                    tool: (*tool).to_owned(),
                    level: McpToolLevel::Disabled,
                })
                .collect(),
        }
    }
}

/// Clamp the limit, drop unknown tools and fail closed on a hand-edited approval-only `automatic`.
fn normalize(mut saved: Saved) -> Saved {
    saved.write_limit_per_min = saved
        .write_limit_per_min
        .clamp(MIN_WRITE_LIMIT, MAX_WRITE_LIMIT);
    saved.tools = EXECUTION_TOOLS
        .iter()
        .map(|(tool, _)| {
            let mut level = saved
                .tools
                .iter()
                .rev()
                .find(|setting| setting.tool == *tool)
                .map_or(McpToolLevel::Disabled, |setting| setting.level);
            if level == McpToolLevel::Automatic && is_approval_only(tool) {
                level = McpToolLevel::Disabled;
            }
            McpToolSetting {
                tool: (*tool).to_owned(),
                level,
            }
        })
        .collect();
    saved
}

fn view_of(saved: &Saved) -> McpSettingsView {
    McpSettingsView {
        enabled: saved.enabled,
        write_limit_per_min: saved.write_limit_per_min,
        tools: saved.tools.clone(),
    }
}

fn load_policy(path: &Path) -> Saved {
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Saved>(&text) {
            Ok(saved) => normalize(saved),
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "the MCP policy is corrupt; using the safe defaults");
                Saved::default()
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Saved::default(),
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "the MCP policy cannot be read; using the safe defaults");
            Saved::default()
        }
    }
}

fn persist_policy(path: &Option<PathBuf>, saved: &Saved) -> Result<(), ErrorPayload> {
    let Some(path) = path else {
        return Ok(());
    };
    let bytes = serde_json::to_vec_pretty(saved)
        .map_err(|err| ErrorPayload::new(ErrorCode::Internal, err.to_string()))?;
    crate::settings::write_json_atomic(path, &bytes).map_err(|err| {
        ErrorPayload::new(
            ErrorCode::Internal,
            format!("could not save the MCP policy: {err}"),
        )
    })
}

struct PolicyStore {
    path: Option<PathBuf>,
    saved: Mutex<Saved>,
}

impl PolicyStore {
    fn open(dir: Option<&Path>) -> Self {
        let path = dir.map(|d| d.join(FILE));
        let saved = path.as_deref().map_or_else(Saved::default, load_policy);
        Self {
            path,
            saved: Mutex::new(saved),
        }
    }

    fn view(&self) -> McpSettingsView {
        view_of(&lock(&self.saved))
    }

    fn enabled(&self) -> bool {
        lock(&self.saved).enabled
    }

    fn write_limit(&self) -> u32 {
        lock(&self.saved).write_limit_per_min
    }

    fn level(&self, tool: &str) -> McpToolLevel {
        lock(&self.saved)
            .tools
            .iter()
            .find(|setting| setting.tool == tool)
            .map_or(McpToolLevel::Disabled, |setting| setting.level)
    }

    fn set(&self, request: &McpSettingsSetRequest) -> Result<McpSettingsView, ErrorPayload> {
        let mut saved = lock(&self.saved).clone();
        if let Some(enabled) = request.enabled {
            saved.enabled = enabled;
        }
        if let Some(limit) = request.write_limit_per_min {
            if !(MIN_WRITE_LIMIT..=MAX_WRITE_LIMIT).contains(&limit) {
                return Err(bad_request(format!(
                    "the write limit must be between {MIN_WRITE_LIMIT} and {MAX_WRITE_LIMIT} per minute"
                )));
            }
            saved.write_limit_per_min = limit;
        }
        if let Some(tools) = &request.tools {
            // Validate everything before anything is written.
            for setting in tools {
                if !is_execution_tool(&setting.tool) {
                    return Err(bad_request(format!(
                        "{:?} is not an MCP execution tool",
                        setting.tool
                    )));
                }
                if is_approval_only(&setting.tool) && setting.level == McpToolLevel::Automatic {
                    return Err(bad_request(format!(
                        "{} can only be disabled or require approval",
                        setting.tool
                    )));
                }
            }
            for setting in tools {
                if let Some(entry) = saved
                    .tools
                    .iter_mut()
                    .find(|entry| entry.tool == setting.tool)
                {
                    entry.level = setting.level;
                }
            }
        }
        let saved = normalize(saved);
        persist_policy(&self.path, &saved)?;
        *lock(&self.saved) = saved.clone();
        Ok(view_of(&saved))
    }
}

// ---- rate limiting -------------------------------------------------------------------------------

/// Sliding window over the last 60 seconds. Pure and clock-injected for deterministic tests.
pub struct SlidingWindow {
    events: VecDeque<u64>,
    window_ns: u64,
}

impl SlidingWindow {
    pub fn per_minute() -> Self {
        Self {
            events: VecDeque::new(),
            window_ns: WINDOW_NS,
        }
    }

    fn trim(&mut self, now_ns: u64) {
        while let Some(&at) = self.events.front() {
            if now_ns.saturating_sub(at) >= self.window_ns {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn allows(&mut self, now_ns: u64, limit: u32) -> bool {
        self.trim(now_ns);
        (self.events.len() as u32) < limit
    }

    pub fn check_and_record(&mut self, now_ns: u64, limit: u32) -> bool {
        if !self.allows(now_ns, limit) {
            return false;
        }
        self.events.push_back(now_ns);
        true
    }
}

// ---- pending approvals ---------------------------------------------------------------------------

/// In-memory approval queue plus the completed outcomes. Nothing survives a restart.
pub struct PendingQueue {
    next_id: u64,
    actions: Vec<McpPendingAction>,
    outcomes: VecDeque<McpActionStatusView>,
}

impl Default for PendingQueue {
    fn default() -> Self {
        Self {
            next_id: 1,
            actions: Vec::new(),
            outcomes: VecDeque::new(),
        }
    }
}

impl PendingQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(
        &mut self,
        tool: &str,
        args: Value,
        summary: String,
        now_ns: u64,
    ) -> McpPendingAction {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let action = McpPendingAction {
            id,
            tool: tool.to_owned(),
            args,
            summary,
            created_ts: now_ns,
            expires_ts: now_ns.saturating_add(APPROVAL_TTL_NS),
        };
        self.actions.push(action.clone());
        action
    }

    pub fn take(&mut self, id: u64) -> Option<McpPendingAction> {
        let index = self.actions.iter().position(|action| action.id == id)?;
        Some(self.actions.remove(index))
    }

    pub fn list(&self) -> McpPendingList {
        McpPendingList {
            actions: self.actions.clone(),
        }
    }

    fn record(&mut self, view: McpActionStatusView) {
        self.outcomes.push_back(view);
        while self.outcomes.len() > MAX_OUTCOMES {
            self.outcomes.pop_front();
        }
    }

    /// Removes and reports the entries whose five minutes are over.
    pub fn expire(&mut self, now_ns: u64) -> Vec<McpPendingAction> {
        let mut expired = Vec::new();
        let mut index = 0;
        while index < self.actions.len() {
            if self.actions[index].expires_ts <= now_ns {
                expired.push(self.actions.remove(index));
            } else {
                index += 1;
            }
        }
        for action in &expired {
            self.record(McpActionStatusView {
                id: action.id,
                status: McpActionStatus::Expired,
                result: None,
                error: None,
            });
        }
        expired
    }

    pub fn finish(&mut self, view: McpActionStatusView) {
        self.record(view);
    }

    pub fn status(&self, id: u64) -> Option<McpActionStatusView> {
        if self.actions.iter().any(|action| action.id == id) {
            return Some(McpActionStatusView {
                id,
                status: McpActionStatus::Pending,
                result: None,
                error: None,
            });
        }
        self.outcomes.iter().find(|view| view.id == id).cloned()
    }
}

// ---- the shared state ----------------------------------------------------------------------------

pub struct Mcp {
    policy: PolicyStore,
    writes: Mutex<SlidingWindow>,
    probes: Mutex<SlidingWindow>,
    pending: Mutex<PendingQueue>,
    changes: broadcast::Sender<McpPendingList>,
}

impl Mcp {
    /// `dir`: the agent data folder (`None`: policy in memory only, as in tests).
    pub fn open(dir: Option<&Path>) -> Self {
        let (changes, _) = broadcast::channel(CHANGE_QUEUE);
        Self {
            policy: PolicyStore::open(dir),
            writes: Mutex::new(SlidingWindow::per_minute()),
            probes: Mutex::new(SlidingWindow::per_minute()),
            pending: Mutex::new(PendingQueue::new()),
            changes,
        }
    }

    pub fn enabled(&self) -> bool {
        self.policy.enabled()
    }

    pub fn view(&self) -> McpSettingsView {
        self.policy.view()
    }

    pub fn level(&self, tool: &str) -> McpToolLevel {
        self.policy.level(tool)
    }

    pub fn set_settings(
        &self,
        request: &McpSettingsSetRequest,
    ) -> Result<McpSettingsView, ErrorPayload> {
        self.policy.set(request)
    }

    /// Would a write be allowed now, without counting it? Used before an action is queued.
    pub fn allows_write(&self, now_ns: u64) -> bool {
        lock(&self.writes).allows(now_ns, self.policy.write_limit())
    }

    /// Counts a write that is about to run; `false` when the minute's budget is spent.
    pub fn record_write(&self, now_ns: u64) -> bool {
        lock(&self.writes).check_and_record(now_ns, self.policy.write_limit())
    }

    /// Counts a probe (MTR, ping, DNS, port check); all four share one budget.
    pub fn record_probe(&self, now_ns: u64) -> bool {
        lock(&self.probes).check_and_record(now_ns, PROBE_LIMIT_PER_MIN)
    }

    pub fn enqueue(
        &self,
        tool: &str,
        args: Value,
        summary: String,
        now_ns: u64,
    ) -> McpPendingAction {
        let action = lock(&self.pending).enqueue(tool, args, summary, now_ns);
        self.publish();
        action
    }

    pub fn take_pending(&self, id: u64) -> Option<McpPendingAction> {
        lock(&self.pending).take(id)
    }

    pub fn reject(&self, id: u64) -> Option<McpPendingAction> {
        let action = lock(&self.pending).take(id)?;
        self.finish(McpActionStatusView {
            id,
            status: McpActionStatus::Rejected,
            result: None,
            error: None,
        });
        self.publish();
        Some(action)
    }

    pub fn finish(&self, view: McpActionStatusView) {
        lock(&self.pending).finish(view);
    }

    pub fn status(&self, id: u64) -> Option<McpActionStatusView> {
        lock(&self.pending).status(id)
    }

    pub fn pending_list(&self) -> McpPendingList {
        lock(&self.pending).list()
    }

    pub fn expire(&self, now_ns: u64) -> Vec<McpPendingAction> {
        let expired = lock(&self.pending).expire(now_ns);
        if !expired.is_empty() {
            self.publish();
        }
        expired
    }

    pub fn subscribe(&self) -> broadcast::Receiver<McpPendingList> {
        self.changes.subscribe()
    }

    /// Full snapshot on every change (create, approve, reject, expire).
    pub fn publish(&self) {
        let _ = self.changes.send(self.pending_list());
    }
}

/// Expires pending approvals every second. The UI is never told something is still waiting after
/// its five minutes are over.
pub async fn expiry_loop(mcp: Arc<Mcp>, defense: Arc<Defense>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        for action in mcp.expire(now_ns()) {
            audit_call(
                &defense,
                &action.tool,
                &action.summary,
                "expired",
                Some(action.id),
            );
        }
    }
}

// ---- tool argument guards ------------------------------------------------------------------------

/// MCP captures are always timed, headers-only and at most a minute.
pub fn forced_capture_request(mut request: RecordStartRequest) -> RecordStartRequest {
    request.mode = RecordModeView::Timed;
    request.duration_secs = Some(
        request
            .duration_secs
            .unwrap_or(MAX_CAPTURE_SECS)
            .clamp(1, MAX_CAPTURE_SECS),
    );
    request.payload = PayloadView::Headers;
    request.confirm_full_payload = false;
    request
}

fn ensure_speed_allowed(request: &SpeedRequest) -> Result<(), ErrorPayload> {
    if matches!(request.kind, SpeedKind::Bin10 | SpeedKind::Bin50) {
        return Err(forbidden(
            "MCP speed tests are limited to 1 GB; the 10 GB and 50 GB tests need the Speed Test page",
        ));
    }
    Ok(())
}

fn mode_of(payload: Value) -> Result<GuardianMode, ErrorPayload> {
    // `pwctl mcp` may send only the mode, or a whole `guardian.set_policy` payload.
    #[derive(Deserialize)]
    struct ModeOnly {
        mode: GuardianMode,
    }
    if let Ok(only) = serde_json::from_value::<ModeOnly>(payload.clone()) {
        return Ok(only.mode);
    }
    let request: SetGuardianPolicy = parse(payload)?;
    Ok(request.policy.mode)
}

fn validate_block(defense: &Defense, request: &BlockRequest) -> Result<(), ErrorPayload> {
    if request.targets.len() != 1 {
        return Err(bad_request("block_ip takes exactly one address"));
    }
    let ttl = request
        .ttl_secs
        .ok_or_else(|| bad_request("block_ip needs a duration (ttl_secs)"))?;
    if ttl == 0 || ttl > MAX_BLOCK_SECS {
        return Err(bad_request(format!(
            "the duration must be between 1 second and {MAX_BLOCK_SECS} seconds (7 days)"
        )));
    }
    let target = request.targets[0].trim();
    target
        .parse::<pw_core::Cidr>()
        .map_err(|_| bad_request(format!("{target:?} is not an IP address or CIDR block")))?;
    if let Some(reason) = defense.refusal_reason(target) {
        return Err(forbidden(format!(
            "{target} is protected ({reason}) and cannot be blocked"
        )));
    }
    Ok(())
}

/// The plain-words description shown in the approval banner. Also validates the arguments so a
/// malformed call never becomes a pending action.
fn pending_summary(tool: &str, payload: &Value) -> Result<String, ErrorPayload> {
    match tool {
        "block_ip" => {
            let request: BlockRequest = parse(payload.clone())?;
            let ttl = request
                .ttl_secs
                .ok_or_else(|| bad_request("block_ip needs a duration (ttl_secs)"))?;
            Ok(format!("Block {} for {ttl} s", request.targets.join(", ")))
        }
        "unblock_ip" => {
            let request: UnblockRequest = parse(payload.clone())?;
            if request.targets.is_empty() {
                return Err(bad_request("unblock_ip needs at least one address"));
            }
            Ok(format!("Unblock {}", request.targets.join(", ")))
        }
        "set_guardian_mode" => {
            let mode = mode_of(payload.clone())?;
            Ok(format!("Set the Guardian mode to {}", mode_name(mode)))
        }
        "create_firewall_rule" => {
            let edit: FirewallRuleEdit = parse(payload.clone())?;
            Ok(format!("Create the firewall rule {:?}", edit.rule.name))
        }
        "delete_firewall_rule" => {
            let action: FirewallRuleAction = parse(payload.clone())?;
            Ok(format!("Delete the firewall rule {:?}", action.name))
        }
        "start_capture" => {
            let request: RecordStartRequest = parse(payload.clone())?;
            let request = forced_capture_request(request);
            Ok(format!(
                "Record headers for up to {} s as {:?}",
                request.duration_secs.unwrap_or(MAX_CAPTURE_SECS),
                request.name
            ))
        }
        "speed_test" => {
            let request: SpeedRequest = parse(payload.clone())?;
            ensure_speed_allowed(&request)?;
            Ok(format!("Run a speed test ({:?})", request.kind))
        }
        "support_bundle" => {
            let request: SupportBundleRequest = parse(payload.clone())?;
            Ok(format!(
                "Build a local support bundle ({} s of headers, logs: {})",
                request.capture_secs, request.include_logs
            ))
        }
        other => Err(bad_request(format!(
            "{other:?} is not an MCP execution tool"
        ))),
    }
}

// ---- the engine gate -----------------------------------------------------------------------------

impl Engine {
    /// Every request from a `ClientKind::Mcp` connection passes through here.
    pub(crate) async fn handle_mcp(
        &self,
        method_name: &str,
        payload: Value,
    ) -> Result<Value, ErrorPayload> {
        let args = args_summary(&payload);
        if !self.mcp.enabled() {
            self.mcp_audit("-", &args, "refused", None);
            return Err(forbidden("the MCP server is switched off"));
        }
        if method_name == method::MCP_ACTION_STATUS {
            let result = self.action_status(payload);
            let outcome = if result.is_ok() { "ok" } else { "refused" };
            self.mcp_audit("action_status", &args, outcome, None);
            return result;
        }
        if let Some(tool) = read_tool_for(method_name) {
            if PROBE_METHODS.contains(&method_name) && !self.mcp.record_probe(now_ns()) {
                self.mcp_audit(tool, &args, "refused", None);
                return Err(rate_limited(
                    "the probe rate limit was reached; try again in a minute",
                ));
            }
            let result = self.dispatch(method_name, payload).await;
            let outcome = if result.is_ok() { "ok" } else { "failed" };
            self.mcp_audit(tool, &args, outcome, None);
            return result;
        }
        let Some(tool) = execution_tool_for(method_name) else {
            self.mcp_audit("-", &args, "refused", None);
            return Err(forbidden(format!(
                "`{method_name}` is not available through MCP"
            )));
        };
        match self.mcp.level(tool) {
            McpToolLevel::Disabled => {
                self.mcp_audit(tool, &args, "refused", None);
                Err(forbidden(format!("the MCP tool {tool} is disabled")))
            }
            McpToolLevel::Approval => {
                if !self.mcp.allows_write(now_ns()) {
                    self.mcp_audit(tool, &args, "refused", None);
                    return Err(rate_limited(
                        "the MCP write limit was reached; the action was not queued",
                    ));
                }
                let summary = match pending_summary(tool, &payload) {
                    Ok(summary) => summary,
                    Err(err) => {
                        self.mcp_audit(tool, &args, "refused", None);
                        return Err(err);
                    }
                };
                // The protected set is checked before anything is queued: a refused block never
                // becomes a pending approval.
                let precheck = match tool {
                    "block_ip" => parse::<BlockRequest>(payload.clone())
                        .and_then(|request| validate_block(&self.defense, &request)),
                    _ => Ok(()),
                };
                if let Err(err) = precheck {
                    self.mcp_audit(tool, &args, "refused", None);
                    return Err(err);
                }
                let action = self.mcp.enqueue(tool, payload, summary, now_ns());
                self.mcp_audit(tool, &action.summary, "pending", Some(action.id));
                to_value(&McpActionStatusView {
                    id: action.id,
                    status: McpActionStatus::Pending,
                    result: None,
                    error: None,
                })
            }
            McpToolLevel::Automatic => {
                if !self.mcp.record_write(now_ns()) {
                    self.mcp_audit(tool, &args, "refused", None);
                    return Err(rate_limited(
                        "the MCP write limit was reached; try again in a minute",
                    ));
                }
                let result = self.run_mcp_tool(tool, payload).await;
                let outcome = if result.is_ok() { "ok" } else { "failed" };
                self.mcp_audit(tool, &args, outcome, None);
                result
            }
        }
    }

    /// Topics for a `ClientKind::Mcp` connection: the switch, then the two allowed progress feeds.
    pub(crate) async fn subscribe_mcp(
        &self,
        topic_name: &str,
    ) -> Result<crate::EventReceiver, ErrorPayload> {
        if !self.mcp.enabled() {
            self.mcp_audit("subscribe", topic_name, "refused", None);
            return Err(forbidden("the MCP server is switched off"));
        }
        if !MCP_TOPICS.contains(&topic_name) {
            self.mcp_audit("subscribe", topic_name, "refused", None);
            return Err(forbidden(format!(
                "`{topic_name}` is not available through MCP"
            )));
        }
        let result = self.dispatch_subscribe(topic_name).await;
        let outcome = if result.is_ok() { "ok" } else { "failed" };
        self.mcp_audit("subscribe", topic_name, outcome, None);
        result
    }

    /// Desktop/`pwctl` only: runs a pending action now, after re-checking the safety rules.
    pub(crate) async fn approve_mcp_action(&self, id: u64) -> Result<Value, ErrorPayload> {
        let Some(action) = self.mcp.take_pending(id) else {
            return Err(bad_request(format!("there is no pending MCP action {id}")));
        };
        if let Some(reason) = self.pending_refusal(&action) {
            self.finish_failed(&action, &reason);
            return Err(forbidden(reason));
        }
        if !self.mcp.record_write(now_ns()) {
            let reason = "the MCP write limit was reached; nothing was run".to_owned();
            self.finish_failed(&action, &reason);
            return Err(rate_limited(reason));
        }
        let result = self.run_mcp_tool(&action.tool, action.args.clone()).await;
        match &result {
            Ok(value) => {
                self.mcp.finish(McpActionStatusView {
                    id,
                    status: McpActionStatus::Approved,
                    result: Some(value.clone()),
                    error: None,
                });
                self.mcp_audit(&action.tool, &action.summary, "approved", Some(id));
            }
            Err(err) => {
                self.mcp.finish(McpActionStatusView {
                    id,
                    status: McpActionStatus::Failed,
                    result: None,
                    error: Some(err.message.clone()),
                });
                self.mcp_audit(&action.tool, &action.summary, "failed", Some(id));
            }
        }
        self.mcp.publish();
        result
    }

    /// Desktop/`pwctl` only.
    pub(crate) fn reject_mcp_action(&self, id: u64) -> Result<Value, ErrorPayload> {
        let Some(action) = self.mcp.reject(id) else {
            return Err(bad_request(format!("there is no pending MCP action {id}")));
        };
        self.mcp_audit(&action.tool, &action.summary, "rejected", Some(id));
        Ok(Value::Null)
    }

    pub(crate) fn action_status(&self, payload: Value) -> Result<Value, ErrorPayload> {
        let request: McpActionStatusRequest = parse(payload)?;
        let view = self
            .mcp
            .status(request.id)
            .ok_or_else(|| bad_request(format!("there is no MCP action {}", request.id)))?;
        to_value(&view)
    }

    fn pending_refusal(&self, action: &McpPendingAction) -> Option<String> {
        if action.tool != "block_ip" {
            return None;
        }
        let request: BlockRequest = serde_json::from_value(action.args.clone()).ok()?;
        let target = request.targets.first()?.trim().to_owned();
        self.defense
            .refusal_reason(&target)
            .map(|reason| format!("{target} is protected ({reason}) and cannot be blocked"))
    }

    fn finish_failed(&self, action: &McpPendingAction, reason: &str) {
        self.mcp.finish(McpActionStatusView {
            id: action.id,
            status: McpActionStatus::Failed,
            result: None,
            error: Some(reason.to_owned()),
        });
        self.mcp.publish();
        self.mcp_audit(&action.tool, &action.summary, "failed", Some(action.id));
    }

    fn mcp_audit(&self, action: &str, target: &str, outcome: &str, approval_id: Option<u64>) {
        audit_call(&self.defense, action, target, outcome, approval_id);
    }

    async fn run_mcp_tool(&self, tool: &str, payload: Value) -> Result<Value, ErrorPayload> {
        match tool {
            "block_ip" => {
                let request: BlockRequest = parse(payload)?;
                validate_block(&self.defense, &request)?;
                let defense = Arc::clone(&self.defense);
                let result = crate::blocking(move || defense.block(&request, "mcp")).await?;
                if result.blocked.is_empty() {
                    if let Some(refusal) = result.refused_protected.first() {
                        return Err(forbidden(format!(
                            "{} is protected ({}); nothing was blocked",
                            refusal.target, refusal.reason
                        )));
                    }
                    if let Some(target) = result.refused_broad.first() {
                        return Err(bad_request(format!("{target} is too wide to block")));
                    }
                }
                to_value(&result)
            }
            "unblock_ip" => {
                let request: UnblockRequest = parse(payload)?;
                if request.targets.is_empty() {
                    return Err(bad_request("unblock_ip needs at least one address"));
                }
                let defense = Arc::clone(&self.defense);
                crate::blocking(move || defense.unblock(&request.targets, "mcp"))
                    .await
                    .and_then(|list| to_value(&list))
            }
            "set_guardian_mode" => {
                let mode = mode_of(payload)?;
                // Only the mode changes; the rest of the policy stays as the owner set it.
                let policy = GuardianPolicy {
                    mode,
                    ..self.defense.policy()
                };
                let request = SetGuardianPolicy {
                    policy,
                    // The desktop approval is the explicit confirmation of an Active switch.
                    confirm_active: true,
                };
                let defense = Arc::clone(&self.defense);
                let status = crate::blocking(move || defense.set_policy(&request, "mcp")).await?;
                self.detection
                    .set_preset(crate::preset_of(status.policy.preset));
                to_value(&status)
            }
            "create_firewall_rule" => {
                let mut edit: FirewallRuleEdit = parse(payload)?;
                // The AI cannot create rules outside PacketWard's group.
                edit.rule.group = pw_firewall::GROUP.to_owned();
                edit.rule.managed = true;
                edit.allow_foreign_edit = false;
                let defense = Arc::clone(&self.defense);
                crate::blocking(move || defense.add_rule(&edit, "mcp")).await?;
                Ok(Value::Null)
            }
            "delete_firewall_rule" => {
                let action: FirewallRuleAction = parse(payload)?;
                let request = FirewallRulesRequest {
                    text: Some(action.name.clone()),
                    managed_only: true,
                    ..FirewallRulesRequest::default()
                };
                let defense = Arc::clone(&self.defense);
                let rules = crate::blocking(move || defense.rules(&request)).await?;
                if !rules
                    .rules
                    .iter()
                    .any(|rule| rule.name == action.name && rule.managed)
                {
                    return Err(forbidden(format!(
                        "{:?} is not a PacketWard rule; MCP can only delete rules in that group",
                        action.name
                    )));
                }
                let defense = Arc::clone(&self.defense);
                crate::blocking(move || defense.remove_rule(&action, "mcp")).await?;
                Ok(Value::Null)
            }
            "start_capture" => {
                let request: RecordStartRequest = parse(payload)?;
                let request = forced_capture_request(request);
                self.capture.record_start(request).await?;
                to_value(&self.capture.status())
            }
            "speed_test" => {
                let request: SpeedRequest = parse(payload)?;
                ensure_speed_allowed(&request)?;
                to_value(&self.speed.start(request)?)
            }
            "support_bundle" => {
                let request: SupportBundleRequest = parse(payload)?;
                // The result is the manifest and the local id; the contents are never exposed.
                let info = self
                    .support
                    .create(self.support_inputs(), request, &self.capture)
                    .await?;
                to_value(&info)
            }
            other => Err(bad_request(format!(
                "{other:?} is not an MCP execution tool"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_is_off_and_every_tool_disabled() {
        let mcp = Mcp::open(None);
        let view = mcp.view();
        assert!(!view.enabled);
        assert_eq!(view.write_limit_per_min, DEFAULT_WRITE_LIMIT);
        assert_eq!(view.tools.len(), EXECUTION_TOOLS.len());
        assert!(view
            .tools
            .iter()
            .all(|tool| tool.level == McpToolLevel::Disabled));
    }

    #[test]
    fn approval_only_tools_can_never_be_automatic_and_unknown_tools_are_refused() {
        let mcp = Mcp::open(None);
        let err = mcp
            .set_settings(&McpSettingsSetRequest {
                enabled: None,
                write_limit_per_min: None,
                tools: Some(vec![McpToolSetting {
                    tool: "unblock_ip".into(),
                    level: McpToolLevel::Automatic,
                }]),
            })
            .err()
            .unwrap();
        assert_eq!(err.code, ErrorCode::BadRequest);
        let err = mcp
            .set_settings(&McpSettingsSetRequest {
                enabled: None,
                write_limit_per_min: None,
                tools: Some(vec![McpToolSetting {
                    tool: "firewall_purge".into(),
                    level: McpToolLevel::Automatic,
                }]),
            })
            .err()
            .unwrap();
        assert_eq!(err.code, ErrorCode::BadRequest);
        for limit in [0, 61] {
            let err = mcp
                .set_settings(&McpSettingsSetRequest {
                    enabled: None,
                    write_limit_per_min: Some(limit),
                    tools: None,
                })
                .err()
                .unwrap();
            assert_eq!(err.code, ErrorCode::BadRequest, "limit {limit}");
        }
    }

    #[test]
    fn the_policy_round_trips_and_a_corrupt_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mcp = Mcp::open(Some(dir.path()));
        mcp.set_settings(&McpSettingsSetRequest {
            enabled: Some(true),
            write_limit_per_min: Some(12),
            tools: Some(vec![McpToolSetting {
                tool: "block_ip".into(),
                level: McpToolLevel::Approval,
            }]),
        })
        .unwrap();
        let reloaded = Mcp::open(Some(dir.path()));
        assert!(reloaded.enabled());
        assert_eq!(reloaded.view().write_limit_per_min, 12);
        assert_eq!(reloaded.level("block_ip"), McpToolLevel::Approval);
        assert_eq!(reloaded.level("unblock_ip"), McpToolLevel::Disabled);

        std::fs::write(dir.path().join(FILE), "{ not json").unwrap();
        let corrupt = Mcp::open(Some(dir.path()));
        assert!(!corrupt.enabled());
        assert_eq!(corrupt.view().write_limit_per_min, DEFAULT_WRITE_LIMIT);
        assert!(corrupt
            .view()
            .tools
            .iter()
            .all(|tool| tool.level == McpToolLevel::Disabled));
    }

    #[test]
    fn a_hand_edited_automatic_approval_tool_is_demoted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(FILE),
            r#"{"enabled":true,"write_limit_per_min":6,"tools":[{"tool":"unblock_ip","level":"automatic"}]}"#,
        )
        .unwrap();
        let mcp = Mcp::open(Some(dir.path()));
        assert_eq!(mcp.level("unblock_ip"), McpToolLevel::Disabled);
    }

    #[test]
    fn the_write_window_counts_sixty_seconds() {
        let mut window = SlidingWindow::per_minute();
        let t0 = 1_000_000_000_000_000_000;
        for i in 0..6 {
            assert!(window.check_and_record(t0 + i, 6), "call {i}");
        }
        assert!(!window.check_and_record(t0 + 10, 6));
        assert!(!window.allows(t0 + WINDOW_NS - 1, 6));
        assert!(window.allows(t0 + WINDOW_NS, 6), "the oldest slot expired");
        assert!(window.check_and_record(t0 + WINDOW_NS, 6));
    }

    #[test]
    fn pending_ids_are_monotonic_and_expiry_is_five_minutes() {
        let mut queue = PendingQueue::new();
        let t0 = 500_000;
        let first = queue.enqueue("unblock_ip", Value::Null, "one".into(), t0);
        let second = queue.enqueue("unblock_ip", Value::Null, "two".into(), t0);
        assert_eq!((first.id, second.id), (1, 2));
        assert_eq!(first.expires_ts, t0 + APPROVAL_TTL_NS);
        assert!(queue.expire(t0 + APPROVAL_TTL_NS - 1).is_empty());
        let expired = queue.expire(t0 + APPROVAL_TTL_NS);
        assert_eq!(expired.len(), 2);
        assert!(queue.list().actions.is_empty());
        assert_eq!(
            queue.status(1).map(|view| view.status),
            Some(McpActionStatus::Expired)
        );
        // The next id keeps counting.
        let third = queue.enqueue("unblock_ip", Value::Null, "three".into(), t0);
        assert_eq!(third.id, 3);
    }

    #[test]
    fn only_the_newest_two_hundred_and_fifty_six_outcomes_are_kept() {
        let mut queue = PendingQueue::new();
        for id in 1..=MAX_OUTCOMES as u64 + 10 {
            queue.finish(McpActionStatusView {
                id,
                status: McpActionStatus::Rejected,
                result: None,
                error: None,
            });
        }
        assert!(queue.status(1).is_none());
        assert!(queue.status(10).is_none());
        assert!(queue.status(11).is_some());
    }

    #[test]
    fn mcp_captures_are_forced_to_timed_headers_only_and_at_most_a_minute() {
        let request = RecordStartRequest {
            name: "ai".into(),
            mode: RecordModeView::Ring,
            duration_secs: Some(3600),
            filter: None,
            payload: PayloadView::Full,
            confirm_full_payload: true,
        };
        let forced = forced_capture_request(request);
        assert_eq!(forced.mode, RecordModeView::Timed);
        assert_eq!(forced.duration_secs, Some(MAX_CAPTURE_SECS));
        assert_eq!(forced.payload, PayloadView::Headers);
        assert!(!forced.confirm_full_payload);

        let mut short = forced.clone();
        short.duration_secs = Some(5);
        assert_eq!(forced_capture_request(short).duration_secs, Some(5));
        let mut none = forced;
        none.duration_secs = None;
        assert_eq!(
            forced_capture_request(none).duration_secs,
            Some(MAX_CAPTURE_SECS)
        );
    }

    #[test]
    fn only_bin_tests_of_at_most_one_gigabyte_are_allowed() {
        let request = |kind| SpeedRequest {
            kind,
            servers: Vec::new(),
            streams: None,
            provider: None,
            duration_secs: None,
            confirm_large: false,
        };
        assert!(ensure_speed_allowed(&request(SpeedKind::Quick)).is_ok());
        assert!(ensure_speed_allowed(&request(SpeedKind::Bin1)).is_ok());
        assert!(ensure_speed_allowed(&request(SpeedKind::Bin10)).is_err());
        assert!(ensure_speed_allowed(&request(SpeedKind::Bin50)).is_err());
    }
}

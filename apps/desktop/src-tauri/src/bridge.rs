// SPDX-License-Identifier: GPL-3.0-or-later
//! Connection to the agent: a supervisor task that keeps (re)connecting to the pipe and tells the
//! webview what is going on, plus the elevated Start/Repair action.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pw_ipc::access::{self, AccessProblem};
use pw_ipc::pipe::{self, PIPE_NAME};
use pw_ipc::scm::{self, AgentService};
use pw_ipc::{Client, ClientError};
use pw_proto::{
    method, topic, AccessReason, AgentConnection, BridgeEvent, ClientKind, ConnectionsRequest,
    ConnectionsResponse, DiagEvent, ElevatedAction, ElevationOutcome, ErrorCode, Heartbeat,
    LiveStats,
};
use tauri::ipc::Channel;
use tauri::{AppHandle, State};

use crate::sys::windows::{run_elevated_and_wait, Elevated};

const RETRY_EVERY: Duration = Duration::from_secs(2);
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const AGENT_EXE: &str = "packetward-agent.exe";

/// The live connection to the agent, shared with the commands that make requests.
type ClientSlot = Arc<Mutex<Option<Client>>>;

/// Holds the running supervisor so a reloaded webview replaces it instead of adding another.
#[derive(Default)]
pub struct Bridge {
    watcher: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    client: ClientSlot,
}

/// Starts watching the agent. Events arrive on `on_event` until the webview goes away.
#[tauri::command]
pub fn agent_watch(bridge: State<'_, Bridge>, on_event: Channel<BridgeEvent>) {
    let task = tauri::async_runtime::spawn(supervise(on_event, Arc::clone(&bridge.client)));
    let mut slot = bridge.watcher.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(previous) = slot.replace(task) {
        previous.abort();
    }
}

/// Emits only when the status changed. Returns `false` once the webview is gone.
struct Emitter {
    channel: Channel<BridgeEvent>,
    last: Option<AgentConnection>,
}

impl Emitter {
    fn status(&mut self, status: AgentConnection) -> bool {
        if self.last.as_ref() == Some(&status) {
            return true;
        }
        self.last = Some(status.clone());
        self.channel.send(BridgeEvent::Status(status)).is_ok()
    }

    fn heartbeat(&self, beat: Heartbeat) -> bool {
        self.channel.send(BridgeEvent::Heartbeat(beat)).is_ok()
    }

    fn stats(&self, stats: LiveStats) -> bool {
        self.channel.send(BridgeEvent::Stats(stats)).is_ok()
    }

    fn diag(&self, event: DiagEvent) -> bool {
        self.channel.send(BridgeEvent::Diag(event)).is_ok()
    }
}

async fn supervise(channel: Channel<BridgeEvent>, slot: ClientSlot) {
    let mut out = Emitter {
        channel,
        last: None,
    };
    if !out.status(AgentConnection::Connecting) {
        return;
    }
    loop {
        let status = match pipe::connect(PIPE_NAME).await {
            Ok(stream) => match Client::connect(stream, ClientKind::Desktop, APP_VERSION).await {
                Ok(client) => {
                    if !run_connected(client, &mut out, &slot).await {
                        return;
                    }
                    // Connection ended: re-probe straight away to learn why.
                    AgentConnection::Connecting
                }
                Err(ClientError::AgentOutdated(agent)) => AgentConnection::AgentOutdated {
                    agent_version: agent.agent_version,
                },
                Err(ClientError::ClientOutdated(agent)) => AgentConnection::UiOutdated {
                    agent_version: agent.agent_version,
                },
                Err(err) => AgentConnection::Error {
                    message: err.to_string(),
                },
            },
            Err(err) => classify_connect_error(err.kind(), &err.to_string()).await,
        };
        if !out.status(status) {
            return;
        }
        tokio::time::sleep(RETRY_EVERY).await;
    }
}

/// Clears the shared client when a connection ends, however it ends.
struct SlotGuard<'a>(&'a ClientSlot);

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Serves one live connection. Returns `false` when the webview is gone.
async fn run_connected(client: Client, out: &mut Emitter, slot: &ClientSlot) -> bool {
    let agent = client.agent().clone();
    let mut heartbeats = match client.subscribe(topic::LIVE_HEARTBEAT).await {
        Ok(subscription) => subscription,
        Err(err) => {
            tracing::warn!(%err, "could not subscribe to the heartbeat");
            return true;
        }
    };
    // Older agents do not publish live.stats; the app then simply has no traffic data.
    let mut stats = match client.subscribe(topic::LIVE_STATS).await {
        Ok(subscription) => Some(subscription),
        Err(err) => {
            tracing::info!(%err, "the agent does not publish live.stats");
            None
        }
    };
    // Progress of ping/MTR jobs; older agents do not have it and the app then has no diagnostics.
    let mut diag = match client.subscribe(topic::DIAG_PROGRESS).await {
        Ok(subscription) => Some(subscription),
        Err(err) => {
            tracing::info!(%err, "the agent does not publish diag.progress");
            None
        }
    };
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(client.clone());
    let _clear_on_exit = SlotGuard(slot);

    let connected = AgentConnection::Connected {
        agent_version: agent.agent_version,
        protocol_major: agent.protocol_major,
        protocol_minor: agent.protocol_minor,
    };
    if !out.status(connected) {
        return false;
    }
    loop {
        tokio::select! {
            beat = heartbeats.recv_as::<Heartbeat>() => match beat {
                Some(beat) => {
                    if !out.heartbeat(beat) {
                        return false;
                    }
                }
                None => return true,
            },
            snapshot = next_stats(&mut stats) => match snapshot {
                Some(snapshot) => {
                    if !out.stats(snapshot) {
                        return false;
                    }
                }
                None => return true,
            },
            event = next_diag(&mut diag) => match event {
                Some(event) => {
                    if !out.diag(event) {
                        return false;
                    }
                }
                None => return true,
            },
            () = client.closed() => return true,
        }
    }
}

/// The next `live.stats` event; never completes when the agent offers none.
async fn next_stats(subscription: &mut Option<pw_ipc::Subscription>) -> Option<LiveStats> {
    match subscription {
        Some(subscription) => subscription.recv_as::<LiveStats>().await,
        None => std::future::pending().await,
    }
}

/// The next `diag.progress` event; never completes when the agent offers none.
async fn next_diag(subscription: &mut Option<pw_ipc::Subscription>) -> Option<DiagEvent> {
    match subscription {
        Some(subscription) => subscription.recv_as::<DiagEvent>().await,
        None => std::future::pending().await,
    }
}

/// Methods the webview may call through `agent_call`. Everything else needs its own typed command, so
/// a compromised page cannot reach agent methods nobody meant to expose to it.
const CALLABLE_METHODS: &[&str] = &[
    method::DIAG_PING_START,
    method::DIAG_MTR_START,
    method::DIAG_CANCEL,
    method::DIAG_MTR_REPORT,
    method::DIAG_DNS_LOOKUP,
    method::DIAG_PORT_CHECK,
    method::DIAG_PORTS_LOCAL,
];

fn is_callable(method_name: &str) -> bool {
    CALLABLE_METHODS.contains(&method_name)
}

/// A request to an allowlisted agent method. Errors are strings the UI maps: `not_connected`,
/// `unsupported` (older agent), `forbidden`, or `<code>: <message>` from the agent.
#[tauri::command]
pub async fn agent_call(
    bridge: State<'_, Bridge>,
    method: String,
    payload: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    if !is_callable(&method) {
        return Err("forbidden".to_owned());
    }
    let client = bridge
        .client
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or_else(|| "not_connected".to_owned())?;
    client
        .request(&method, &payload.unwrap_or(serde_json::Value::Null))
        .await
        .map_err(|err| match err {
            ClientError::Remote(remote) if remote.code == ErrorCode::UnknownMethod => {
                "unsupported".to_owned()
            }
            ClientError::Remote(remote) => format!("{:?}: {}", remote.code, remote.message),
            other => other.to_string(),
        })
}

/// The agent's connection table (capped on the agent side). Called while the Connections page is
/// open. `"unsupported"` means the agent is older than this app and cannot provide it.
#[tauri::command]
pub async fn agent_connections(
    bridge: State<'_, Bridge>,
    limit: Option<u32>,
) -> Result<ConnectionsResponse, String> {
    let client = bridge
        .client
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or_else(|| "not_connected".to_owned())?;
    client
        .request(method::NETSTAT_CONNECTIONS, &ConnectionsRequest { limit })
        .await
        .map_err(|err| match err {
            ClientError::Remote(remote) if remote.code == ErrorCode::UnknownMethod => {
                "unsupported".to_owned()
            }
            other => other.to_string(),
        })
}

/// Works out why the pipe could not be opened.
async fn classify_connect_error(kind: std::io::ErrorKind, message: &str) -> AgentConnection {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::NotFound => {
            let service = tauri::async_runtime::spawn_blocking(scm::agent_service).await;
            match service {
                Ok(Ok(AgentService::NotInstalled)) => AgentConnection::NotInstalled,
                Ok(Ok(AgentService::Stopped | AgentService::Stopping)) => AgentConnection::Stopped,
                Ok(Ok(AgentService::Starting)) => AgentConnection::Starting,
                Ok(Ok(AgentService::Running)) => AgentConnection::Error {
                    message: "the service is running but its pipe is not available".to_owned(),
                },
                Ok(Err(err)) => AgentConnection::Error {
                    message: format!("could not query the service: {err}"),
                },
                Err(err) => AgentConnection::Error {
                    message: err.to_string(),
                },
            }
        }
        ErrorKind::PermissionDenied => {
            match tauri::async_runtime::spawn_blocking(access::diagnose).await {
                Ok(Ok(problem)) => AgentConnection::AccessDenied {
                    reason: match problem {
                        AccessProblem::GroupMissing => AccessReason::GroupMissing,
                        AccessProblem::NotMember => AccessReason::NotMember,
                        AccessProblem::SignOutRequired => AccessReason::SignOutRequired,
                        AccessProblem::Unexplained => AccessReason::Unexplained,
                    },
                },
                _ => AgentConnection::AccessDenied {
                    reason: AccessReason::Unexplained,
                },
            }
        }
        _ => AgentConnection::Error {
            message: message.to_owned(),
        },
    }
}

/// Runs `packetward-agent start|repair` with administrator rights (UAC prompt).
#[tauri::command]
pub async fn agent_elevate(_app: AppHandle, action: ElevatedAction) -> ElevationOutcome {
    let job = tauri::async_runtime::spawn_blocking(move || elevate(action)).await;
    match job {
        Ok(outcome) => outcome,
        Err(err) => ElevationOutcome::Failed {
            message: err.to_string(),
        },
    }
}

fn elevate(action: ElevatedAction) -> ElevationOutcome {
    let exe = match std::env::current_exe() {
        Ok(path) => path.with_file_name(AGENT_EXE),
        Err(err) => {
            return ElevationOutcome::Failed {
                message: err.to_string(),
            }
        }
    };
    if !exe.is_file() {
        return ElevationOutcome::Failed {
            message: format!(
                "{AGENT_EXE} was not found next to the app ({})",
                exe.display()
            ),
        };
    }
    let args = match action {
        ElevatedAction::Start => "start".to_owned(),
        // Pass this user's SID so the group gets the person using the app, not whichever
        // administrator account approved the UAC prompt.
        ElevatedAction::Repair => match access::current_user_sid() {
            Ok(sid) => format!("repair --operator-sid {sid}"),
            Err(err) => {
                return ElevationOutcome::Failed {
                    message: format!("could not determine your Windows user: {err}"),
                }
            }
        },
    };
    match run_elevated_and_wait(&exe, &args) {
        Ok(Elevated::Exited(0)) => ElevationOutcome::Done,
        Ok(Elevated::Exited(code)) => ElevationOutcome::Failed {
            message: format!("the agent command exited with code {code}"),
        },
        Ok(Elevated::Cancelled) => ElevationOutcome::Cancelled,
        Err(err) => ElevationOutcome::Failed {
            message: err.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_diagnostics_methods_are_callable_from_the_webview() {
        for allowed in CALLABLE_METHODS {
            assert!(allowed.starts_with("diag."), "{allowed}");
            assert!(is_callable(allowed));
        }
        for blocked in [
            method::SYSTEM_INFO,
            method::HELLO,
            method::SUBSCRIBE,
            "firewall.block",
            "",
        ] {
            assert!(!is_callable(blocked), "{blocked:?}");
        }
    }
}

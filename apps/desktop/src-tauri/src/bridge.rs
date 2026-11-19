// SPDX-License-Identifier: GPL-3.0-or-later
//! Connection to the agent: a supervisor task that keeps (re)connecting to the pipe and tells the
//! webview what is going on, plus the elevated Start/Repair action.

use std::sync::Mutex;
use std::time::Duration;

use pw_ipc::access::{self, AccessProblem};
use pw_ipc::pipe::{self, PIPE_NAME};
use pw_ipc::scm::{self, AgentService};
use pw_ipc::{Client, ClientError};
use pw_proto::{
    topic, AccessReason, AgentConnection, BridgeEvent, ClientKind, ElevatedAction,
    ElevationOutcome, Heartbeat,
};
use tauri::ipc::Channel;
use tauri::{AppHandle, State};

use crate::sys::windows::{run_elevated_and_wait, Elevated};

const RETRY_EVERY: Duration = Duration::from_secs(2);
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const AGENT_EXE: &str = "packetward-agent.exe";

/// Holds the running supervisor so a reloaded webview replaces it instead of adding another.
#[derive(Default)]
pub struct Bridge {
    watcher: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

/// Starts watching the agent. Events arrive on `on_event` until the webview goes away.
#[tauri::command]
pub fn agent_watch(bridge: State<'_, Bridge>, on_event: Channel<BridgeEvent>) {
    let task = tauri::async_runtime::spawn(supervise(on_event));
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
}

async fn supervise(channel: Channel<BridgeEvent>) {
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
                    if !run_connected(client, &mut out).await {
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

/// Serves one live connection. Returns `false` when the webview is gone.
async fn run_connected(client: Client, out: &mut Emitter) -> bool {
    let agent = client.agent().clone();
    let mut heartbeats = match client.subscribe(topic::LIVE_HEARTBEAT).await {
        Ok(subscription) => subscription,
        Err(err) => {
            tracing::warn!(%err, "could not subscribe to the heartbeat");
            return true;
        }
    };
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
            () = client.closed() => return true,
        }
    }
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

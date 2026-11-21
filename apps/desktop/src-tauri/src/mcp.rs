// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Settings → MCP: where the installed `pwctl.exe` is and whether `pwctl mcp` starts.
//!
//! The MCP policy itself lives in the agent (`mcp.settings.get/set`); the shell only answers the two
//! questions the page cannot: the path of the binary next to this app (for the client configuration
//! snippets) and a live smoke test of that binary. The smoke test closes stdin at once, which is how
//! a real client ends the session, and expects the server to exit cleanly.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

/// The CLI installed next to `PacketWard.exe` by the installer.
const PWCTL_EXE: &str = "pwctl.exe";
/// How long the smoke test waits for the server to exit after its stdin closes.
const CHECK_TIMEOUT: Duration = Duration::from_secs(8);
/// Poll interval while waiting for the child.
const POLL_EVERY: Duration = Duration::from_millis(50);
/// Windows `CREATE_NO_WINDOW`: a console window must never flash in front of the user.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Where the installer put `pwctl.exe` for this copy of the app.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpInstallInfo {
    /// Absolute path of `pwctl.exe`, whether or not it exists.
    pub path: String,
    pub exists: bool,
}

/// How the smoke test ended; the page turns each one into a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckOutcome {
    /// The server started and exited with code 0.
    Ok,
    /// `pwctl.exe` is not next to the app.
    Missing,
    /// The server was still running after [`CHECK_TIMEOUT`] and was killed.
    Timeout,
    /// The process could not be created at all.
    Spawn,
    /// The server exited with a non-zero code.
    Exit,
}

/// Result of `mcp_self_check`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpSelfCheck {
    pub ok: bool,
    pub path: String,
    pub outcome: CheckOutcome,
    /// Exit code, spawn error or the server's last stderr line; empty when `outcome` is `ok`.
    pub detail: String,
}

fn pwctl_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    Ok(exe.with_file_name(PWCTL_EXE))
}

/// The path the page puts in the client snippets.
#[tauri::command]
pub fn mcp_install_info() -> McpInstallInfo {
    match pwctl_path() {
        Ok(path) => McpInstallInfo {
            exists: path.is_file(),
            path: path.display().to_string(),
        },
        Err(_) => McpInstallInfo {
            exists: false,
            path: String::new(),
        },
    }
}

/// Runs `pwctl mcp` with stdin closed and reports how it ended.
#[tauri::command]
pub async fn mcp_self_check() -> McpSelfCheck {
    match tauri::async_runtime::spawn_blocking(run_self_check).await {
        Ok(check) => check,
        Err(err) => McpSelfCheck {
            ok: false,
            path: String::new(),
            outcome: CheckOutcome::Spawn,
            detail: err.to_string(),
        },
    }
}

fn run_self_check() -> McpSelfCheck {
    let path = match pwctl_path() {
        Ok(path) => path,
        Err(err) => {
            return McpSelfCheck {
                ok: false,
                path: String::new(),
                outcome: CheckOutcome::Spawn,
                detail: err,
            };
        }
    };
    let shown = path.display().to_string();
    if !path.is_file() {
        return McpSelfCheck {
            ok: false,
            path: shown,
            outcome: CheckOutcome::Missing,
            detail: String::new(),
        };
    }

    let mut command = Command::new(&path);
    command
        .arg("mcp")
        // A real client closes the session by closing stdin; stdout carries JSON-RPC and is not
        // read here, and stderr is small (diagnostics only).
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return McpSelfCheck {
                ok: false,
                path: shown,
                outcome: CheckOutcome::Spawn,
                detail: err.to_string(),
            };
        }
    };

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stderr = child
                    .stderr
                    .take()
                    .map(|mut pipe| {
                        let mut text = String::new();
                        let _ = pipe.read_to_string(&mut text);
                        last_line(&text)
                    })
                    .unwrap_or_default();
                return if status.success() {
                    McpSelfCheck {
                        ok: true,
                        path: shown,
                        outcome: CheckOutcome::Ok,
                        detail: String::new(),
                    }
                } else {
                    let code = status
                        .code()
                        .map_or_else(|| "?".to_owned(), |code| code.to_string());
                    McpSelfCheck {
                        ok: false,
                        path: shown,
                        outcome: CheckOutcome::Exit,
                        detail: if stderr.is_empty() {
                            code
                        } else {
                            format!("{code}: {stderr}")
                        },
                    }
                };
            }
            Ok(None) if started.elapsed() >= CHECK_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return McpSelfCheck {
                    ok: false,
                    path: shown,
                    outcome: CheckOutcome::Timeout,
                    detail: String::new(),
                };
            }
            Ok(None) => std::thread::sleep(POLL_EVERY),
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return McpSelfCheck {
                    ok: false,
                    path: shown,
                    outcome: CheckOutcome::Spawn,
                    detail: err.to_string(),
                };
            }
        }
    }
}

/// Last non-empty line of a diagnostic, clipped so it fits in the UI.
fn last_line(text: &str) -> String {
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("");
    line.chars().take(300).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_line_skips_trailing_blanks_and_clips() {
        assert_eq!(last_line("a\nb\n\n"), "b");
        assert_eq!(last_line(""), "");
        assert_eq!(last_line("only"), "only");
        let long = "x".repeat(400);
        assert_eq!(last_line(&long).chars().count(), 300);
    }
}

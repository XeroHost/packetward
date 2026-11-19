// SPDX-License-Identifier: GPL-3.0-or-later
//! PacketWard desktop shell (Tauri 2). Runs unelevated; the agent service owns privileged work.

// Hide the console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bridge;
mod prefs;
mod sys;

use tauri::Manager;

use prefs::{PrefsError, UiPrefs};

fn prefs_file(app: &tauri::AppHandle) -> Result<std::path::PathBuf, PrefsError> {
    prefs::prefs_path(app.path().config_dir().ok())
}

#[tauri::command]
fn ui_prefs_load(app: tauri::AppHandle) -> UiPrefs {
    match prefs_file(&app) {
        Ok(path) => prefs::load_from(&path),
        Err(err) => {
            tracing::warn!(%err, "no preferences path; using defaults");
            UiPrefs::default()
        }
    }
}

#[tauri::command]
fn ui_prefs_save(app: tauri::AppHandle, prefs: UiPrefs) -> Result<(), PrefsError> {
    prefs::save_to(&prefs_file(&app)?, &prefs)
}

/// OS display locale (e.g. "es-MX"), used on first run to pick the UI language.
#[tauri::command]
fn system_locale() -> Option<String> {
    sys_locale::get_locale()
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(bridge::Bridge::default())
        .invoke_handler(tauri::generate_handler![
            ui_prefs_load,
            ui_prefs_save,
            system_locale,
            bridge::agent_watch,
            bridge::agent_elevate
        ])
        .run(tauri::generate_context!())
        .map_err(|err| {
            tracing::error!(%err, "tauri runtime failed");
            err
        })?;
    Ok(())
}

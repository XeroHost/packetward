// SPDX-License-Identifier: GPL-3.0-or-later
//! PacketWard desktop shell (Tauri 2). Runs unelevated; the agent service owns privileged work.

// Hide the console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bridge;
mod prefs;
mod sys;
mod tray;

use tauri::{Manager, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};

use prefs::{Language, PrefsError, UiPrefs};

/// Passed by the autostart entry so the app opens straight into the tray.
const MINIMIZED_FLAG: &str = "--minimized";

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

/// Whether the UI starts (minimized to the tray) when this user signs in to Windows.
#[tauri::command]
fn autostart_state(app: tauri::AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|err| err.to_string())
}

#[tauri::command]
fn autostart_set(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let launcher = app.autolaunch();
    if enabled {
        launcher.enable()
    } else {
        launcher.disable()
    }
    .map_err(|err| err.to_string())
}

/// Whether the window can currently be seen (not hidden to the tray, not minimized).
#[tauri::command]
fn window_visible() -> bool {
    tray::is_visible()
}

/// Keeps the tray menu in the language the user picked.
#[tauri::command]
fn tray_set_locale(app: tauri::AppHandle, locale: String) -> Result<(), String> {
    tray::set_locale(&app, &locale).map_err(|err| err.to_string())
}

/// Shows what is going on in the tray icon (a coloured badge) and its tooltip.
#[tauri::command]
fn tray_set_state(
    app: tauri::AppHandle,
    state: tray::TrayState,
    tooltip: String,
) -> Result<(), String> {
    tray::set_state(&app, state, &tooltip).map_err(|err| err.to_string())
}

/// Pops up a Windows notification. The UI decides which alerts deserve one (the user's severity
/// settings); this process is the one that can show it, the agent service cannot.
#[tauri::command]
fn notify_alert(app: tauri::AppHandle, title: String, body: String) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;
    app.notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|err| err.to_string())
}

fn startup_locale(app: &tauri::AppHandle) -> &'static str {
    let saved = prefs_file(app)
        .map(|path| prefs::load_from(&path).language)
        .unwrap_or(Language::Auto);
    match saved {
        Language::En => "en",
        Language::Es => "es",
        Language::PtBr => "pt-BR",
        Language::Auto => tray::detect_locale(sys_locale::get_locale().as_deref()),
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    tauri::Builder::default()
        // Must be first: a second launch just brings the existing window forward.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main_window(app);
        }))
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![MINIMIZED_FLAG]),
        ))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .manage(bridge::Bridge::default())
        .invoke_handler(tauri::generate_handler![
            ui_prefs_load,
            ui_prefs_save,
            system_locale,
            autostart_state,
            autostart_set,
            tray_set_locale,
            window_visible,
            bridge::agent_watch,
            bridge::agent_connections,
            bridge::agent_call,
            bridge::support_bundle_save,
            tray_set_state,
            notify_alert,
            bridge::agent_elevate
        ])
        .setup(|app| {
            let handle = app.handle();
            tray::init(handle, startup_locale(handle))?;
            // The window is created hidden (see tauri.conf.json) so a minimized start never flashes.
            if std::env::args().any(|arg| arg == MINIMIZED_FLAG) {
                tray::announce_visibility(handle, false);
            } else {
                tray::show_main_window(handle);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it to the tray; "Quit" in the tray menu really exits.
            match event {
                WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    let _ = window.hide();
                    tray::announce_visibility(window.app_handle(), false);
                }
                // Minimizing and restoring both resize the window.
                WindowEvent::Resized(_) => {
                    let minimized = window.is_minimized().unwrap_or(false);
                    let shown = window.is_visible().unwrap_or(true);
                    tray::announce_visibility(window.app_handle(), shown && !minimized);
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .map_err(|err| {
            tracing::error!(%err, "tauri runtime failed");
            err
        })?;
    Ok(())
}

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! PacketWard desktop shell (Tauri 2). Runs unelevated; the agent service owns privileged work.

// Hide the console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bridge;
mod mcp;
mod prefs;
mod sys;
mod tray;
mod updater;

use std::sync::{Arc, Mutex, Once};
use tauri::{Emitter, Manager, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};

use prefs::{Language, PrefsError, UiPrefs};

/// Passed by the autostart entry so the app opens straight into the tray.
const MINIMIZED_FLAG: &str = "--minimized";
/// Event the webview listens for when the user clicks the MCP approval notification.
const MCP_PENDING_OPEN: &str = "mcp-pending-open";
/// Identifier of the notification that announces a pending MCP approval.
const MCP_NOTIFICATION_ID: i32 = 7_100;

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

/// Whether the window got the Mica backdrop. Mica needs Windows 11 (build 22000+) with transparency
/// effects switched on; Windows Server 2019/2022 and Windows 10 keep the solid token background.
struct Backdrop(bool);

/// "mica" when the window backdrop is the system material, "solid" otherwise.
#[tauri::command]
fn window_backdrop(state: tauri::State<'_, Backdrop>) -> &'static str {
    if state.0 {
        "mica"
    } else {
        "solid"
    }
}

fn apply_backdrop(app: &tauri::App) -> bool {
    use tauri::window::{Effect, EffectsBuilder};
    if !sys::windows::transparency_enabled() {
        return false;
    }
    let Some(window) = app.get_webview_window("main") else {
        return false;
    };
    window
        .set_effects(EffectsBuilder::new().effect(Effect::Mica).build())
        .is_ok()
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

/// The notification that asks the owner to approve an MCP action. A click brings the window back
/// and tells the UI to open the approval dialog (ARCHITECTURE 6.14).
#[derive(Clone, Default)]
struct ApprovalToast {
    /// The click handler is registered once; the plugin cannot remove one.
    installed: Arc<Once>,
    /// The identifier of the notification on screen, so clicks on alert notifications are ignored.
    last_id: Arc<Mutex<Option<i32>>>,
}

#[tauri::command]
fn notify_action_request(
    app: tauri::AppHandle,
    toast: tauri::State<'_, ApprovalToast>,
    title: String,
    body: String,
) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;
    *toast.last_id.lock().unwrap_or_else(|err| err.into_inner()) = Some(MCP_NOTIFICATION_ID);
    let last_id = Arc::clone(&toast.last_id);
    let handle = app.clone();
    let installer = app.clone();
    toast.installed.call_once(move || {
        let registered = installer.notification().on_action(move |action| {
            if action.action_id() != "tap" {
                return;
            }
            let shown = action.notification().map(|notification| notification.id());
            if shown.is_none() || shown != *last_id.lock().unwrap_or_else(|err| err.into_inner()) {
                return;
            }
            tray::show_main_window(&handle);
            let _ = handle.emit(MCP_PENDING_OPEN, ());
        });
        if let Err(err) = registered {
            tracing::warn!(%err, "could not listen for notification clicks");
        }
    });
    app.notification()
        .builder()
        .id(MCP_NOTIFICATION_ID)
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

    let context = tauri::generate_context!();

    let builder = tauri::Builder::default()
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
        .manage(ApprovalToast::default());
    // The updater plugin is only registered with a valid public key; see updater.rs.
    updater::register(builder, context.config())
        .invoke_handler(tauri::generate_handler![
            ui_prefs_load,
            ui_prefs_save,
            system_locale,
            autostart_state,
            autostart_set,
            tray_set_locale,
            window_visible,
            window_backdrop,
            bridge::agent_watch,
            bridge::agent_connections,
            bridge::agent_call,
            bridge::support_bundle_save,
            tray_set_state,
            notify_alert,
            notify_action_request,
            bridge::agent_elevate,
            mcp::mcp_install_info,
            mcp::mcp_self_check,
            updater::update_info,
            updater::update_check,
            updater::update_install
        ])
        .setup(|app| {
            let handle = app.handle();
            app.manage(Backdrop(apply_backdrop(app)));
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
        .run(context)
        .map_err(|err| {
            tracing::error!(%err, "tauri runtime failed");
            err
        })?;
    Ok(())
}

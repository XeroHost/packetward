// SPDX-License-Identifier: GPL-3.0-or-later
//! System tray icon and the "close hides to tray" behaviour.
//!
//! The desktop app is a viewer: closing the window hides it, and quitting the UI leaves the agent
//! (which does the actual protecting) running.

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

const TRAY_ID: &str = "main";
const MAIN_WINDOW: &str = "main";
const OPEN_ID: &str = "open";
const QUIT_ID: &str = "quit";

struct Labels {
    open: &'static str,
    quit: &'static str,
}

fn labels(locale: &str) -> Labels {
    match locale {
        "es" => Labels {
            open: "Abrir PacketWard",
            quit: "Salir (el agente sigue activo)",
        },
        "pt-BR" => Labels {
            open: "Abrir o PacketWard",
            quit: "Sair (o agente continua ativo)",
        },
        _ => Labels {
            open: "Open PacketWard",
            quit: "Quit (the agent keeps running)",
        },
    }
}

fn menu(app: &AppHandle, locale: &str) -> tauri::Result<Menu<tauri::Wry>> {
    let text = labels(locale);
    let open = MenuItem::with_id(app, OPEN_ID, text.open, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, QUIT_ID, text.quit, true, None::<&str>)?;
    Menu::with_items(app, &[&open, &quit])
}

/// Brings the main window back (from the tray or from a second launch).
pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub fn init(app: &AppHandle, locale: &str) -> tauri::Result<()> {
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("PacketWard")
        .menu(&menu(app, locale)?)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            OPEN_ID => show_main_window(app),
            QUIT_ID => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

/// Re-labels the tray menu when the user changes the interface language.
pub fn set_locale(app: &AppHandle, locale: &str) -> tauri::Result<()> {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        tray.set_menu(Some(menu(app, locale)?))?;
    }
    Ok(())
}

/// Same rule as the UI (`src/app/locale.ts`): `es-*` is Spanish, `pt-*` is Brazilian Portuguese,
/// anything else English.
pub fn detect_locale(tag: Option<&str>) -> &'static str {
    let lower = tag
        .unwrap_or_default()
        .to_ascii_lowercase()
        .replace('_', "-");
    let language = lower.split('-').next().unwrap_or_default();
    match language {
        "es" => "es",
        "pt" => "pt-BR",
        _ => "en",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_like_the_ui() {
        for (tag, expected) in [
            (Some("es-MX"), "es"),
            (Some("ES-ar"), "es"),
            (Some("pt-PT"), "pt-BR"),
            (Some("pt_BR"), "pt-BR"),
            (Some("en-US"), "en"),
            (Some("de-DE"), "en"),
            (Some(""), "en"),
            (None, "en"),
        ] {
            assert_eq!(detect_locale(tag), expected, "{tag:?}");
        }
    }

    #[test]
    fn labels_exist_for_every_language() {
        for locale in ["en", "es", "pt-BR", "unknown"] {
            let text = labels(locale);
            assert!(!text.open.is_empty() && !text.quit.is_empty());
        }
    }
}

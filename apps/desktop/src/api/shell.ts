// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Window-shell features owned by the desktop process: start-at-sign-in and the tray menu.
// This module is the only place that talks to Tauri for them.
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { isTauri } from './uiPrefs'

/** Whether the UI starts (minimized to the tray) when this Windows user signs in. */
export async function getAutostart(): Promise<boolean> {
  if (!isTauri()) return false
  return invoke<boolean>('autostart_state')
}

export async function setAutostart(enabled: boolean): Promise<void> {
  if (!isTauri()) return
  await invoke('autostart_set', { enabled })
}

/** Keeps the tray menu in the language of the UI. Failures are not worth bothering the user. */
export async function setTrayLocale(locale: string): Promise<void> {
  if (!isTauri()) return
  try {
    await invoke('tray_set_locale', { locale })
  } catch (err) {
    console.warn('Could not update the tray menu language', err)
  }
}

export type TrayState = 'neutral' | 'warning' | 'alert'

/** Shows the machine's state in the tray icon (a coloured badge) and its tooltip. */
export async function setTrayState(state: TrayState, tooltip: string): Promise<void> {
  if (!isTauri()) return
  try {
    await invoke('tray_set_state', { state, tooltip })
  } catch (err) {
    console.warn('Could not update the tray icon', err)
  }
}

/** A Windows notification. Failures (notifications disabled in Windows) are not worth a dialog. */
export async function notifyAlert(title: string, body: string): Promise<void> {
  if (!isTauri()) return
  try {
    await invoke('notify_alert', { title, body })
  } catch (err) {
    console.warn('Could not show the notification', err)
  }
}

/** Whether the native window can currently be seen (not hidden to the tray, not minimized). */
export async function getWindowVisible(): Promise<boolean> {
  if (!isTauri()) return true
  try {
    return await invoke<boolean>('window_visible')
  } catch {
    return true
  }
}

/**
 * Calls `onChange` whenever the native window is hidden, shown or minimized. The webview's own
 * `document.visibilityState` does not follow those changes, so the shell announces them.
 * Returns a function that stops listening.
 */
export async function watchWindowVisible(
  onChange: (visible: boolean) => void,
): Promise<() => void> {
  if (!isTauri()) return () => {}
  return listen<boolean>('window-visibility', (event) => onChange(event.payload))
}

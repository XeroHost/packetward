// SPDX-License-Identifier: GPL-3.0-or-later
// Window-shell features owned by the desktop process: start-at-sign-in and the tray menu.
// This module is the only place that talks to Tauri for them.
import { invoke } from '@tauri-apps/api/core'
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

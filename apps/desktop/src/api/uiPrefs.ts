// SPDX-License-Identifier: GPL-3.0-or-later
// Typed wrappers for the per-user UI preferences stored by the desktop shell
// (%AppData%\PacketWard\ui.json). This module is the only place that talks to Tauri.
import { invoke } from '@tauri-apps/api/core'

export type ThemeSetting = 'dark' | 'light' | 'system'
export type MonoFont = 'jetbrains' | 'geist' | 'system'
export type Density = 'comfortable' | 'compact'
export type TextSize = 90 | 100 | 110 | 125
export type LanguageSetting = 'auto' | 'en' | 'es' | 'pt-BR'

export interface AppearancePrefs {
  theme: ThemeSetting
  monoFont: MonoFont
  density: Density
  textSize: TextSize
  reduceMotion: boolean
}

/** Which alert severities pop up a Windows notification (alerts always appear in the inbox). */
export interface NotificationPrefs {
  critical: boolean
  high: boolean
  medium: boolean
  low: boolean
}

export type UpdateChannel = 'stable' | 'beta'

/**
 * Update preferences. `checkOnStart` (on by default) looks for a new version when the app opens and
 * every 24 hours; it only looks, nothing is ever downloaded or installed without the user pressing the
 * button. The switch in Settings turns it off.
 */
export interface UpdatePrefs {
  channel: UpdateChannel
  checkOnStart: boolean
}

export interface UiPrefs {
  version: 1
  language: LanguageSetting
  appearance: AppearancePrefs
  notifications: NotificationPrefs
  updates: UpdatePrefs
}

export const DEFAULT_NOTIFICATIONS: NotificationPrefs = {
  critical: true,
  high: true,
  medium: false,
  low: false,
}

export const DEFAULT_UPDATES: UpdatePrefs = { channel: 'stable', checkOnStart: true }

export const DEFAULT_UI_PREFS: UiPrefs = {
  version: 1,
  language: 'auto',
  appearance: {
    theme: 'dark',
    monoFont: 'jetbrains',
    density: 'comfortable',
    textSize: 100,
    reduceMotion: false,
  },
  notifications: { ...DEFAULT_NOTIFICATIONS },
  updates: { ...DEFAULT_UPDATES },
}

/** True when running inside the Tauri webview (false in plain browsers and unit tests). */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
}

export async function loadUiPrefs(): Promise<UiPrefs> {
  if (!isTauri()) return structuredClone(DEFAULT_UI_PREFS)
  try {
    return await invoke<UiPrefs>('ui_prefs_load')
  } catch {
    return structuredClone(DEFAULT_UI_PREFS)
  }
}

export async function saveUiPrefs(prefs: UiPrefs): Promise<void> {
  if (!isTauri()) return
  await invoke('ui_prefs_save', { prefs })
}

/** OS locale tag as reported by the Rust side (`sys-locale`), e.g. "es-MX". */
export async function systemLocale(): Promise<string | null> {
  if (!isTauri()) return typeof navigator === 'undefined' ? null : navigator.language
  try {
    return await invoke<string | null>('system_locale')
  } catch {
    return null
  }
}

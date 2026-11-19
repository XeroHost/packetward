// SPDX-License-Identifier: GPL-3.0-or-later
// Typed wrappers for the updater commands of the desktop shell (src-tauri/src/updater.rs).
// This module is the only place that talks to Tauri for updates. Keep both sides in sync.
import { Channel, invoke } from '@tauri-apps/api/core'
import { isTauri, type UpdateChannel } from './uiPrefs'

export type { UpdateChannel }

/** What the Settings page can show without touching the network. */
export interface UpdateInfo {
  currentVersion: string
  /** False when the build has no updater public key: every update feature is off. */
  configured: boolean
}

export type UpdateCheck =
  | { state: 'notConfigured' }
  | { state: 'upToDate'; currentVersion: string }
  | {
      state: 'available'
      currentVersion: string
      version: string
      notes: string | null
      /** RFC 3339 when the release metadata carries it. */
      date: string | null
    }

export type InstallEvent =
  { event: 'progress'; downloaded: number; total: number | null } | { event: 'installing' }

/** Version string reported while running in a plain browser (no shell, no updater). */
export const PREVIEW_VERSION = 'browser-preview'

export async function getUpdateInfo(): Promise<UpdateInfo> {
  if (!isTauri()) return { currentVersion: PREVIEW_VERSION, configured: false }
  return invoke<UpdateInfo>('update_info')
}

/** Asks the channel's manifest whether a newer version exists. Rejects with a message on failure. */
export async function checkForUpdate(channel: UpdateChannel): Promise<UpdateCheck> {
  if (!isTauri()) return { state: 'notConfigured' }
  return invoke<UpdateCheck>('update_check', { channel })
}

/**
 * Downloads the update found by the last check, verifies its signature and starts the installer.
 * On Windows the app exits when the installer starts, so this usually does not resolve.
 */
export async function installUpdate(onEvent: (event: InstallEvent) => void): Promise<void> {
  if (!isTauri()) return
  const channel = new Channel<InstallEvent>()
  channel.onmessage = onEvent
  await invoke('update_install', { onEvent: channel })
}

// SPDX-License-Identifier: GPL-3.0-or-later
// The window itself: the app draws its own title bar, so minimize/maximize/close come from here.
// Outside Tauri (browser, Vitest) every call is a no-op.
import { invoke } from '@tauri-apps/api/core'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { isTauri } from './uiPrefs'

export type Backdrop = 'mica' | 'solid'

/** Whether the window got the system Mica material (Windows 11) or keeps the solid background. */
export async function windowBackdrop(): Promise<Backdrop> {
  if (!isTauri()) return 'solid'
  try {
    return await invoke<Backdrop>('window_backdrop')
  } catch {
    return 'solid'
  }
}

/**
 * Tells Windows which theme this window is in. The Mica material and the system caption colours follow
 * the window theme, not the page: without this, the light theme on a dark system keeps a black window
 * (title bar, sidebar) behind the light panel.
 */
export async function setWindowTheme(theme: 'light' | 'dark'): Promise<void> {
  if (!isTauri()) return
  try {
    await getCurrentWindow().setTheme(theme)
  } catch {
    // The page theme still applies; only the system material keeps the OS colours.
  }
}

export async function minimizeWindow(): Promise<void> {
  if (isTauri()) await getCurrentWindow().minimize()
}

export async function toggleMaximizeWindow(): Promise<void> {
  if (isTauri()) await getCurrentWindow().toggleMaximize()
}

/** Closing the window hides it to the tray (the shell decides); "Quit" in the tray exits. */
export async function closeWindow(): Promise<void> {
  if (isTauri()) await getCurrentWindow().close()
}

export async function isWindowMaximized(): Promise<boolean> {
  return isTauri() ? getCurrentWindow().isMaximized() : false
}

/** Calls `handler` whenever the window is resized (maximize/restore included). Returns the unsubscribe. */
export async function onWindowResized(handler: () => void): Promise<() => void> {
  if (!isTauri()) return () => {}
  return getCurrentWindow().onResized(handler)
}

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { openUrl } from '@tauri-apps/plugin-opener'
import { isTauri } from './uiPrefs'

export const XEROHOST_URL = 'https://xerohost.net'

/** Opens an https URL in the user's default browser. */
export async function openExternal(url: string): Promise<void> {
  if (isTauri()) {
    await openUrl(url)
  } else {
    window.open(url, '_blank', 'noopener,noreferrer')
  }
}

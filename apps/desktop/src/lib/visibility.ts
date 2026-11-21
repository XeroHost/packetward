// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { useDocumentVisibility } from '@vueuse/core'
import { computed, ref, type ComputedRef } from 'vue'
import { getWindowVisible, watchWindowVisible } from '@/api/shell'

/** What the shell says about the native window; true until it tells us otherwise. */
const nativeVisible = ref(true)
let started = false

/**
 * Starts following the native window (tray hide, minimize). Call once at start-up. Safe to call
 * again; the browser preview and tests have no shell, so everything stays visible there.
 */
export async function startWindowVisibility(): Promise<void> {
  if (started) return
  started = true
  nativeVisible.value = await getWindowVisible()
  await watchWindowVisible((visible) => {
    nativeVisible.value = visible
  })
}

/**
 * True while the user can actually see the window. Combines the document's own visibility (a
 * background browser tab) with the native window state (hidden to the tray, minimized): drawing
 * charts or polling data for a window nobody can see just burns CPU.
 */
export function useAppVisible(): ComputedRef<boolean> {
  const document = useDocumentVisibility()
  return computed(() => document.value === 'visible' && nativeVisible.value)
}

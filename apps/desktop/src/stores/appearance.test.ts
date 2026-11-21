// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it } from 'vitest'
import { nextTick } from 'vue'
import { useAppearanceStore } from './appearance'

// jsdom has no matchMedia; the store only needs it to resolve "system"/"reduced motion".
beforeEach(() => {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
    onchange: null,
  })) as unknown as typeof window.matchMedia
  setActivePinia(createPinia())
})

describe('appearance store', () => {
  it('applies changes live to <html>', async () => {
    const store = useAppearanceStore()
    store.setTheme('light')
    store.setDensity('compact')
    store.setTextSize(110)
    store.setReduceMotion(true)
    await nextTick()
    const root = document.documentElement
    expect(root.dataset.theme).toBe('light')
    expect(root.dataset.density).toBe('compact')
    expect(root.dataset.motion).toBe('reduced')
    expect(root.style.fontSize).toBe('110%')
  })

  it('resolves "system" to light when the OS does not prefer dark', async () => {
    const store = useAppearanceStore()
    store.setTheme('system')
    await nextTick()
    expect(store.resolvedTheme).toBe('light')
    expect(document.documentElement.dataset.theme).toBe('light')
  })
})

// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it, vi } from 'vitest'

const shell = vi.hoisted(() => ({
  initial: true,
  emit: null as ((visible: boolean) => void) | null,
}))

vi.mock('@/api/shell', () => ({
  getWindowVisible: () => Promise.resolve(shell.initial),
  watchWindowVisible: (onChange: (visible: boolean) => void) => {
    shell.emit = onChange
    return Promise.resolve(() => {})
  },
}))

// The module keeps its state at module level, so every test gets a fresh copy.
async function fresh() {
  vi.resetModules()
  return import('./visibility')
}

beforeEach(() => {
  shell.initial = true
  shell.emit = null
})

describe('window visibility', () => {
  it('is visible by default (browser preview, tests)', async () => {
    const { useAppVisible } = await fresh()
    expect(useAppVisible().value).toBe(true)
  })

  it('follows the hide / show announcements of the shell', async () => {
    const { startWindowVisibility, useAppVisible } = await fresh()
    await startWindowVisibility()
    const visible = useAppVisible()
    expect(visible.value).toBe(true)

    shell.emit?.(false) // window hidden to the tray, or minimized
    expect(visible.value).toBe(false)
    shell.emit?.(true)
    expect(visible.value).toBe(true)
  })

  it('starts hidden when the shell says the app was launched minimized', async () => {
    shell.initial = false
    const { startWindowVisibility, useAppVisible } = await fresh()
    await startWindowVisibility()
    expect(useAppVisible().value).toBe(false)
  })

  it('also needs the document itself to be visible', async () => {
    const { useAppVisible } = await fresh()
    const visible = useAppVisible()
    expect(visible.value).toBe(true)
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
    expect(visible.value).toBe(false)
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' })
    document.dispatchEvent(new Event('visibilitychange'))
    expect(visible.value).toBe(true)
  })

  it('starts following only once', async () => {
    const { startWindowVisibility } = await fresh()
    await startWindowVisibility()
    const first = shell.emit
    await startWindowVisibility()
    expect(shell.emit).toBe(first)
  })
})

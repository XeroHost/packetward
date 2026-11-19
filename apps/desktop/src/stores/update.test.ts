// SPDX-License-Identifier: GPL-3.0-or-later
import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { UiPrefs } from '@/api/uiPrefs'
import { DEFAULT_UI_PREFS } from '@/api/uiPrefs'
import { useSettingsStore } from './settings'
import { START_CHECK_DELAY_MS, useUpdateStore } from './update'

const api = vi.hoisted(() => ({
  getUpdateInfo: vi.fn(),
  checkForUpdate: vi.fn(),
  installUpdate: vi.fn(),
}))
vi.mock('@/api/update', () => api)

const prefsApi = vi.hoisted(() => ({
  saved: [] as UiPrefs[],
}))
vi.mock('@/api/uiPrefs', async (importOriginal) => {
  const original = await importOriginal<typeof import('@/api/uiPrefs')>()
  return {
    ...original,
    saveUiPrefs: vi.fn(async (prefs: UiPrefs) => {
      prefsApi.saved.push(JSON.parse(JSON.stringify(prefs)) as UiPrefs)
    }),
  }
})
vi.mock('@/api/shell', () => ({ setTrayLocale: vi.fn() }))

const configured = { currentVersion: '0.1.0', configured: true }

beforeEach(() => {
  localStorage.clear()
  setActivePinia(createPinia())
  prefsApi.saved.length = 0
  for (const fn of Object.values(api)) fn.mockReset()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('not configured (placeholder public key)', () => {
  it('reports it without ever asking the network', async () => {
    api.getUpdateInfo.mockResolvedValue({ currentVersion: '0.1.0', configured: false })
    const update = useUpdateStore()
    await update.load()
    expect(update.status).toBe('notConfigured')
    expect(update.configured).toBe(false)
    await update.check()
    expect(update.status).toBe('notConfigured')
    expect(api.checkForUpdate).not.toHaveBeenCalled()
    await update.install()
    expect(api.installUpdate).not.toHaveBeenCalled()
  })
})

describe('checking', () => {
  it('asks the channel the user picked', async () => {
    api.getUpdateInfo.mockResolvedValue(configured)
    api.checkForUpdate.mockResolvedValue({ state: 'upToDate', currentVersion: '0.1.0' })
    const settings = useSettingsStore()
    await settings.setUpdateChannel('beta')
    const update = useUpdateStore()
    await update.check()
    expect(api.checkForUpdate).toHaveBeenCalledWith('beta')
    expect(update.status).toBe('upToDate')
    expect(update.checkedAt).not.toBeNull()
  })

  it('keeps the update that was found', async () => {
    api.getUpdateInfo.mockResolvedValue(configured)
    api.checkForUpdate.mockResolvedValue({
      state: 'available',
      currentVersion: '0.1.0',
      version: '0.2.0',
      notes: 'Fixes',
      date: null,
    })
    const update = useUpdateStore()
    await update.check()
    expect(update.status).toBe('available')
    expect(update.available?.version).toBe('0.2.0')
  })

  it('shows a failed check and allows trying again', async () => {
    api.getUpdateInfo.mockResolvedValue(configured)
    api.checkForUpdate.mockRejectedValueOnce('could not reach the server')
    const update = useUpdateStore()
    await update.check()
    expect(update.status).toBe('error')
    expect(update.error).toContain('could not reach')
    api.checkForUpdate.mockResolvedValue({ state: 'upToDate', currentVersion: '0.1.0' })
    await update.check()
    expect(update.status).toBe('upToDate')
    expect(update.error).toBeNull()
  })

  it('does not start a second check while one runs', async () => {
    api.getUpdateInfo.mockResolvedValue(configured)
    let finish: (value: unknown) => void = () => {}
    api.checkForUpdate.mockReturnValue(new Promise((resolve) => (finish = resolve)))
    const update = useUpdateStore()
    const first = update.check()
    await Promise.resolve()
    await update.check()
    finish({ state: 'upToDate', currentVersion: '0.1.0' })
    await first
    expect(api.checkForUpdate).toHaveBeenCalledTimes(1)
  })

  it('forgets a result when the channel changes', async () => {
    api.getUpdateInfo.mockResolvedValue(configured)
    api.checkForUpdate.mockResolvedValue({
      state: 'available',
      currentVersion: '0.1.0',
      version: '0.2.0-beta.1',
      notes: null,
      date: null,
    })
    const update = useUpdateStore()
    await update.check()
    update.reset()
    expect(update.status).toBe('idle')
    expect(update.available).toBeNull()
  })
})

describe('installing', () => {
  async function withUpdate() {
    api.getUpdateInfo.mockResolvedValue(configured)
    api.checkForUpdate.mockResolvedValue({
      state: 'available',
      currentVersion: '0.1.0',
      version: '0.2.0',
      notes: null,
      date: null,
    })
    const update = useUpdateStore()
    await update.check()
    return update
  }

  it('does nothing without a found update', async () => {
    api.getUpdateInfo.mockResolvedValue(configured)
    const update = useUpdateStore()
    await update.load()
    await update.install()
    expect(api.installUpdate).not.toHaveBeenCalled()
  })

  it('reports download progress as a fraction', async () => {
    const update = await withUpdate()
    api.installUpdate.mockImplementation(async (onEvent: (e: unknown) => void) => {
      onEvent({ event: 'progress', downloaded: 250, total: 1000 })
      expect(update.status).toBe('installing')
      expect(update.progress).toBe(0.25)
      onEvent({ event: 'progress', downloaded: 5000, total: 1000 })
      expect(update.progress).toBe(1)
      onEvent({ event: 'progress', downloaded: 10, total: null })
      expect(update.progress).toBeNull()
    })
    await update.install()
  })

  it('shows an installer failure (for example a bad signature) and stays usable', async () => {
    const update = await withUpdate()
    api.installUpdate.mockRejectedValue('the signature does not match')
    await update.install()
    expect(update.status).toBe('error')
    expect(update.error).toContain('signature')
  })
})

describe('check at start', () => {
  it('is off by default: no request at all', async () => {
    vi.useFakeTimers()
    expect(DEFAULT_UI_PREFS.updates.checkOnStart).toBe(false)
    const update = useUpdateStore()
    const done = update.checkAtStart()
    await vi.runAllTimersAsync()
    await done
    expect(api.getUpdateInfo).not.toHaveBeenCalled()
    expect(api.checkForUpdate).not.toHaveBeenCalled()
  })

  it('checks once, after a delay, when the user switched it on', async () => {
    vi.useFakeTimers()
    api.getUpdateInfo.mockResolvedValue(configured)
    api.checkForUpdate.mockResolvedValue({ state: 'upToDate', currentVersion: '0.1.0' })
    await useSettingsStore().setCheckOnStart(true)
    const update = useUpdateStore()
    const done = update.checkAtStart()
    await vi.advanceTimersByTimeAsync(START_CHECK_DELAY_MS - 1)
    expect(api.checkForUpdate).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(2)
    await done
    expect(api.checkForUpdate).toHaveBeenCalledTimes(1)
  })

  it('stays quiet when the build has no updater key', async () => {
    vi.useFakeTimers()
    api.getUpdateInfo.mockResolvedValue({ currentVersion: '0.1.0', configured: false })
    await useSettingsStore().setCheckOnStart(true)
    const update = useUpdateStore()
    const done = update.checkAtStart()
    await vi.runAllTimersAsync()
    await done
    expect(api.checkForUpdate).not.toHaveBeenCalled()
  })
})

describe('persistence through the settings store', () => {
  it('saves the channel and the start-up switch together with the other preferences', async () => {
    const settings = useSettingsStore()
    await settings.setUpdateChannel('beta')
    await settings.setCheckOnStart(true)
    const last = prefsApi.saved.at(-1)
    expect(last?.updates).toEqual({ channel: 'beta', checkOnStart: true })
    // A later unrelated change must not reset them.
    await settings.setNotification('low', true)
    expect(prefsApi.saved.at(-1)?.updates).toEqual({ channel: 'beta', checkOnStart: true })
  })

  it('defaults to the stable channel with no start-up check', () => {
    const settings = useSettingsStore()
    expect(settings.updates).toEqual({ channel: 'stable', checkOnStart: false })
  })
})

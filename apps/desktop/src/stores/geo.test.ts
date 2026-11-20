// SPDX-License-Identifier: GPL-3.0-or-later
import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useGeoStore } from './geo'

const api = vi.hoisted(() => ({ geoStatus: vi.fn(), geoLookup: vi.fn() }))
vi.mock('@/api/intel', () => api)

beforeEach(() => {
  vi.useFakeTimers()
  setActivePinia(createPinia())
  for (const fn of Object.values(api)) fn.mockReset()
})
afterEach(() => vi.useRealTimers())

const entry = (addr: string, country_code?: string, reserved = false) => ({
  addr,
  country_code,
  reserved,
})

describe('geo store', () => {
  it('asks for many addresses in one batch and remembers the answers', async () => {
    api.geoStatus.mockResolvedValue({ state: 'ready' })
    api.geoLookup.mockResolvedValue({
      entries: [entry('8.8.8.8', 'us'), entry('10.0.0.1', undefined, true)],
    })
    const geo = useGeoStore()
    expect(geo.place('8.8.8.8')).toBeUndefined()
    expect(geo.place('10.0.0.1')).toBeUndefined()
    expect(geo.place('8.8.8.8')).toBeUndefined() // not asked twice
    await vi.advanceTimersByTimeAsync(200)
    expect(api.geoLookup).toHaveBeenCalledTimes(1)
    expect(api.geoLookup).toHaveBeenCalledWith(['8.8.8.8', '10.0.0.1'])
    expect(geo.place('8.8.8.8')).toEqual({ code: 'US' })
    expect(geo.place('10.0.0.1')).toBeNull() // private: nothing to show
    expect(geo.ready).toBe(true)
  })

  it('does not look anything up without a GeoIP database, and checks again later', async () => {
    api.geoStatus.mockResolvedValue({ state: 'missing' })
    const geo = useGeoStore()
    geo.place('8.8.8.8')
    await vi.advanceTimersByTimeAsync(200)
    expect(api.geoLookup).not.toHaveBeenCalled()
    expect(geo.ready).toBe(false)
    expect(geo.place('8.8.8.8')).toBeUndefined()

    // The user downloads the database; a later request finds it.
    api.geoStatus.mockResolvedValue({ state: 'ready' })
    api.geoLookup.mockResolvedValue({ entries: [entry('8.8.8.8', 'US')] })
    await vi.advanceTimersByTimeAsync(31_000)
    geo.place('8.8.8.8')
    await vi.advanceTimersByTimeAsync(200)
    expect(geo.place('8.8.8.8')).toEqual({ code: 'US' })
  })

  it('treats an address the agent did not answer as final, not as a loop', async () => {
    api.geoStatus.mockResolvedValue({ state: 'ready' })
    api.geoLookup.mockResolvedValue({ entries: [] })
    const geo = useGeoStore()
    geo.place('203.0.113.9')
    await vi.advanceTimersByTimeAsync(200)
    expect(geo.place('203.0.113.9')).toBeNull()
    expect(api.geoLookup).toHaveBeenCalledTimes(1)
  })
})

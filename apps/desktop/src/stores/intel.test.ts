// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ListStatusView } from '@/types/generated/ListStatusView'
import { countryLeaderboard, useIntelStore } from './intel'

const api = vi.hoisted(() => ({
  geoStatus: vi.fn(),
  geoUpdate: vi.fn(),
  geoLookup: vi.fn(),
  blocklists: vi.fn(),
  setListEnabled: vi.fn(),
  refreshList: vi.fn(),
  abuseStatus: vi.fn(),
  setAbuseKey: vi.fn(),
  abuseCheck: vi.fn(),
}))
vi.mock('@/api/intel', () => api)

const list = (id: string, enabled: boolean): ListStatusView => ({
  id,
  name: id,
  description: '',
  signed: false,
  enabled,
  refresh_interval_secs: 3600,
  entries: 0,
})

beforeEach(() => {
  setActivePinia(createPinia())
  for (const fn of Object.values(api)) fn.mockReset()
})

describe('countryLeaderboard', () => {
  it('groups by country, skips reserved and unknown, and sorts by connections', () => {
    const rows = countryLeaderboard(
      [
        { addr: '1.1.1.1', connections: 2 },
        { addr: '2.2.2.2', connections: 9 },
        { addr: '3.3.3.3', connections: 5 },
        { addr: '10.0.0.1', connections: 50 },
        { addr: '4.4.4.4', connections: 7 },
      ],
      [
        { addr: '1.1.1.1', country_code: 'AU', country_name: 'Australia', reserved: false },
        { addr: '2.2.2.2', country_code: 'RU', country_name: 'Russia', reserved: false },
        { addr: '3.3.3.3', country_code: 'RU', country_name: 'Russia', reserved: false },
        { addr: '10.0.0.1', reserved: true },
        { addr: '4.4.4.4', reserved: false },
      ],
    )
    expect(rows).toEqual([
      { code: 'RU', name: 'Russia', sources: 2, connections: 14 },
      { code: 'AU', name: 'Australia', sources: 1, connections: 2 },
    ])
  })
})

describe('the store', () => {
  it('loads geo, lists and the AbuseIPDB state together', async () => {
    api.geoStatus.mockResolvedValue({ state: 'missing', updating: false, attribution: 'DB-IP' })
    api.blocklists.mockResolvedValue({ lists: [list('spamhaus-drop', false)] })
    api.abuseStatus.mockResolvedValue({ configured: false, state: 'not_configured' })
    const intel = useIntelStore()
    await intel.refresh()
    expect(intel.geoReady).toBe(false)
    expect(intel.lists).toHaveLength(1)
    expect(intel.abuse?.configured).toBe(false)
    expect(intel.error).toBeNull()
  })

  it('shows the reason when a call fails and keeps what it had', async () => {
    api.setListEnabled.mockRejectedValue(new Error('the list is not available'))
    const intel = useIntelStore()
    await intel.toggleList('xerohost', true)
    expect(intel.error).toBe('the list is not available')
    expect(intel.busy).toBe(false)
  })

  it('replaces the lists with the agent answer after a toggle', async () => {
    api.setListEnabled.mockResolvedValue({ lists: [list('spamhaus-drop', true)] })
    const intel = useIntelStore()
    await intel.toggleList('spamhaus-drop', true)
    expect(intel.lists[0]?.enabled).toBe(true)
    expect(api.setListEnabled).toHaveBeenCalledWith('spamhaus-drop', true)
  })

  it('removes the key by sending null and checks an address', async () => {
    api.setAbuseKey.mockResolvedValue({ configured: false, state: 'not_configured' })
    api.abuseCheck.mockResolvedValue({
      addr: '8.8.8.8',
      score: 12,
      total_reports: 3,
      from_cache: false,
    })
    api.abuseStatus.mockResolvedValue({ configured: true, state: 'ready' })
    const intel = useIntelStore()
    await intel.saveKey(null)
    expect(api.setAbuseKey).toHaveBeenCalledWith(null)
    await intel.checkAddress(' 8.8.8.8 ')
    expect(api.abuseCheck).toHaveBeenCalledWith('8.8.8.8')
    expect(intel.check?.score).toBe(12)
  })

  it('builds the leaderboard from a lookup and clears it with no talkers', async () => {
    api.geoLookup.mockResolvedValue({
      entries: [{ addr: '2.2.2.2', country_code: 'RU', country_name: 'Russia', reserved: false }],
    })
    const intel = useIntelStore()
    await intel.updateCountries([{ addr: '2.2.2.2', connections: 4 }])
    expect(intel.countries[0]?.code).toBe('RU')
    await intel.updateCountries([])
    expect(intel.countries).toEqual([])
  })
})

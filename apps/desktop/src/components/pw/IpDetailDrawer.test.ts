// SPDX-License-Identifier: GPL-3.0-or-later
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { i18n } from '@/app/i18n'
import { useDefenseStore } from '@/stores/defense'
import { useIpDetailStore } from '@/stores/ipDetail'
import type { AlertView } from '@/types/generated/AlertView'
import type { BlockView } from '@/types/generated/BlockView'
import IpCell from './IpCell.vue'
import IpDetailDrawer from './IpDetailDrawer.vue'

const api = vi.hoisted(() => ({
  geoLookup: vi.fn(),
  geoStatus: vi.fn(),
  abuseStatus: vi.fn(),
  abuseCheck: vi.fn(),
  blocklists: vi.fn(),
  geoUpdate: vi.fn(),
  setListEnabled: vi.fn(),
  refreshList: vi.fn(),
  setAbuseKey: vi.fn(),
}))
vi.mock('@/api/intel', () => api)
vi.mock('@/api/shell', () => ({
  notifyAlert: vi.fn(),
  setTrayState: vi.fn(),
  setTrayLocale: vi.fn(),
}))
const defenseApi = vi.hoisted(() => ({
  LOCKOUT_PHRASE: 'x',
  fetchBlocks: vi.fn(),
  fetchAllowlist: vi.fn(),
  saveAllowlist: vi.fn(),
  unblockTargets: vi.fn(),
}))
vi.mock('@/api/defense', () => defenseApi)
const alertsApi = vi.hoisted(() => ({ fetchAlerts: vi.fn(), clearEndedAlerts: vi.fn() }))
vi.mock('@/api/alerts', () => alertsApi)
vi.mock('@/stores/live', () => ({
  useLiveStore: () => ({
    rdpPeers: new Set<string>(['203.0.113.9']),
    rdpTrusted: new Set<string>(),
    rows: [
      {
        id: 0,
        proto: 'tcp',
        local_addr: '10.0.0.2',
        local_port: 3389,
        remote_addr: '203.0.113.9',
        remote_port: 51000,
        state: 'established',
        pid: 4,
        process: 'svchost.exe',
      },
      {
        id: 1,
        proto: 'tcp',
        local_addr: '10.0.0.2',
        local_port: 443,
        remote_addr: '198.51.100.1',
        remote_port: 1,
        state: 'established',
        pid: 5,
        process: 'other.exe',
      },
    ],
    loadConnections: vi.fn(),
  }),
}))

const ALERT: AlertView = {
  id: 1,
  phase: 'started',
  kind: 'rdp_brute_force',
  severity: 'high',
  source: '203.0.113.9',
  summary_key: 'rdp_brute_force',
  metrics: [],
  window_secs: 60,
  first_seen_unix_ms: 1_000,
  last_seen_unix_ms: 2_000,
  protected: false,
  peak_severity: 'high',
}
const BLOCK: BlockView = {
  cidr: '203.0.113.9/32',
  source: 'guardian',
  reason: 'brute force',
  created_unix_ms: 1_000,
  escalation: 0,
}

beforeEach(() => {
  setActivePinia(createPinia())
  i18n.global.locale.value = 'en'
  for (const fn of [...Object.values(api), ...Object.values(alertsApi)]) fn.mockReset()
  for (const fn of Object.values(defenseApi)) if (typeof fn !== 'string') fn.mockReset()
  alertsApi.fetchAlerts.mockResolvedValue({ alerts: [], dropped: 0 })
  defenseApi.fetchBlocks.mockResolvedValue({ blocks: [] })
  defenseApi.fetchAllowlist.mockResolvedValue({ allowlist: [], management: [] })
  api.geoLookup.mockResolvedValue({
    entries: [
      {
        addr: '203.0.113.9',
        country_code: 'ES',
        country_name: 'Spain',
        asn: 64500,
        as_org: 'Example Net',
        reserved: false,
      },
    ],
  })
  api.geoStatus.mockResolvedValue({ state: 'ready' })
  api.abuseStatus.mockResolvedValue({ configured: false, state: 'not_configured' })
  api.blocklists.mockResolvedValue({ lists: [] })
})

async function open(addr = '203.0.113.9') {
  const wrapper = mount(IpDetailDrawer, {
    attachTo: document.body,
    global: { plugins: [i18n], stubs: { Teleport: true, Transition: false } },
  })
  useIpDetailStore().open(addr)
  await flushPromises()
  return wrapper
}

describe('IpDetailDrawer', () => {
  it('is closed until an address is opened and never opens for a CIDR', async () => {
    const wrapper = await open('10.0.0.0/8')
    expect(wrapper.find('[data-testid="ip-detail"]').exists()).toBe(false)
  })

  it('shows where the address is, its alerts, its block and its live connections', async () => {
    alertsApi.fetchAlerts.mockResolvedValue({ alerts: [ALERT], dropped: 0 })
    defenseApi.fetchBlocks.mockResolvedValue({ blocks: [BLOCK] })
    const wrapper = await open()
    const text = wrapper.text()
    expect(wrapper.find('[data-testid="ip-detail-addr"]').text()).toBe('203.0.113.9')
    expect(text).toContain('Spain')
    expect(text).toContain('AS64500')
    expect(text).toContain('Example Net')
    expect(wrapper.find('[data-testid="ip-state-blocked"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="ip-alerts"]').text()).toContain('High')
    const connections = wrapper.find('[data-testid="ip-connections"]').text()
    expect(connections).toContain('svchost.exe')
    expect(connections).not.toContain('other.exe')
    // Blocked: the action is to unblock, not to block again.
    expect(wrapper.find('[data-testid="ip-unblock"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="ip-block"]').exists()).toBe(false)
  })

  it('says nothing is sent to AbuseIPDB without a key, and offers the check with one', async () => {
    let wrapper = await open()
    expect(wrapper.text()).toContain('Nothing is sent without it')
    wrapper.unmount()
    api.abuseStatus.mockResolvedValue({ configured: true, state: 'ready' })
    setActivePinia(createPinia())
    wrapper = await open()
    expect(wrapper.text()).toContain('Check on AbuseIPDB')
  })

  it('opens from the address in an IpCell and the block button asks for the block dialog', async () => {
    const cell = mount(IpCell, { props: { addr: '203.0.113.9' }, global: { plugins: [i18n] } })
    await cell.find('[data-testid="ip-open"]').trigger('click')
    const detail = useIpDetailStore()
    expect(detail.addr).toBe('203.0.113.9')
    const wrapper = await open()
    await wrapper.find('[data-testid="ip-block"]').trigger('click')
    expect(useDefenseStore().blockTarget).toBe('203.0.113.9')
  })

  it('adds the address to the allowlist', async () => {
    const defense = useDefenseStore()
    const save = vi.spyOn(defense, 'updateAllowlist').mockResolvedValue(true)
    const wrapper = await open()
    await wrapper.find('[data-testid="ip-allow"]').trigger('click')
    await flushPromises()
    expect(save).toHaveBeenCalledWith({ allowlist: ['203.0.113.9'], management: [] })
    expect(wrapper.text()).toContain('Added to the allowlist')
  })
})

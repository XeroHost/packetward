// SPDX-License-Identifier: GPL-3.0-or-later
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { previewStats } from '@/api/preview'
import { i18n } from '@/app/i18n'
import { useAgentStore } from '@/stores/agent'
import { useLiveStore } from '@/stores/live'
import DashboardPage from './DashboardPage.vue'

vi.mock('@/api/agent', () => ({
  watchAgent: () => () => {},
  elevateAgent: vi.fn(),
  fetchConnections: vi.fn(),
  AgentUnsupportedError: class extends Error {},
}))

beforeEach(() => {
  setActivePinia(createPinia())
  i18n.global.locale.value = 'en'
})

function connect(minor = 1) {
  useAgentStore().apply({
    type: 'status',
    data: { state: 'connected', agent_version: '1.2.3', protocol_major: 1, protocol_minor: minor },
  })
}

// The chart needs a canvas, which jsdom does not have; it has its own option-builder tests.
const mountPage = () =>
  mount(DashboardPage, { global: { plugins: [i18n], stubs: { TrafficChart: true } } })

describe('DashboardPage', () => {
  it('shows the heartbeat from the agent', async () => {
    const agent = useAgentStore()
    connect()
    const wrapper = mountPage()
    expect(wrapper.text()).toContain('Waiting for the first heartbeat')
    expect(wrapper.text()).toContain('1.2.3')

    agent.apply({ type: 'heartbeat', data: { seq: 7, uptime_secs: 65, unix_ms: 1 } })
    await wrapper.vm.$nextTick()
    expect(wrapper.get('[data-testid="heartbeat-seq"]').text()).toBe('#7')
    expect(wrapper.get('[data-testid="heartbeat-uptime"]').text()).toBe('1m 5s')
  })

  it('shows placeholders until the first live.stats arrives', () => {
    connect()
    const wrapper = mountPage()
    const tiles = wrapper.findAll('[data-testid="tile-value"]').map((t) => t.text())
    expect(tiles).toEqual(['—', '—', '—', '—'])
    expect(wrapper.text()).toContain('No remote connections')
  })

  it('shows traffic, connections and RDP numbers from live.stats', async () => {
    connect()
    const stats = previewStats(1)
    stats.totals.in_bps = 12_500_000
    stats.totals.out_bps = 1_000_000
    stats.connections.established = 118
    stats.connections.total = 312
    useLiveStore().applyStats(stats)
    const wrapper = mountPage()
    const tiles = wrapper.findAll('[data-testid="tile-value"]').map((t) => t.text())
    expect(tiles).toEqual(['12.5 Mbps', '1.00 Mbps', '118', '1'])
    expect(wrapper.text()).toContain('312 in total')
    expect(wrapper.text()).toContain('Link 10.0 Gbps')
  })

  it('marks the current RDP client in the top remote addresses and lists the adapters', () => {
    connect()
    useLiveStore().applyStats(previewStats(1))
    const wrapper = mountPage()
    const top = wrapper.get('[data-testid="top-remote"]')
    const rdpRow = top.findAll('li').find((li) => li.text().includes('203.0.113.50'))
    expect(rdpRow?.text()).toContain('RDP')
    const other = top.findAll('li').find((li) => li.text().includes('198.51.100.7'))
    expect(other?.text()).not.toContain('RDP')

    const adapters = wrapper.get('[data-testid="adapters"]').text()
    expect(adapters).toContain('Ethernet')
    expect(adapters).toContain('Counted in the totals')
    expect(adapters).toContain('WireGuard')
    expect(adapters).toContain('Not in the totals')
  })

  it('tells the real RDP peers apart from the address the client reports', () => {
    connect()
    useLiveStore().applyStats(previewStats(1))
    const text = mountPage().text()
    expect(text).toContain('Connected from')
    expect(text).toContain('203.0.113.50')
    expect(text).toContain('client reports')
    expect(text).toContain('100.64.0.9')
  })

  it('warns when the agent is older than the app', () => {
    connect(0)
    expect(mountPage().text()).toContain('older than this app')
  })

  it('is translated', () => {
    connect()
    useLiveStore().applyStats(previewStats(1))
    i18n.global.locale.value = 'es'
    const text = mountPage().text()
    expect(text).toContain('Entrada')
    expect(text).toContain('Direcciones remotas principales')
  })
})

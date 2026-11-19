// SPDX-License-Identifier: GPL-3.0-or-later
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { i18n } from '@/app/i18n'
import { useAgentStore } from '@/stores/agent'
import DashboardPage from './DashboardPage.vue'

vi.mock('@/api/agent', () => ({ watchAgent: () => () => {}, elevateAgent: vi.fn() }))

beforeEach(() => {
  setActivePinia(createPinia())
  i18n.global.locale.value = 'en'
})

describe('DashboardPage', () => {
  it('shows the heartbeat from the agent', async () => {
    const agent = useAgentStore()
    agent.apply({
      type: 'status',
      data: { state: 'connected', agent_version: '1.2.3', protocol_major: 1, protocol_minor: 0 },
    })
    const wrapper = mount(DashboardPage, { global: { plugins: [i18n] } })
    expect(wrapper.text()).toContain('Waiting for the first heartbeat')
    expect(wrapper.text()).toContain('1.2.3')

    agent.apply({ type: 'heartbeat', data: { seq: 7, uptime_secs: 65, unix_ms: 1 } })
    await wrapper.vm.$nextTick()
    expect(wrapper.get('[data-testid="heartbeat-seq"]').text()).toBe('#7')
    expect(wrapper.get('[data-testid="heartbeat-uptime"]').text()).toBe('1m 5s')
  })
})

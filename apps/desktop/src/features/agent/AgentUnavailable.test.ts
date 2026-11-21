// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AgentConnection } from '@/api/agent'
import { i18n } from '@/app/i18n'
import { useAgentStore } from '@/stores/agent'
import AgentUnavailable from './AgentUnavailable.vue'

vi.mock('@/api/agent', () => ({ watchAgent: () => () => {}, elevateAgent: vi.fn() }))
vi.mock('@/api/links', () => ({ openExternal: vi.fn(), XEROHOST_URL: 'https://xerohost.net' }))

beforeEach(() => {
  // jsdom has no matchMedia; the logo and appearance store read it.
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
  i18n.global.locale.value = 'en'
})

function show(connection: AgentConnection) {
  const agent = useAgentStore()
  agent.connection = connection
  const run = vi.spyOn(agent, 'runElevated').mockResolvedValue()
  const wrapper = mount(AgentUnavailable, { global: { plugins: [i18n] } })
  return { wrapper, run }
}

const buttons = (wrapper: ReturnType<typeof show>['wrapper']) =>
  wrapper.findAll('button').map((b) => b.text())

describe('AgentUnavailable', () => {
  it('offers to install when the service is missing', async () => {
    const { wrapper, run } = show({ state: 'not_installed' })
    expect(wrapper.text()).toContain('The PacketWard agent is not installed')
    await wrapper.findAll('button')[0]?.trigger('click')
    expect(run).toHaveBeenCalledWith('repair')
  })

  it('offers Start (and Repair) when the service is stopped', async () => {
    const { wrapper, run } = show({ state: 'stopped' })
    expect(buttons(wrapper)).toEqual(expect.arrayContaining(['Start agent', 'Repair installation']))
    await wrapper.findAll('button')[0]?.trigger('click')
    expect(run).toHaveBeenCalledWith('start')
  })

  it('tells the user to sign out when the group membership is not in their token yet, or to repair', async () => {
    const { wrapper, run } = show({ state: 'access_denied', reason: 'sign_out_required' })
    expect(wrapper.text()).toContain('Sign out of Windows and sign back in')
    expect(wrapper.text()).toContain('is not enough')
    // Repair restarts the agent with the member's own SID in the pipe ACL: no sign-out needed.
    expect(buttons(wrapper)).toContain('Repair installation')
    await wrapper.findAll('button')[0]?.trigger('click')
    expect(run).toHaveBeenCalledWith('repair')
  })

  it.each([
    ['group_missing', 'The “PacketWard Operators” group does not exist'],
    ['not_member', 'Only administrators and members'],
  ] as const)('explains %s and offers Repair', async (reason, text) => {
    const { wrapper, run } = show({ state: 'access_denied', reason })
    expect(wrapper.text()).toContain(text)
    await wrapper.findAll('button')[0]?.trigger('click')
    expect(run).toHaveBeenCalledWith('repair')
  })

  it('shows the agent version when the two sides are incompatible', () => {
    const { wrapper } = show({ state: 'agent_outdated', agent_version: '0.0.9' })
    expect(wrapper.text()).toContain('The agent is out of date')
    expect(wrapper.text()).toContain('0.0.9')
  })

  it('shows the error detail', () => {
    const { wrapper } = show({ state: 'error', message: 'pipe exploded' })
    expect(wrapper.text()).toContain('pipe exploded')
  })

  it('shows a progress state while the service starts, without actions', () => {
    const { wrapper } = show({ state: 'starting' })
    expect(wrapper.text()).toContain('Starting the PacketWard agent')
    expect(buttons(wrapper)).toEqual(['Contact XeroHost support'])
  })

  it('reports a declined UAC prompt and a failure', async () => {
    const { wrapper } = show({ state: 'stopped' })
    const agent = useAgentStore()
    agent.elevationNotice = { kind: 'cancelled' }
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('permission prompt was declined')
    agent.elevationNotice = { kind: 'failed', message: 'exit code 5' }
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('That did not work: exit code 5')
  })

  it('disables the actions while an elevated command runs', async () => {
    const { wrapper } = show({ state: 'stopped' })
    useAgentStore().elevating = true
    await wrapper.vm.$nextTick()
    expect(wrapper.findAll('button')[0]?.attributes('disabled')).toBeDefined()
  })

  it('is translated', () => {
    i18n.global.locale.value = 'es'
    const { wrapper } = show({ state: 'stopped' })
    expect(wrapper.text()).toContain('El agente de PacketWard no se está ejecutando')
    expect(wrapper.text()).toContain('Iniciar agente')
  })
})

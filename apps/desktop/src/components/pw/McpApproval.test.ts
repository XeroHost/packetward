// SPDX-License-Identifier: GPL-3.0-or-later
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { nextTick } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { i18n } from '@/app/i18n'
import { useMcpStore } from '@/stores/mcp'
import type { McpPendingAction } from '@/types/generated/McpPendingAction'
import McpApprovalBanner from './McpApprovalBanner.vue'
import McpApprovalDialog from './McpApprovalDialog.vue'

const api = vi.hoisted(() => ({
  fetchPendingActions: vi.fn(),
  approveMcpAction: vi.fn(),
  rejectMcpAction: vi.fn(),
  notifyActionRequest: vi.fn(),
  watchApprovalOpen: vi.fn(),
}))
vi.mock('@/api/mcp', () => api)

const action = (id: number, overrides: Partial<McpPendingAction> = {}): McpPendingAction => ({
  id,
  tool: 'block_ip',
  args: { ip: '203.0.113.9', ttl_secs: 3600 },
  summary: 'Block 203.0.113.9 for one hour',
  created_ts: Date.now() * 1_000_000,
  expires_ts: (Date.now() + 60_000) * 1_000_000,
  ...overrides,
})

beforeEach(() => {
  setActivePinia(createPinia())
  i18n.global.locale.value = 'en'
  document.documentElement.dataset.motion = 'reduced'
  // jsdom has the <dialog> element but not its modal methods yet.
  HTMLDialogElement.prototype.showModal = function (this: HTMLDialogElement) {
    this.open = true
  }
  HTMLDialogElement.prototype.close = function (this: HTMLDialogElement) {
    if (!this.open) return
    this.open = false
    this.dispatchEvent(new Event('close'))
  }
  Object.values(api).forEach((fn) => fn.mockReset())
  api.watchApprovalOpen.mockResolvedValue(() => {})
})

afterEach(() => {
  delete document.documentElement.dataset.motion
  document.body.innerHTML = ''
})

describe('McpApprovalBanner', () => {
  it('stays out of the way while nothing waits', () => {
    const wrapper = mount(McpApprovalBanner, { global: { plugins: [i18n] } })
    expect(wrapper.find('[data-testid="mcp-banner"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('names the client, counts the requests and opens the dialog', async () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(1), action(2)] })
    const wrapper = mount(McpApprovalBanner, { global: { plugins: [i18n] } })
    const banner = wrapper.get('[data-testid="mcp-banner"]')
    expect(banner.text()).toContain('An AI client requests an action')
    expect(banner.text()).toContain('2 waiting')
    await banner.get('button').trigger('click')
    expect(mcp.open).toBe(true)
    wrapper.unmount()
  })
})

describe('McpApprovalDialog', () => {
  async function show(pending: McpPendingAction[]) {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: pending })
    const wrapper = mount(McpApprovalDialog, {
      global: { plugins: [i18n] },
      attachTo: document.body,
    })
    mcp.openDialog()
    await nextTick()
    await nextTick()
    return { wrapper, mcp }
  }

  it('shows the tool, the summary, the full arguments and the countdown', async () => {
    const { wrapper } = await show([action(1)])
    expect((wrapper.get('dialog').element as HTMLDialogElement).open).toBe(true)
    const section = wrapper.get('[data-testid="mcp-action-1"]')
    expect(section.text()).toContain('block_ip')
    expect(section.text()).toContain('Block 203.0.113.9 for one hour')
    expect(section.text()).toContain('Blocks an address in the firewall.')
    expect(section.get('pre').text()).toContain('"ip": "203.0.113.9"')
    expect(section.get('pre').text()).toContain('"ttl_secs": 3600')
    expect(section.text()).toContain('Expires in 60 s')
    wrapper.unmount()
  })

  it('approves and rejects through the store', async () => {
    const { wrapper } = await show([action(1), action(2)])
    api.approveMcpAction.mockResolvedValue({})
    api.rejectMcpAction.mockResolvedValue({})
    const first = wrapper.get('[data-testid="mcp-action-1"]')
    const firstButtons = first.findAll('button')
    await firstButtons[0]?.trigger('click')
    expect(api.rejectMcpAction).toHaveBeenCalledWith(1)
    const second = wrapper.get('[data-testid="mcp-action-2"]')
    const buttons = second.findAll('button')
    await buttons.at(-1)?.trigger('click')
    expect(api.approveMcpAction).toHaveBeenCalledWith(2)
    wrapper.unmount()
  })

  it('translates the consequence line', async () => {
    i18n.global.locale.value = 'es'
    const { wrapper } = await show([action(1)])
    expect(wrapper.text()).toContain('Bloquea una dirección en el firewall')
    i18n.global.locale.value = 'en'
    wrapper.unmount()
  })
})

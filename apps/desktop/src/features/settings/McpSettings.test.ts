// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { i18n } from '@/app/i18n'
import PwSelect from '@/components/pw/PwSelect.vue'
import { Switch } from '@/components/ui/switch'
import type { McpSettingsView } from '@/types/generated/McpSettingsView'
import type { McpToolSetting } from '@/types/generated/McpToolSetting'
import McpSettings from './McpSettings.vue'

const api = vi.hoisted(() => ({
  fetchMcpSettings: vi.fn(),
  saveMcpSettings: vi.fn(),
  fetchMcpInstallInfo: vi.fn(),
  runMcpSelfCheck: vi.fn(),
}))
vi.mock('@/api/mcp', () => api)

const PWCTL = 'C:\\Program Files\\PacketWard\\pwctl.exe'

const tools = (overrides: Record<string, McpToolSetting['level']> = {}): McpToolSetting[] =>
  [
    'block_ip',
    'start_capture',
    'speed_test',
    'support_bundle',
    'unblock_ip',
    'set_guardian_mode',
    'create_firewall_rule',
    'delete_firewall_rule',
  ].map((tool) => ({ tool, level: overrides[tool] ?? 'disabled' }))

const view = (overrides: Partial<McpSettingsView> = {}): McpSettingsView => ({
  enabled: false,
  write_limit_per_min: 6,
  tools: tools(),
  ...overrides,
})

/** PwSelect is a generic component: VTU types its props as `never`, so probe it structurally. */
type ProbedSelect = {
  props: (key: string) => unknown
  exists: () => boolean
  vm: { $emit: (event: string, ...args: unknown[]) => void }
}
function probe(component: unknown): ProbedSelect {
  return component as ProbedSelect
}

/** The PwSelect of one tool (or the client picker), by its accessible name. */
function select(wrapper: VueWrapper, label: string): ProbedSelect {
  const found = wrapper
    .findAllComponents(PwSelect)
    .find((component) => probe(component).props('ariaLabel') === label)
  if (!found) throw new Error(`no PwSelect labelled ${label}`)
  return probe(found)
}

async function mountPage(policy: McpSettingsView = view()): Promise<VueWrapper> {
  api.fetchMcpSettings.mockResolvedValue(policy)
  api.fetchMcpInstallInfo.mockResolvedValue({ path: PWCTL, exists: true })
  const wrapper = mount(McpSettings, { global: { plugins: [i18n] } })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  i18n.global.locale.value = 'en'
  document.documentElement.dataset.motion = 'reduced'
  HTMLDialogElement.prototype.showModal = function (this: HTMLDialogElement) {
    this.open = true
  }
  HTMLDialogElement.prototype.close = function (this: HTMLDialogElement) {
    if (!this.open) return
    this.open = false
    this.dispatchEvent(new Event('close'))
  }
  Object.values(api).forEach((fn) => fn.mockReset())
  api.saveMcpSettings.mockImplementation((request: Record<string, unknown>) => {
    // Apply the request the way the agent does, so the page keeps a complete policy.
    const base = view()
    const changes = (request.tools as McpToolSetting[] | undefined) ?? []
    base.tools = base.tools.map((setting) => {
      const change = changes.find((entry) => entry.tool === setting.tool)
      return change ? { ...setting, level: change.level } : setting
    })
    return Promise.resolve({
      ...base,
      ...request,
      tools: base.tools,
    })
  })
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  })
})

describe('McpSettings', () => {
  it('starts with the server off and says so', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-testid="mcp-enabled"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="mcp-off-note"]').exists()).toBe(true)
    expect(select(wrapper, 'Block an address').exists()).toBe(true)
    expect(select(wrapper, 'Delete a firewall rule').exists()).toBe(true)
  })

  it('asks for confirmation before enabling the server', async () => {
    const wrapper = await mountPage()
    wrapper.findComponent(Switch).vm.$emit('update:modelValue', true)
    await flushPromises()
    expect(api.saveMcpSettings).not.toHaveBeenCalled()
    const dialog = wrapper.find('[data-testid="mcp-enable-dialog"]').element as HTMLDialogElement
    expect(dialog.open).toBe(true)

    await wrapper.find('[data-testid="mcp-enable-confirm"]').trigger('click')
    await flushPromises()
    expect(api.saveMcpSettings).toHaveBeenCalledWith({ enabled: true })
  })

  it('turns the server off without a dialog', async () => {
    const wrapper = await mountPage(view({ enabled: true }))
    wrapper.findComponent(Switch).vm.$emit('update:modelValue', false)
    await flushPromises()
    expect(api.saveMcpSettings).toHaveBeenCalledWith({ enabled: false })
  })

  it('saves only the tool whose level changed', async () => {
    const wrapper = await mountPage(view({ enabled: true }))
    select(wrapper, 'Block an address').vm.$emit('update:modelValue', 'automatic')
    await flushPromises()
    expect(api.saveMcpSettings).toHaveBeenCalledWith({
      tools: [{ tool: 'block_ip', level: 'automatic' }],
    })
  })

  it('never offers "automatic" for the tools that always need an approval', async () => {
    const wrapper = await mountPage()
    const options = select(wrapper, 'Unblock an address').props('options') as {
      value: string
    }[]
    expect(options.map((option) => option.value)).toEqual(['disabled', 'approval'])
    const block = select(wrapper, 'Block an address').props('options') as { value: string }[]
    expect(block.map((option) => option.value)).toEqual(['disabled', 'automatic', 'approval'])
  })

  it('refuses a write limit outside 1..60 and saves a valid one', async () => {
    const wrapper = await mountPage()
    const input = wrapper.find('[data-testid="mcp-limit"]')
    await input.setValue('0')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(api.saveMcpSettings).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Between 1 and 60.')

    await input.setValue('30')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(api.saveMcpSettings).toHaveBeenCalledWith({ write_limit_per_min: 30 })
  })

  it('builds a snippet with the installed pwctl.exe for every client', async () => {
    const wrapper = await mountPage()
    const snippet = () => wrapper.find('[data-testid="mcp-snippet"]').text()
    expect(snippet()).toContain(JSON.stringify(PWCTL))
    expect(snippet()).toContain('"mcpServers"')

    select(wrapper, 'Client').vm.$emit('update:modelValue', 'opencode')
    await flushPromises()
    expect(snippet()).toContain('"type": "local"')
    expect(snippet()).toContain(`[${JSON.stringify(PWCTL)}, "mcp"]`)

    select(wrapper, 'Client').vm.$emit('update:modelValue', 'claudeCode')
    await flushPromises()
    expect(snippet()).toContain('"type": "stdio"')
  })

  it('copies the snippet to the clipboard', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-testid="mcp-copy"]').trigger('click')
    await flushPromises()
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      wrapper.find('[data-testid="mcp-snippet"]').text(),
    )
    expect(wrapper.find('[data-testid="mcp-copy"]').text()).toBe('Copied')
  })

  it('reports the result of the installed pwctl.exe smoke test', async () => {
    api.runMcpSelfCheck.mockResolvedValue({ ok: true, path: PWCTL, outcome: 'ok', detail: '' })
    const wrapper = await mountPage()
    await wrapper.find('[data-testid="mcp-check"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="mcp-check-result"]').text()).toContain(
      'started and exited cleanly',
    )

    api.runMcpSelfCheck.mockResolvedValue({
      ok: false,
      path: PWCTL,
      outcome: 'missing',
      detail: '',
    })
    await wrapper.find('[data-testid="mcp-check"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="mcp-check-result"]').text()).toContain(
      'Reinstall PacketWard',
    )
  })

  it('shows the agent error instead of pretending the change was saved', async () => {
    const wrapper = await mountPage(view({ enabled: true }))
    api.saveMcpSettings.mockRejectedValue(new Error('pipe closed'))
    select(wrapper, 'Block an address').vm.$emit('update:modelValue', 'approval')
    await flushPromises()
    expect(wrapper.find('[data-testid="mcp-save-error"]').exists()).toBe(true)
  })
})

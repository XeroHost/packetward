// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { i18n } from '@/app/i18n'
import type { AgentSettingsView } from '@/types/generated/AgentSettingsView'
import CaptureSettings from './CaptureSettings.vue'

const api = vi.hoisted(() => ({
  getAgentSettings: vi.fn(),
  setProxy: vi.fn(),
  setCaptureOnStart: vi.fn(),
  auditLog: vi.fn(),
}))
vi.mock('@/api/agentSettings', () => api)

function view(captureOnStart: boolean): AgentSettingsView {
  return { restart_required: false, proxy_credentials: false, capture_on_start: captureOnStart }
}

beforeEach(() => {
  setActivePinia(createPinia())
  i18n.global.locale.value = 'en'
  for (const fn of Object.values(api)) fn.mockReset()
})

async function row(initial: boolean) {
  api.getAgentSettings.mockResolvedValue(view(initial))
  const wrapper = mount(CaptureSettings, { global: { plugins: [i18n] } })
  await flushPromises()
  return wrapper
}

describe('CaptureSettings', () => {
  it('is on by default and says nothing alarming', async () => {
    const wrapper = await row(true)
    expect(wrapper.find('[data-testid="capture-on-start"]').attributes('aria-checked')).toBe('true')
    expect(wrapper.find('[data-testid="capture-off-note"]').exists()).toBe(false)
  })

  it('turning it off asks the agent, then explains what stops seeing packets', async () => {
    api.setCaptureOnStart.mockResolvedValue(view(false))
    const wrapper = await row(true)
    await wrapper.find('[data-testid="capture-on-start"]').trigger('click')
    await flushPromises()
    expect(api.setCaptureOnStart).toHaveBeenCalledWith(false)
    expect(wrapper.find('[data-testid="capture-off-note"]').text()).toContain('flood detection')
  })

  it('shows the reason when the agent cannot save it', async () => {
    api.setCaptureOnStart.mockRejectedValue(new Error('could not save settings'))
    const wrapper = await row(true)
    await wrapper.find('[data-testid="capture-on-start"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('could not save settings')
  })
})

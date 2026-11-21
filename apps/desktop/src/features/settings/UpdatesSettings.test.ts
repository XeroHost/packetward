// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { i18n } from '@/app/i18n'
import UpdatesSettings from './UpdatesSettings.vue'

const api = vi.hoisted(() => ({
  getUpdateInfo: vi.fn(),
  checkForUpdate: vi.fn(),
  installUpdate: vi.fn(),
}))
vi.mock('@/api/update', () => api)
vi.mock('@/api/shell', () => ({ setTrayLocale: vi.fn() }))

beforeEach(() => {
  localStorage.clear()
  setActivePinia(createPinia())
  i18n.global.locale.value = 'en'
  for (const fn of Object.values(api)) fn.mockReset()
})

describe('UpdatesSettings', () => {
  it('says "not configured" and offers no way to check when the build has no key', async () => {
    api.getUpdateInfo.mockResolvedValue({ currentVersion: '0.1.0', configured: false })
    const wrapper = mount(UpdatesSettings, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(wrapper.find('[data-testid="update-current"]').text()).toBe('0.1.0')
    expect(wrapper.find('[data-testid="update-not-configured"]').exists()).toBe(true)
    const check = wrapper.findAll('button').find((b) => b.text() === 'Check for updates')
    expect(check?.attributes('disabled')).toBeDefined()
    expect(api.checkForUpdate).not.toHaveBeenCalled()
  })

  it('checks on demand and offers the install button for a newer version', async () => {
    api.getUpdateInfo.mockResolvedValue({ currentVersion: '0.1.0', configured: true })
    api.checkForUpdate.mockResolvedValue({
      state: 'available',
      currentVersion: '0.1.0',
      version: '0.2.0',
      notes: null,
      date: null,
    })
    const wrapper = mount(UpdatesSettings, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(api.checkForUpdate).not.toHaveBeenCalled()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Check for updates')
      ?.trigger('click')
    await flushPromises()
    expect(api.checkForUpdate).toHaveBeenCalledWith('stable')
    expect(wrapper.text()).toContain('Download and install 0.2.0')
  })
})

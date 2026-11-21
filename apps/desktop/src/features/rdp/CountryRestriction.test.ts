// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { i18n } from '@/app/i18n'
import { useAgentStore } from '@/stores/agent'
import type { RdpCountryStatus } from '@/types/generated/RdpCountryStatus'
import CountryRestriction from './CountryRestriction.vue'

const api = vi.hoisted(() => ({
  fetchRdpCountry: vi.fn(),
  setRdpCountry: vi.fn(),
  fetchRdpAudit: vi.fn(),
}))
vi.mock('@/api/rdp', () => api)

function status(over: Partial<RdpCountryStatus> = {}): RdpCountryStatus {
  return {
    policy: { enabled: false, mode: 'deny', countries: [] },
    geo_ready: true,
    operator_countries: ['ES'],
    blocked_24h: 0,
    would_block_24h: 0,
    ...over,
  }
}

async function mountRow(initial: RdpCountryStatus) {
  api.fetchRdpCountry.mockResolvedValue(initial)
  const wrapper = mount(CountryRestriction, { global: { plugins: [i18n] } })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  setActivePinia(createPinia())
  i18n.global.locale.value = 'en'
  api.fetchRdpCountry.mockReset()
  api.setRdpCountry.mockReset()
  useAgentStore().guardianMode = 'active'
})

describe('CountryRestriction', () => {
  it('is off by default and shows no country controls', async () => {
    const wrapper = await mountRow(status())
    expect(wrapper.text()).toContain('Country restriction')
    expect(wrapper.find('[data-testid="country-chips"]').exists()).toBe(false)
    expect(wrapper.find('#rdp-country-search').exists()).toBe(false)
  })

  it('refuses to save an allow-only list with no country', async () => {
    const wrapper = await mountRow(
      status({ policy: { enabled: true, mode: 'allow', countries: [] } }),
    )
    expect(wrapper.text()).toContain('needs at least one country')
    expect(wrapper.find('[data-testid="country-save"]').attributes('disabled')).toBeDefined()
  })

  it('warns when allow-only would lock the operator out', async () => {
    const wrapper = await mountRow(
      status({ policy: { enabled: true, mode: 'allow', countries: ['US'] } }),
    )
    expect(wrapper.text()).toContain('you would lock yourself out')
    expect(wrapper.text()).toContain('Spain')
  })

  it('says the Guardian is not Active and that a missing GeoIP database blocks nothing', async () => {
    useAgentStore().guardianMode = 'monitor'
    const wrapper = await mountRow(
      status({ geo_ready: false, policy: { enabled: true, mode: 'deny', countries: ['CN'] } }),
    )
    expect(wrapper.text()).toContain('only records what it would block')
    expect(wrapper.text()).toContain('GeoIP database is not installed')
  })

  it('adds a country from the search and saves the policy', async () => {
    api.setRdpCountry.mockImplementation((policy) => Promise.resolve(status({ policy })))
    const wrapper = await mountRow(
      status({ policy: { enabled: true, mode: 'deny', countries: [] } }),
    )
    await wrapper.find('#rdp-country-search').setValue('china')
    await flushPromises()
    await wrapper.find('[role="option"] button').trigger('click')
    expect(wrapper.find('[data-testid="country-chips"]').text()).toContain('China')
    await wrapper.find('[data-testid="country-save"]').trigger('click')
    await flushPromises()
    expect(api.setRdpCountry).toHaveBeenCalledWith({
      enabled: true,
      mode: 'deny',
      countries: ['CN'],
    })
    expect(wrapper.text()).toContain('Saved.')
  })

  it('shows the reason when the agent refuses the policy', async () => {
    api.setRdpCountry.mockRejectedValue(new Error('refused'))
    const wrapper = await mountRow(
      status({ policy: { enabled: true, mode: 'deny', countries: ['CN'] } }),
    )
    await wrapper.find('[data-testid="country-save"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('refused')
    expect(wrapper.text()).not.toContain('Saved.')
  })
})

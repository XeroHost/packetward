// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { previewStats } from '@/api/preview'
import { i18n } from '@/app/i18n'
import { useLiveStore } from '@/stores/live'
import type { LiveStats } from '@/types/generated/LiveStats'
import AuditBanner from './AuditBanner.vue'

vi.mock('@/api/agent', () => ({
  fetchConnections: vi.fn(),
  AgentUnsupportedError: class extends Error {},
}))

beforeEach(() => {
  setActivePinia(createPinia())
  i18n.global.locale.value = 'en'
})

function show(change: (stats: LiveStats) => void) {
  const stats = previewStats(1)
  change(stats)
  useLiveStore().applyStats(stats)
  return mount(AuditBanner, { global: { plugins: [i18n] } })
}

describe('AuditBanner', () => {
  it('stays out of the way when auditing is on and the feed works', () => {
    expect(
      show(() => {})
        .find('[data-testid="audit-banner"]')
        .exists(),
    ).toBe(false)
  })

  it('shows nothing before the first stats arrive', () => {
    setActivePinia(createPinia())
    expect(
      mount(AuditBanner, { global: { plugins: [i18n] } })
        .find('[role="alert"]')
        .exists(),
    ).toBe(false)
  })

  it('warns when successful logons are not audited and says how to fix it', () => {
    const wrapper = show((s) => (s.rdp_trust.audit.success = 'disabled'))
    expect(wrapper.text()).toContain('not auditing successful logons')
    expect(wrapper.text()).toContain(
      'auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
    )
  })

  it('warns separately about failed logons (no brute-force detection)', () => {
    const text = show((s) => (s.rdp_trust.audit.failure = 'disabled')).text()
    expect(text).toContain('brute-force attacks cannot be detected')
    expect(text).not.toContain('not auditing successful logons')
  })

  it('reports an unreadable policy as unknown, not as off', () => {
    const text = show((s) => (s.rdp_trust.audit.success = 'unknown')).text()
    expect(text).toContain('could not be read')
  })

  it('reports an unreadable Security log', () => {
    expect(show((s) => (s.rdp_trust.feed = 'unavailable')).text()).toContain('cannot be read')
  })

  it('is translated', () => {
    i18n.global.locale.value = 'es'
    expect(show((s) => (s.rdp_trust.audit.failure = 'disabled')).text()).toContain('fuerza bruta')
  })
})

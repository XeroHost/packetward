// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { i18n } from '@/app/i18n'
import { useSpeedStore } from '@/stores/speed'
import type { SpeedResultView } from '@/types/generated/SpeedResultView'
import SpeedTestPage from './SpeedTestPage.vue'

vi.mock('@/api/speed', () => ({ startSpeedTest: vi.fn(), cancelSpeedTest: vi.fn() }))
vi.mock('@/stores/geo', () => ({
  useGeoStore: () => ({ place: () => null, warm: () => undefined, ready: false }),
}))

const transfer = {
  streams: 4,
  avg_mbps: 480,
  peak_mbps: 510,
  bytes: 1,
  duration_ms: 1,
  buckets_mbps: [1, 2],
}

function result(over: Partial<SpeedResultView> = {}): SpeedResultView {
  return {
    started_unix_ms: 1,
    kind: 'quick',
    server: { id: 'hetzner-fsn1', name: 'Hetzner Falkenstein', custom: false, provider: 'hetzner' },
    candidates: [],
    download: transfer,
    ...over,
  }
}

beforeEach(() => {
  localStorage.clear()
  setActivePinia(createPinia())
  i18n.global.locale.value = 'en'
})

async function page() {
  const wrapper = mount(SpeedTestPage, { global: { plugins: [i18n] } })
  await flushPromises()
  return wrapper
}

describe('SpeedTestPage providers', () => {
  it('works with no server typed: the default is automatic and the test can start', async () => {
    const wrapper = await page()
    expect(useSpeedStore().provider).toBe('auto')
    expect(wrapper.find('[data-testid="provider-hint"]').text()).toContain('lowest latency')
    const quick = wrapper.findAll('button').find((b) => b.text() === 'Quick test')
    expect(quick?.attributes('disabled')).toBeUndefined()
  })

  it('says which tests a provider does not offer instead of failing later', async () => {
    useSpeedStore().setProvider('cloudflare')
    const wrapper = await page()
    for (const id of ['run-bin1', 'run-bin10']) {
      expect(wrapper.find(`[data-testid="${id}"]`).attributes('disabled')).toBeDefined()
    }
    // The 50 GB test and its confirmation are not even offered.
    expect(wrapper.find('[data-testid="run-bin50"]').exists()).toBe(false)
    expect(wrapper.find('input[type="checkbox"]').exists()).toBe(false)
    useSpeedStore().setProvider('ovh')
    await flushPromises()
    expect(wrapper.find('[data-testid="run-bin1"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-testid="run-bin10"]').attributes('disabled')).toBeDefined()
  })

  it('tells the connection limit of a rate-limited provider and caps the streams field', async () => {
    useSpeedStore().setProvider('hetzner')
    const wrapper = await page()
    expect(wrapper.find('[data-testid="provider-hint"]').text()).toContain('at most 2 connections')
    expect(wrapper.find('input[type="number"]').attributes('max')).toBe('2')
  })

  it('shows the steps while a test runs and says what to do when the server limits us', async () => {
    const speed = useSpeedStore()
    speed.running = true
    speed.kind = 'quick'
    speed.phase = 'download'
    const wrapper = await page()
    const steps = wrapper.find('[data-testid="steps"]').text()
    expect(steps).toContain('Latency')
    expect(steps).toContain('Upload')
    expect(wrapper.find('[aria-current="step"]').text()).toContain('Download')
    speed.running = false
    speed.failure = { code: 'rate_limited', message: 'the server is rate limiting this client' }
    await flushPromises()
    const text = wrapper.find('[data-testid="failure"]').text()
    expect(text).toContain('Wait a minute')
    expect(text).not.toContain('0 seconds')
    speed.failure = {
      code: 'rate_limited',
      message: 'the server is rate limiting this client',
      retryAfterSecs: 3463,
    }
    await flushPromises()
    expect(wrapper.find('[data-testid="failure"]').text()).toContain('about 58 minutes')
  })

  it('shows the own-server box only when it can be used', async () => {
    const wrapper = await page()
    expect(wrapper.find('textarea').exists()).toBe(true)
    useSpeedStore().setProvider('hetzner')
    await flushPromises()
    expect(wrapper.find('textarea').exists()).toBe(false)
    useSpeedStore().setProvider('custom')
    await flushPromises()
    expect(wrapper.find('textarea').exists()).toBe(true)
  })

  it('names the server that measured the upload, or says the provider only downloads', async () => {
    const speed = useSpeedStore()
    speed.results = [
      result({
        upload: transfer,
        upload_server: {
          id: 'cloudflare',
          name: 'Cloudflare',
          custom: false,
          provider: 'cloudflare',
        },
      }),
    ]
    const wrapper = await page()
    expect(wrapper.find('[data-testid="upload-server"]').text()).toContain('measured on Cloudflare')
    speed.results = [result()]
    await flushPromises()
    expect(wrapper.find('[data-testid="download-only"]').text()).toContain('only measures download')
  })
})

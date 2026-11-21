// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AgentCallError } from '@/api/call'
import type { CaptureLive } from '@/types/generated/CaptureLive'
import type { CaptureStatus } from '@/types/generated/CaptureStatus'
import { CAPTURE_HISTORY, useCaptureStore } from './capture'

const api = vi.hoisted(() => ({
  fetchCaptureStatus: vi.fn(),
  startCapture: vi.fn(),
  stopCapture: vi.fn(),
  startRecording: vi.fn(),
  stopRecording: vi.fn(),
  fetchCaptureFiles: vi.fn(),
  deleteCaptureFile: vi.fn(),
  previewSupportBundle: vi.fn(),
  saveSupportBundle: vi.fn(),
}))

vi.mock('@/api/capture', () => api)

const status = (state: CaptureStatus['state'], blind = false): CaptureStatus => ({
  selection: {
    selected: 'raw_socket',
    npcap: { kind: 'npcap', available: false, sees_outbound: true, bpf: true },
    raw_socket: { kind: 'raw_socket', available: true, sees_outbound: true, bpf: false },
    missing: [],
    summary: 'raw socket',
  },
  state,
  blind,
  counters: { received: 0, delivered: 0, dropped: 0 },
  interfaces: [],
  captures_dir: 'C:\\captures',
})

const sample = (n: number): CaptureLive => ({
  unix_ms: n,
  blind: false,
  inbound: { pps: n, bps: n * 8 },
  outbound: { pps: 1, bps: 8 },
  protocols: [],
  top_talkers: [],
  dropped: 0,
  untracked_packets: 0,
})

beforeEach(() => {
  setActivePinia(createPinia())
  for (const fn of Object.values(api)) fn.mockReset()
})

describe('live samples', () => {
  it('keeps a bounded history in time order', () => {
    const capture = useCaptureStore()
    for (let i = 1; i <= CAPTURE_HISTORY + 30; i += 1) capture.applyLive(sample(i))
    expect(capture.history.t).toHaveLength(CAPTURE_HISTORY)
    expect(capture.history.t[0]).toBe(31)
    expect(capture.history.t.at(-1)).toBe(CAPTURE_HISTORY + 30)
    expect(capture.history.inBps.at(-1)).toBe((CAPTURE_HISTORY + 30) * 8)
    expect(capture.live?.unix_ms).toBe(CAPTURE_HISTORY + 30)
  })

  it('forgets everything on reset', () => {
    const capture = useCaptureStore()
    capture.applyLive(sample(1))
    capture.reset()
    expect(capture.live).toBeNull()
    expect(capture.history.t).toEqual([])
  })
})

describe('controls', () => {
  it('starts and stops the capture through the agent', async () => {
    const capture = useCaptureStore()
    api.startCapture.mockResolvedValue(status('running'))
    await capture.start()
    expect(api.startCapture).toHaveBeenCalledWith({})
    expect(capture.status?.state).toBe('running')
    api.stopCapture.mockResolvedValue(status('stopped'))
    capture.applyLive(sample(1))
    await capture.stop()
    expect(capture.status?.state).toBe('stopped')
    expect(capture.live).toBeNull()
  })

  it('keeps the agent explanation when a request fails', async () => {
    const capture = useCaptureStore()
    api.startCapture.mockRejectedValue(new AgentCallError('bad_request', 'No capture backend'))
    await capture.start()
    expect(capture.error).toEqual({ kind: 'bad_request', message: 'No capture backend' })
    expect(capture.busy).toBe(false)
  })

  it('deletes a file and shows the list the agent returns', async () => {
    const capture = useCaptureStore()
    api.deleteCaptureFile.mockResolvedValue({ dir: 'd', files: [] })
    await capture.removeFile('a.pcapng')
    expect(api.deleteCaptureFile).toHaveBeenCalledWith('a.pcapng')
    expect(capture.files).toEqual([])
  })
})

describe('support bundle', () => {
  const request = { anonymize_local_ips: false, capture_secs: 0, include_logs: true }

  it('a preview is discarded when the options change and a failed save is reported', async () => {
    const capture = useCaptureStore()
    api.previewSupportBundle.mockResolvedValue({ items: [], local_addrs_hidden: 0 })
    await capture.previewBundle(request)
    expect(capture.bundlePreview).not.toBeNull()
    api.saveSupportBundle.mockRejectedValue(new AgentCallError('failed', 'disk full'))
    await capture.saveBundle(request)
    expect(capture.bundleError?.message).toBe('disk full')
    expect(capture.bundleSaved).toBeNull()
    expect(capture.bundleBusy).toBe(false)
  })

  it('remembers where the bundle was saved', async () => {
    const capture = useCaptureStore()
    api.saveSupportBundle.mockResolvedValue({ path: 'C:\\x.zip', bytes: 10, items: [] })
    await capture.saveBundle(request)
    expect(capture.bundleSaved?.path).toBe('C:\\x.zip')
  })
})

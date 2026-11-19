// SPDX-License-Identifier: GPL-3.0-or-later
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AgentCallError } from '@/api/call'
import type { SpeedEvent } from '@/types/generated/SpeedEvent'
import type { SpeedResultView } from '@/types/generated/SpeedResultView'
import { KEEP_RESULTS, useSpeedStore } from './speed'

const api = vi.hoisted(() => ({ startSpeedTest: vi.fn(), cancelSpeedTest: vi.fn() }))
vi.mock('@/api/speed', () => api)

const result = (n: number): SpeedResultView => ({
  started_unix_ms: n,
  kind: 'quick',
  server: { id: 's', name: 'Miami', custom: false },
  candidates: [],
  source_ip: '203.0.113.9',
})

beforeEach(() => {
  localStorage.clear()
  setActivePinia(createPinia())
  for (const fn of Object.values(api)) fn.mockReset()
})

describe('a run', () => {
  it('collects live rates (not the warm-up) and ends with a result', async () => {
    const speed = useSpeedStore()
    api.startSpeedTest.mockResolvedValue({ job_id: 3, rejected: [] })
    await speed.start({ kind: 'quick' })
    expect(speed.running).toBe(true)
    const events: SpeedEvent[] = [
      { type: 'phase', job_id: 3, phase: 'download' },
      {
        type: 'rate',
        job_id: 3,
        direction: 'download',
        elapsed_ms: 500,
        warmup: true,
        mbps: 10,
        avg_mbps: 0,
      },
      {
        type: 'rate',
        job_id: 3,
        direction: 'download',
        elapsed_ms: 3000,
        warmup: false,
        mbps: 90,
        avg_mbps: 90,
      },
      {
        type: 'rate',
        job_id: 3,
        direction: 'upload',
        elapsed_ms: 3000,
        warmup: false,
        mbps: 40,
        avg_mbps: 40,
      },
      {
        type: 'rate',
        job_id: 99,
        direction: 'download',
        elapsed_ms: 1,
        warmup: false,
        mbps: 5,
        avg_mbps: 5,
      },
    ]
    for (const event of events) speed.applyEvent(event)
    expect(speed.phase).toBe('download')
    expect(speed.down).toEqual([90])
    expect(speed.up).toEqual([40])
    speed.applyEvent({ type: 'done', job_id: 3, result: result(1) })
    expect(speed.running).toBe(false)
    expect(speed.results[0]?.source_ip).toBe('203.0.113.9')
  })

  it('keeps events that arrive before the start reply', async () => {
    const speed = useSpeedStore()
    let resolve: (value: unknown) => void = () => {}
    api.startSpeedTest.mockReturnValue(new Promise((r) => (resolve = r)))
    const start = speed.start({ kind: 'quick' })
    speed.applyEvent({ type: 'phase', job_id: 8, phase: 'latency' })
    expect(speed.phase).toBe('')
    resolve({ job_id: 8, rejected: ['#1: bad host'] })
    await start
    expect(speed.phase).toBe('latency')
    expect(speed.rejected).toEqual(['#1: bad host'])
  })

  it('a failure is shown, but a cancellation is not an error', async () => {
    const speed = useSpeedStore()
    api.startSpeedTest.mockResolvedValue({ job_id: 1, rejected: [] })
    await speed.start({ kind: 'bin1' })
    speed.applyEvent({ type: 'failed', job_id: 1, code: 'cancelled', message: 'cancelled' })
    expect(speed.running).toBe(false)
    expect(speed.failure).toBeNull()

    api.startSpeedTest.mockResolvedValue({ job_id: 2, rejected: [] })
    await speed.start({ kind: 'bin1' })
    speed.applyEvent({
      type: 'failed',
      job_id: 2,
      code: 'rate_limited',
      message: 'slow down',
      retry_after_secs: 30,
    })
    expect(speed.failure).toEqual({
      code: 'rate_limited',
      message: 'slow down',
      retryAfterSecs: 30,
    })
  })

  it('a refused start is reported and does not leave the page "running"', async () => {
    const speed = useSpeedStore()
    api.startSpeedTest.mockRejectedValue(new AgentCallError('bad_request', 'no speed-test server'))
    await speed.start({ kind: 'quick' })
    expect(speed.running).toBe(false)
    expect(speed.failure?.message).toBe('no speed-test server')
  })

  it('sends the saved servers and the confirmation, and keeps a bounded history', async () => {
    const speed = useSpeedStore()
    speed.setServers('https://a.example:443\nb.example')
    api.startSpeedTest.mockResolvedValue({ job_id: 1, rejected: [] })
    await speed.start({ kind: 'bin50', confirmLarge: true, streams: 8 })
    expect(api.startSpeedTest).toHaveBeenCalledWith({
      kind: 'bin50',
      servers: ['https://a.example:443', 'b.example'],
      streams: 8,
      duration_secs: undefined,
      confirm_large: true,
    })
    for (let i = 0; i < KEEP_RESULTS + 5; i += 1) {
      speed.applyEvent({ type: 'done', job_id: 1, result: result(i) })
      speed.reset()
      api.startSpeedTest.mockResolvedValue({ job_id: 1, rejected: [] })
      await speed.start({ kind: 'quick' })
    }
    expect(speed.results).toHaveLength(KEEP_RESULTS)
    expect(localStorage.getItem('pw.speed.servers')).toContain('b.example')
  })
})

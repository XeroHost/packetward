// SPDX-License-Identifier: GPL-3.0-or-later
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { DiagEvent } from '@/api/diag'
import { DiagError } from '@/api/diag'
import { PING_VISIBLE, useDiagStore } from './diag'

const api = vi.hoisted(() => ({
  startPing: vi.fn(),
  startMtr: vi.fn(),
  cancelJob: vi.fn(),
  fetchMtrReport: vi.fn(),
  dnsLookup: vi.fn(),
  portCheck: vi.fn(),
  fetchLocalPorts: vi.fn(),
}))

vi.mock('@/api/diag', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/diag')>()),
  ...api,
}))

const reply = (job: number, seq: number, ok = true): DiagEvent => ({
  type: 'ping_reply',
  job_id: job,
  reply: { seq, outcome: ok ? 'success' : 'timed_out', bytes: 32 },
})

beforeEach(() => {
  setActivePinia(createPinia())
  for (const fn of Object.values(api)) fn.mockReset()
})

describe('ping', () => {
  it('counts replies and finishes with the summary', async () => {
    const diag = useDiagStore()
    api.startPing.mockResolvedValue({ job_id: 7, target_ip: '192.0.2.1' })
    await diag.runPing('example.com', 3)
    expect(diag.pingRunning).toBe(true)
    expect(diag.pingResolved).toBe('192.0.2.1')

    diag.applyEvent(reply(7, 1))
    diag.applyEvent(reply(7, 2, false))
    expect([diag.pingSent, diag.pingReceived]).toEqual([2, 1])

    diag.applyEvent({
      type: 'ping_done',
      job_id: 7,
      summary: { target: '192.0.2.1', sent: 2, received: 1, loss_percent: 50, cancelled: false },
    })
    expect(diag.pingRunning).toBe(false)
    expect(diag.pingSummary?.loss_percent).toBe(50)
  })

  it('keeps events that arrive before the start reply', async () => {
    const diag = useDiagStore()
    let resolveStart: (value: unknown) => void = () => {}
    api.startPing.mockReturnValue(new Promise((resolve) => (resolveStart = resolve)))
    const run = diag.runPing('192.0.2.1', 2)
    diag.applyEvent(reply(9, 1)) // the job's first event beats the reply that names the job
    expect(diag.pingSent).toBe(0)
    resolveStart({ job_id: 9, target_ip: '192.0.2.1' })
    await run
    expect(diag.pingSent).toBe(1)
  })

  it('ignores events of other jobs and bounds the visible replies', async () => {
    const diag = useDiagStore()
    api.startPing.mockResolvedValue({ job_id: 1, target_ip: '192.0.2.1' })
    await diag.runPing('192.0.2.1', 500)
    diag.applyEvent(reply(2, 1))
    expect(diag.pingSent).toBe(0)
    for (let seq = 1; seq <= PING_VISIBLE + 50; seq += 1) diag.applyEvent(reply(1, seq))
    expect(diag.pingReplies).toHaveLength(PING_VISIBLE)
    expect(diag.pingReplies.at(-1)?.seq).toBe(PING_VISIBLE + 50)
    expect(diag.pingSent).toBe(PING_VISIBLE + 50)
  })

  it('reports a refused start and is free to run again', async () => {
    const diag = useDiagStore()
    api.startPing.mockRejectedValueOnce(new DiagError('busy', 'too many'))
    await diag.runPing('192.0.2.1', 3)
    expect(diag.pingRunning).toBe(false)
    expect(diag.pingError?.kind).toBe('busy')
    api.startPing.mockResolvedValue({ job_id: 3, target_ip: '192.0.2.1' })
    await diag.runPing('192.0.2.1', 3)
    expect(diag.pingError).toBeNull()
    expect(diag.pingRunning).toBe(true)
  })

  it('does not start a second ping while one runs', async () => {
    const diag = useDiagStore()
    api.startPing.mockResolvedValue({ job_id: 1, target_ip: '192.0.2.1' })
    await diag.runPing('192.0.2.1', 3)
    await diag.runPing('192.0.2.2', 3)
    expect(api.startPing).toHaveBeenCalledTimes(1)
  })
})

describe('mtr', () => {
  const snapshot = {
    target: '192.0.2.9',
    cycle: 3,
    total_cycles: 10,
    hops: [],
    destination_reached: false,
    cancelled: false,
  }

  it('shows snapshots and the report only once there is data', async () => {
    const diag = useDiagStore()
    api.startMtr.mockResolvedValue({ job_id: 4, target_ip: '192.0.2.9' })
    await diag.runMtr('192.0.2.9', 10, true)
    expect(await diag.mtrReportText()).toBeNull()
    expect(api.fetchMtrReport).not.toHaveBeenCalled()

    diag.applyEvent({ type: 'mtr_snapshot', job_id: 4, snapshot })
    expect(diag.mtrSnapshot?.cycle).toBe(3)
    api.fetchMtrReport.mockResolvedValue({ text: 'report text' })
    expect(await diag.mtrReportText()).toBe('report text')

    diag.applyEvent({ type: 'mtr_done', job_id: 4, cancelled: true })
    expect(diag.mtrRunning).toBe(false)
    expect(diag.mtrCancelled).toBe(true)
  })

  it('a failed job surfaces the agent message', async () => {
    const diag = useDiagStore()
    api.startMtr.mockResolvedValue({ job_id: 4, target_ip: '192.0.2.9' })
    await diag.runMtr('192.0.2.9', 10, false)
    diag.applyEvent({ type: 'failed', job_id: 4, message: 'raw socket denied' })
    expect(diag.mtrError?.message).toBe('raw socket denied')
    expect(diag.mtrRunning).toBe(false)
  })
})

describe('one-shot tools and reset', () => {
  it('stores results and errors of DNS and port checks', async () => {
    const diag = useDiagStore()
    api.dnsLookup.mockResolvedValue({
      query: 'a',
      requested: 'A',
      records: [],
      errors: [],
      elapsed_ms: 5,
    })
    await diag.runDns({ name: 'a', record_type: 'A', resolver: 'system', custom_servers: [] })
    expect(diag.dnsResult?.elapsed_ms).toBe(5)
    api.portCheck.mockRejectedValue(new DiagError('bad_request', 'invalid port'))
    await diag.runPortCheck({ host: 'a', port: 1, protocol: 'tcp' })
    expect(diag.portError?.message).toBe('invalid port')
    expect(diag.portResult).toBeNull()
  })

  it('reset stops anything that looks running', async () => {
    const diag = useDiagStore()
    api.startMtr.mockResolvedValue({ job_id: 4, target_ip: '192.0.2.9' })
    await diag.runMtr('192.0.2.9', 10, true)
    diag.reset()
    expect(diag.mtrRunning).toBe(false)
  })
})

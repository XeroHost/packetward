// SPDX-License-Identifier: GPL-3.0-or-later
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AgentUnsupportedError, type ConnectionsResponse } from '@/api/agent'
import { previewStats } from '@/api/preview'
import { HISTORY_POINTS, useLiveStore } from './live'

const api = vi.hoisted(() => ({ fetch: vi.fn<() => Promise<ConnectionsResponse>>() }))

vi.mock('@/api/agent', async () => {
  class AgentUnsupportedError extends Error {}
  return { AgentUnsupportedError, fetchConnections: () => api.fetch() }
})

const sample = (n: number) => {
  const stats = previewStats(n)
  stats.unix_ms = 1000 * n
  stats.totals.in_bps = n
  stats.totals.out_bps = n * 2
  return stats
}

beforeEach(() => {
  setActivePinia(createPinia())
  api.fetch.mockReset()
})

describe('history ring buffer', () => {
  it('keeps samples in time order', () => {
    const live = useLiveStore()
    for (let n = 1; n <= 5; n += 1) live.applyStats(sample(n))
    const history = live.history()
    expect(history.t).toEqual([1000, 2000, 3000, 4000, 5000])
    expect(history.inBps).toEqual([1, 2, 3, 4, 5])
    expect(history.outBps).toEqual([2, 4, 6, 8, 10])
  })

  it('never grows past its fixed size and drops the oldest first', () => {
    const live = useLiveStore()
    const extra = 40
    for (let n = 1; n <= HISTORY_POINTS + extra; n += 1) live.applyStats(sample(n))
    const history = live.history()
    expect(history.t).toHaveLength(HISTORY_POINTS)
    expect(history.inBps[0]).toBe(extra + 1)
    expect(history.inBps[HISTORY_POINTS - 1]).toBe(HISTORY_POINTS + extra)
    // Still strictly ordered after wrapping around.
    expect(history.t.every((value, i) => i === 0 || value > (history.t[i - 1] ?? 0))).toBe(true)
  })

  it('exposes the latest stats, the RDP peers, and a changing tick', () => {
    const live = useLiveStore()
    const before = live.tick
    live.applyStats(sample(1))
    expect(live.stats?.seq).toBe(1)
    expect(live.rdpPeers.has('203.0.113.50')).toBe(true)
    expect(live.tick).toBeGreaterThan(before)
  })

  it('reset forgets the data', () => {
    const live = useLiveStore()
    live.applyStats(sample(1))
    live.reset()
    expect(live.stats).toBeNull()
    expect(live.history().t).toEqual([])
    expect(live.rdpPeers.size).toBe(0)
  })
})

describe('connections', () => {
  const response: ConnectionsResponse = {
    connections: [
      {
        proto: 'tcp',
        local_addr: '10.0.0.5',
        local_port: 443,
        remote_addr: '1.2.3.4',
        remote_port: 5000,
        state: 'established',
        pid: 100,
      },
      {
        proto: 'udp',
        local_addr: '0.0.0.0',
        local_port: 53,
        remote_addr: '',
        remote_port: 0,
        pid: 999,
      },
    ],
    processes: { 100: 'nginx.exe' },
    total: 2500,
    truncated: true,
    sampled_unix_ms: 42,
  }

  it('maps the response into rows with process names and keeps the real total', async () => {
    api.fetch.mockResolvedValue(response)
    const live = useLiveStore()
    await live.loadConnections()
    expect(live.rows).toHaveLength(2)
    expect(live.rows[0]?.process).toBe('nginx.exe')
    expect(live.rows[1]?.process).toBe('')
    expect(live.rows.map((r) => r.id)).toEqual([0, 1])
    expect(live.total).toBe(2500)
    expect(live.truncated).toBe(true)
    expect(live.connectionsError).toBeNull()
  })

  it('reports an agent that is too old separately from other failures', async () => {
    const live = useLiveStore()
    api.fetch.mockRejectedValue(new AgentUnsupportedError())
    await live.loadConnections()
    expect(live.connectionsError).toBe('unsupported')
    api.fetch.mockRejectedValue(new Error('boom'))
    await live.loadConnections()
    expect(live.connectionsError).toBe('failed')
  })

  it('does not stack requests behind a slow one', async () => {
    let finish: (value: ConnectionsResponse) => void = () => {}
    api.fetch.mockReturnValue(new Promise((resolve) => (finish = resolve)))
    const live = useLiveStore()
    const first = live.loadConnections()
    await live.loadConnections()
    expect(api.fetch).toHaveBeenCalledTimes(1)
    finish(response)
    await first
    expect(live.rows).toHaveLength(2)
  })
})

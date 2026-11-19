// SPDX-License-Identifier: GPL-3.0-or-later
import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { BridgeEvent, ElevationOutcome } from '@/api/agent'
import { HEARTBEAT_STALE_MS, useAgentStore } from './agent'

const api = vi.hoisted(() => ({
  emit: null as ((event: BridgeEvent) => void) | null,
  stop: vi.fn(),
  elevate: vi.fn<() => Promise<ElevationOutcome>>(),
}))

vi.mock('@/api/agent', () => ({
  watchAgent: (onEvent: (event: BridgeEvent) => void) => {
    api.emit = onEvent
    return api.stop
  },
  elevateAgent: () => api.elevate(),
}))

const connected: BridgeEvent = {
  type: 'status',
  data: { state: 'connected', agent_version: '1.2.3', protocol_major: 1, protocol_minor: 0 },
}
const beat = (seq: number): BridgeEvent => ({
  type: 'heartbeat',
  data: { seq, uptime_secs: seq * 2, unix_ms: 1000 * seq },
})

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
  setActivePinia(createPinia())
  api.emit = null
  api.stop.mockReset()
  api.elevate.mockReset()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('agent store', () => {
  it('starts as connecting, with a neutral pill', () => {
    const agent = useAgentStore()
    expect(agent.connecting).toBe(true)
    expect(agent.connected).toBe(false)
    expect(agent.pill).toBe('unknown')
  })

  it('follows status events', () => {
    const agent = useAgentStore()
    agent.start()
    api.emit?.(connected)
    expect(agent.connected).toBe(true)
    expect(agent.pill).toBe('connected')

    api.emit?.({ type: 'status', data: { state: 'stopped' } })
    expect(agent.connected).toBe(false)
    expect(agent.connecting).toBe(false)
    expect(agent.pill).toBe('disconnected')
    expect(agent.connection.state).toBe('stopped')
  })

  it('keeps the latest heartbeat and clears it when the agent goes away', () => {
    const agent = useAgentStore()
    agent.start()
    api.emit?.(connected)
    api.emit?.(beat(1))
    api.emit?.(beat(2))
    expect(agent.heartbeat?.seq).toBe(2)

    api.emit?.({ type: 'status', data: { state: 'stopped' } })
    expect(agent.heartbeat).toBeNull()
    expect(agent.secondsSinceBeat).toBeNull()
  })

  it('reports an unresponsive agent when heartbeats stop but the pipe is still open', async () => {
    const agent = useAgentStore()
    agent.start()
    api.emit?.(connected)
    api.emit?.(beat(1))
    expect(agent.stale).toBe(false)

    await vi.advanceTimersByTimeAsync(HEARTBEAT_STALE_MS - 1000)
    expect(agent.stale).toBe(false)
    await vi.advanceTimersByTimeAsync(2000)
    expect(agent.stale).toBe(true)
    expect(agent.pill).toBe('unresponsive')
    expect(agent.secondsSinceBeat).toBeGreaterThanOrEqual(5)

    api.emit?.(beat(2))
    expect(agent.stale).toBe(false)
    expect(agent.pill).toBe('connected')
  })

  it('does not call a fresh connection unresponsive before its first beat', async () => {
    const agent = useAgentStore()
    agent.start()
    api.emit?.(connected)
    await vi.advanceTimersByTimeAsync(HEARTBEAT_STALE_MS - 500)
    expect(agent.stale).toBe(false)
  })

  it('stop() ends the watch', () => {
    const agent = useAgentStore()
    agent.start()
    agent.stop()
    expect(api.stop).toHaveBeenCalledOnce()
  })
})

describe('elevated actions', () => {
  it('records nothing when the action succeeds', async () => {
    api.elevate.mockResolvedValue({ result: 'done' })
    const agent = useAgentStore()
    await agent.runElevated('repair')
    expect(agent.elevationNotice).toBeNull()
    expect(agent.elevating).toBe(false)
  })

  it('tells a declined UAC prompt apart from a failure', async () => {
    const agent = useAgentStore()
    api.elevate.mockResolvedValue({ result: 'cancelled' })
    await agent.runElevated('start')
    expect(agent.elevationNotice).toEqual({ kind: 'cancelled' })

    api.elevate.mockResolvedValue({ result: 'failed', message: 'exit code 5' })
    await agent.runElevated('start')
    expect(agent.elevationNotice).toEqual({ kind: 'failed', message: 'exit code 5' })
  })

  it('turns a rejected call into a failure notice', async () => {
    api.elevate.mockRejectedValue(new Error('ipc broke'))
    const agent = useAgentStore()
    await agent.runElevated('repair')
    expect(agent.elevationNotice?.kind).toBe('failed')
    expect(agent.elevating).toBe(false)
  })

  it('ignores a second click while one is running', async () => {
    let finish: (outcome: ElevationOutcome) => void = () => {}
    api.elevate.mockReturnValue(new Promise((resolve) => (finish = resolve)))
    const agent = useAgentStore()
    const first = agent.runElevated('repair')
    await agent.runElevated('repair')
    expect(api.elevate).toHaveBeenCalledTimes(1)
    expect(agent.elevating).toBe(true)
    finish({ result: 'done' })
    await first
    expect(agent.elevating).toBe(false)
  })
})

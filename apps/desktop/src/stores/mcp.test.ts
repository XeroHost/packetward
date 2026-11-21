// SPDX-License-Identifier: GPL-3.0-or-later
import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { McpPendingAction } from '@/types/generated/McpPendingAction'
import { useMcpStore } from './mcp'
import { useSettingsStore } from './settings'

const api = vi.hoisted(() => ({
  fetchPendingActions: vi.fn(),
  approveMcpAction: vi.fn(),
  rejectMcpAction: vi.fn(),
  notifyActionRequest: vi.fn(),
  watchApprovalOpen: vi.fn(),
}))
vi.mock('@/api/mcp', () => api)

/** A fixed wall clock; the agent's timestamps are in nanoseconds. */
const NOW = 1_700_000_000_000

const action = (id: number, overrides: Partial<McpPendingAction> = {}): McpPendingAction => ({
  id,
  tool: 'block_ip',
  args: { ip: '203.0.113.9', ttl_secs: 3600 },
  summary: 'Block 203.0.113.9 for one hour',
  created_ts: (NOW - 1000) * 1_000_000,
  expires_ts: (NOW + 60_000) * 1_000_000,
  ...overrides,
})

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
  setActivePinia(createPinia())
  Object.values(api).forEach((fn) => fn.mockReset())
  api.watchApprovalOpen.mockResolvedValue(() => {})
})

afterEach(() => {
  vi.useRealTimers()
})

describe('snapshots', () => {
  it('replaces the queue with every snapshot', () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(1), action(2)] })
    expect(mcp.pending.map((a) => a.id)).toEqual([1, 2])
    mcp.applySnapshot({ actions: [action(2)] })
    expect(mcp.pending.map((a) => a.id)).toEqual([2])
    mcp.applySnapshot({ actions: [] })
    expect(mcp.pending).toEqual([])
  })

  it('drops an action whose five minutes ran out, without a new snapshot', () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(1), action(2, { expires_ts: (NOW + 120_000) * 1e6 })] })
    expect(mcp.count).toBe(2)
    vi.setSystemTime(NOW + 90_000)
    mcp.tick()
    expect(mcp.pending.map((a) => a.id)).toEqual([2])
    expect(mcp.actions.map((a) => a.id)).toEqual([2])
    vi.setSystemTime(NOW + 180_000)
    mcp.tick()
    expect(mcp.pending).toEqual([])
  })

  it('closes the dialog when nothing is left', () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(1)] })
    mcp.openDialog()
    expect(mcp.open).toBe(true)
    mcp.applySnapshot({ actions: [] })
    expect(mcp.open).toBe(false)
  })
})

describe('decisions', () => {
  it('approves once through the api and takes the action off the list', async () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(1), action(2)] })
    api.approveMcpAction.mockResolvedValue({ blocked: ['203.0.113.9/32'] })
    await expect(mcp.approve(1)).resolves.toBe(true)
    expect(api.approveMcpAction).toHaveBeenCalledTimes(1)
    expect(api.approveMcpAction).toHaveBeenCalledWith(1)
    expect(mcp.pending.map((a) => a.id)).toEqual([2])
  })

  it('rejects once through the api', async () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(3)] })
    api.rejectMcpAction.mockResolvedValue({ id: 3, status: 'rejected' })
    await expect(mcp.reject(3)).resolves.toBe(true)
    expect(api.rejectMcpAction).toHaveBeenCalledTimes(1)
    expect(api.rejectMcpAction).toHaveBeenCalledWith(3)
    expect(mcp.pending).toEqual([])
  })

  it('keeps the action and explains why when the agent refuses', async () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(4)] })
    const { AgentCallError } = await import('@/api/call')
    api.approveMcpAction.mockRejectedValue(new AgentCallError('bad_request', 'the action expired'))
    await expect(mcp.approve(4)).resolves.toBe(false)
    expect(mcp.pending.map((a) => a.id)).toEqual([4])
    expect(mcp.error).toEqual({ kind: 'bad_request', message: 'the action expired' })
  })

  it('does not send a second decision while one is on the way', async () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(5)] })
    let release: (value: unknown) => void = () => {}
    api.approveMcpAction.mockReturnValue(
      new Promise((resolve) => {
        release = resolve
      }),
    )
    const first = mcp.approve(5)
    await expect(mcp.approve(5)).resolves.toBe(false)
    release({})
    await first
    expect(api.approveMcpAction).toHaveBeenCalledTimes(1)
  })
})

describe('notifications', () => {
  it('only announces ids that are new since the last snapshot', () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(1)] })
    expect(api.notifyActionRequest).not.toHaveBeenCalled()
    mcp.applySnapshot({ actions: [action(1), action(2)] })
    expect(api.notifyActionRequest).toHaveBeenCalledTimes(1)
    expect(api.notifyActionRequest.mock.calls[0]?.[1]).toContain('Block 203.0.113.9')
    // The same queue again is not new.
    mcp.applySnapshot({ actions: [action(1), action(2)] })
    expect(api.notifyActionRequest).toHaveBeenCalledTimes(1)
    mcp.applySnapshot({ actions: [action(1), action(2), action(3)] })
    expect(api.notifyActionRequest).toHaveBeenCalledTimes(2)
  })

  it('follows the notification settings', () => {
    const settings = useSettingsStore()
    settings.notifications.high = false
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [] })
    mcp.applySnapshot({ actions: [action(7)] })
    expect(api.notifyActionRequest).not.toHaveBeenCalled()
  })

  it('a click on the notification opens the dialog', async () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(1)] })
    mcp.start()
    await Promise.resolve()
    await Promise.resolve()
    const handler = api.watchApprovalOpen.mock.calls[0]?.[0] as () => void
    handler()
    expect(mcp.open).toBe(true)
    mcp.stop()
  })
})

describe('connection loss', () => {
  it('reset empties the queue and closes the dialog', () => {
    const mcp = useMcpStore()
    mcp.applySnapshot({ actions: [action(1)] })
    mcp.openDialog()
    mcp.reset()
    expect(mcp.actions).toEqual([])
    expect(mcp.open).toBe(false)
    expect(mcp.loaded).toBe(false)
  })

  it('loads the queue on connect and treats the first snapshot as known', async () => {
    const mcp = useMcpStore()
    api.fetchPendingActions.mockResolvedValue({ actions: [action(1)] })
    await mcp.load()
    expect(mcp.pending.map((a) => a.id)).toEqual([1])
    expect(api.notifyActionRequest).not.toHaveBeenCalled()
  })
})

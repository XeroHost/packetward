// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AgentCallError } from '@/api/call'
import type { RdpAudit } from '@/types/generated/RdpAudit'
import { useRdpStore } from './rdp'

const api = vi.hoisted(() => ({
  fetchRdpAudit: vi.fn(),
  restrictRdp: vi.fn(),
  unrestrictRdp: vi.fn(),
  changeRdpPort: vi.fn(),
  setRdpNla: vi.fn(),
  setRdpLockout: vi.fn(),
  setRdpAttempts: vi.fn(),
  confirmRdp: vi.fn(),
  cancelRdp: vi.fn(),
  resetRdp: vi.fn(),
  endRdpSession: vi.fn(),
}))
vi.mock('@/api/rdp', () => api)

const audit = (pendingDeadline?: number): RdpAudit => ({
  enabled: true,
  port: 3389,
  nla_required: true,
  security_layer: 2,
  lockout_threshold: 0,
  lockout_window_mins: 0,
  lockout_duration_mins: 0,
  remote_desktop_users: [],
  open_to_any: true,
  restricted: false,
  allowed: [],
  builtin_rules_enabled: true,
  attempts: { threshold: 10, window_secs: 300 },
  findings: [],
  pending:
    pendingDeadline === undefined
      ? undefined
      : {
          id: 5,
          kind: 'port',
          description: 'RDP port 3389 -> 43389',
          deadline_unix_ms: pendingDeadline,
        },
  confirm_secs: 120,
})

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
  setActivePinia(createPinia())
  for (const fn of Object.values(api)) fn.mockReset()
})
afterEach(() => vi.useRealTimers())

describe('pending change', () => {
  it('counts down to the deadline and never goes negative', async () => {
    const rdp = useRdpStore()
    const deadline = Date.now() + 90_000
    api.changeRdpPort.mockResolvedValue(audit(deadline))
    expect(await rdp.changePort({ port: 43389, i_understand: true })).toBe(true)
    expect(rdp.pending?.id).toBe(5)
    expect(rdp.secondsLeft).toBe(90)
    api.fetchRdpAudit.mockResolvedValue(audit(deadline))
    rdp.startWatch()
    await vi.advanceTimersByTimeAsync(30_000)
    expect(rdp.secondsLeft).toBe(60)
    await vi.advanceTimersByTimeAsync(120_000)
    expect(rdp.secondsLeft).toBe(0)
    rdp.stopWatch()
  })

  it('confirm and cancel act on the pending id and refresh the audit', async () => {
    const rdp = useRdpStore()
    api.changeRdpPort.mockResolvedValue(audit(Date.now() + 120_000))
    await rdp.changePort({ port: 43389, i_understand: true })
    api.confirmRdp.mockResolvedValue(audit())
    expect(await rdp.confirm()).toBe(true)
    expect(api.confirmRdp).toHaveBeenCalledWith(5)
    expect(rdp.pending).toBeNull()
    expect(await rdp.cancel()).toBe(false) // nothing waiting
    expect(api.cancelRdp).not.toHaveBeenCalled()
  })
})

describe('errors', () => {
  it('keeps the agent explanation when a change is refused', async () => {
    const rdp = useRdpStore()
    api.restrictRdp.mockRejectedValue(
      new AgentCallError('bad_request', 'typed confirmation required'),
    )
    expect(await rdp.restrict({ allowed: [], disable_builtin: true })).toBe(false)
    expect(rdp.error?.message).toContain('confirmation')
    expect(rdp.busy).toBe(false)
  })

  it('an older agent without the Shield shows no error', async () => {
    const rdp = useRdpStore()
    api.fetchRdpAudit.mockRejectedValue(new AgentCallError('unsupported', 'unsupported'))
    await rdp.load()
    expect(rdp.error).toBeNull()
    expect(rdp.audit).toBeNull()
  })

  it('disconnecting the agent stops the watch and forgets the audit', async () => {
    const rdp = useRdpStore()
    api.fetchRdpAudit.mockResolvedValue(audit())
    rdp.startWatch()
    await vi.advanceTimersByTimeAsync(10)
    expect(rdp.audit).not.toBeNull()
    rdp.disconnect()
    expect(rdp.audit).toBeNull()
    api.fetchRdpAudit.mockClear()
    await vi.advanceTimersByTimeAsync(10_000)
    expect(api.fetchRdpAudit).not.toHaveBeenCalled()
  })
})

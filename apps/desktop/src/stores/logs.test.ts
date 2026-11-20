// SPDX-License-Identifier: GPL-3.0-or-later
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { auditToCsv, auditToJson, useLogsStore } from './logs'

const api = vi.hoisted(() => ({
  auditLog: vi.fn(),
  getAgentSettings: vi.fn(),
  setProxy: vi.fn(),
}))
vi.mock('@/api/agentSettings', () => api)

beforeEach(() => {
  setActivePinia(createPinia())
  for (const fn of Object.values(api)) fn.mockReset()
})

const entry = (detail: string) => ({
  unix_ms: 1_700_000_000_000,
  actor: 'operator',
  action: 'block',
  target: '203.0.113.5',
  detail,
  result: 'ok',
})

describe('exports', () => {
  it('quotes CSV fields and neutralises spreadsheet formulas', () => {
    const csv = auditToCsv([entry('=HYPERLINK("http://x")'), entry('a, b')])
    const lines = csv.trimEnd().split('\n')
    expect(lines[0]).toBe('time,actor,action,target,detail,result')
    expect(lines[1]).toContain(`"'=HYPERLINK(""http://x"")"`)
    expect(lines[2]).toContain('"a, b"')
  })

  it('writes JSON', () => {
    expect(JSON.parse(auditToJson([entry('x')]))[0].target).toBe('203.0.113.5')
  })
})

describe('the store', () => {
  it('loads the log with the search text', async () => {
    api.auditLog.mockResolvedValue({ entries: [entry('x')], truncated: true })
    const logs = useLogsStore()
    await logs.load(' block ')
    expect(api.auditLog).toHaveBeenCalledWith(500, 'block')
    expect(logs.entries).toHaveLength(1)
    expect(logs.truncated).toBe(true)
  })

  it('reports a failed load', async () => {
    api.auditLog.mockRejectedValue(new Error('pipe closed'))
    const logs = useLogsStore()
    await logs.load()
    expect(logs.error).toBe('pipe closed')
    expect(logs.loading).toBe(false)
  })

  it('saves a proxy, sending null to go back to the system proxy', async () => {
    api.setProxy.mockResolvedValue({ proxy: 'http://p:1', restart_required: true })
    const logs = useLogsStore()
    expect(await logs.saveProxy(' http://p:1 ')).toBe(true)
    expect(api.setProxy).toHaveBeenCalledWith({ proxy: 'http://p:1' })
    await logs.saveProxy('  ')
    expect(api.setProxy).toHaveBeenLastCalledWith({ proxy: null })
  })

  it('sends the credentials next to the address, never inside it', async () => {
    api.setProxy.mockResolvedValue({ proxy: 'http://p:1', restart_required: true })
    const logs = useLogsStore()
    await logs.saveProxy('http://p:1', { username: 'alice', password: 'hunter2' })
    expect(api.setProxy).toHaveBeenCalledWith({
      proxy: 'http://p:1',
      username: 'alice',
      password: 'hunter2',
    })
    await logs.saveProxy('http://p:1', { clearCredentials: true })
    expect(api.setProxy).toHaveBeenLastCalledWith({ proxy: 'http://p:1', clearCredentials: true })
  })

  it('keeps the error of a refused proxy', async () => {
    api.setProxy.mockRejectedValue(
      new Error('the proxy address must not contain a user name or password'),
    )
    const logs = useLogsStore()
    expect(await logs.saveProxy('http://u:p@h:1')).toBe(false)
    expect(logs.settingsError).toContain('password')
  })
})

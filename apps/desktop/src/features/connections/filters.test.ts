// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import type { ConnectionRow } from '@/stores/live'
import { applyFilters } from './filters'

const rows: ConnectionRow[] = [
  {
    id: 0,
    proto: 'tcp',
    local_addr: '10.0.0.5',
    local_port: 3389,
    remote_addr: '203.0.113.50',
    remote_port: 51234,
    state: 'established',
    pid: 1340,
    process: 'svchost.exe',
  },
  {
    id: 1,
    proto: 'tcp',
    local_addr: '10.0.0.5',
    local_port: 443,
    remote_addr: '198.51.100.7',
    remote_port: 40000,
    state: 'time_wait',
    pid: 2204,
    process: 'nginx.exe',
  },
  {
    id: 2,
    proto: 'tcp',
    local_addr: '0.0.0.0',
    local_port: 1433,
    remote_addr: '',
    remote_port: 0,
    state: 'listen',
    pid: 3120,
    process: 'sqlservr.exe',
  },
  {
    id: 3,
    proto: 'udp',
    local_addr: '0.0.0.0',
    local_port: 5353,
    remote_addr: '',
    remote_port: 0,
    pid: 5120,
    process: '',
  },
]

const none = { proto: 'all', state: 'all', search: '' } as const
const ids = (list: ConnectionRow[]) => list.map((row) => row.id)

describe('applyFilters', () => {
  it('returns everything without filters, as a copy', () => {
    const all = applyFilters(rows, none)
    expect(ids(all)).toEqual([0, 1, 2, 3])
    expect(all).not.toBe(rows)
  })

  it('filters by protocol and by state', () => {
    expect(ids(applyFilters(rows, { ...none, proto: 'udp' }))).toEqual([3])
    expect(ids(applyFilters(rows, { ...none, proto: 'tcp' }))).toEqual([0, 1, 2])
    expect(ids(applyFilters(rows, { ...none, state: 'listen' }))).toEqual([2])
    expect(ids(applyFilters(rows, { ...none, proto: 'udp', state: 'listen' }))).toEqual([])
  })

  it('searches process names case-insensitively', () => {
    expect(ids(applyFilters(rows, { ...none, search: 'NGINX' }))).toEqual([1])
  })

  it('searches addresses by substring and ports or PIDs exactly', () => {
    expect(ids(applyFilters(rows, { ...none, search: '203.0.113' }))).toEqual([0])
    expect(ids(applyFilters(rows, { ...none, search: '443' }))).toEqual([1])
    expect(ids(applyFilters(rows, { ...none, search: '44' }))).toEqual([]) // not a substring match for ports
    expect(ids(applyFilters(rows, { ...none, search: '3120' }))).toEqual([2])
  })

  it('combines filters and ignores surrounding spaces', () => {
    expect(
      ids(applyFilters(rows, { proto: 'tcp', state: 'established', search: '  svchost ' })),
    ).toEqual([0])
  })

  it('handles tens of thousands of rows in one quick pass', () => {
    const many: ConnectionRow[] = Array.from({ length: 50_000 }, (_, i) => ({
      ...rows[1]!,
      id: i,
      remote_addr: `198.51.${i % 250}.${i % 200}`,
    }))
    const started = performance.now()
    const result = applyFilters(many, { ...none, search: '198.51.7.' })
    expect(result.length).toBeGreaterThan(0)
    expect(performance.now() - started).toBeLessThan(500)
  })
})

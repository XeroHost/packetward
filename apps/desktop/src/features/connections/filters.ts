// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import type { ConnectionRow } from '@/stores/live'
import type { TcpState } from '@/types/generated/TcpState'

export type ProtoFilter = 'all' | 'tcp' | 'udp'
export type StateFilter = 'all' | TcpState

export interface Filters {
  proto: ProtoFilter
  state: StateFilter
  /** Free text: matches the process name, either address, either port or the PID. */
  search: string
}

/**
 * The rows that pass every filter. Runs over up to tens of thousands of rows, so it does one pass
 * and lowercases the search text once.
 */
export function applyFilters(rows: readonly ConnectionRow[], filters: Filters): ConnectionRow[] {
  const needle = filters.search.trim().toLowerCase()
  if (filters.proto === 'all' && filters.state === 'all' && needle === '') return [...rows]
  return rows.filter((row) => {
    if (filters.proto !== 'all' && row.proto !== filters.proto) return false
    if (filters.state !== 'all' && row.state !== filters.state) return false
    if (needle === '') return true
    return (
      row.process.toLowerCase().includes(needle) ||
      row.local_addr.includes(needle) ||
      row.remote_addr.includes(needle) ||
      String(row.local_port) === needle ||
      String(row.remote_port) === needle ||
      String(row.pid) === needle
    )
  })
}

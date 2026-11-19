// SPDX-License-Identifier: GPL-3.0-or-later
import { defineStore } from 'pinia'
import { computed, ref, shallowRef } from 'vue'
import { AgentUnsupportedError, fetchConnections } from '@/api/agent'
import type { Connection } from '@/types/generated/Connection'
import type { LiveStats } from '@/types/generated/LiveStats'

/** Seconds of history the dashboard chart keeps (one point per second). */
export const HISTORY_POINTS = 300

/** A connection plus what the table needs to show and sort it. */
export interface ConnectionRow extends Connection {
  id: number
  /** Image name of the owning process, or '' when Windows would not tell us. */
  process: string
  /** "10.0.0.5:443" / "[2001:db8::1]:443", or '' for an empty address. Built once per refresh. */
  local: string
  remote: string
}

/** IPv6 with a port needs brackets: [2001:db8::1]:443. */
export function endpointText(addr: string, port: number): string {
  if (!addr) return ''
  return addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`
}

export interface History {
  /** Unix ms of each sample, oldest first. */
  t: number[]
  inBps: number[]
  outBps: number[]
}

export type ConnectionsError = 'unsupported' | 'failed'

/**
 * Live network data from the agent: the latest `live.stats`, a fixed-size history of the traffic
 * (never grows past HISTORY_POINTS) and the connection table of the Connections page.
 */
export const useLiveStore = defineStore('live', () => {
  const stats = shallowRef<LiveStats | null>(null)

  // Ring buffer: three preallocated arrays and a write position. No per-tick allocation.
  const times = new Float64Array(HISTORY_POINTS)
  const inSeries = new Float64Array(HISTORY_POINTS)
  const outSeries = new Float64Array(HISTORY_POINTS)
  let next = 0
  let count = 0
  /** Bumped on every sample so watchers know the history changed. */
  const tick = ref(0)

  function applyStats(snapshot: LiveStats): void {
    stats.value = snapshot
    times[next] = snapshot.unix_ms
    inSeries[next] = snapshot.totals.in_bps
    outSeries[next] = snapshot.totals.out_bps
    next = (next + 1) % HISTORY_POINTS
    count = Math.min(count + 1, HISTORY_POINTS)
    tick.value += 1
  }

  /** The history in time order. Copies at most HISTORY_POINTS numbers per series. */
  function history(): History {
    const out: History = { t: [], inBps: [], outBps: [] }
    const start = count < HISTORY_POINTS ? 0 : next
    for (let i = 0; i < count; i += 1) {
      const at = (start + i) % HISTORY_POINTS
      out.t.push(times[at] ?? 0)
      out.inBps.push(inSeries[at] ?? 0)
      out.outBps.push(outSeries[at] ?? 0)
    }
    return out
  }

  /** Addresses with an established connection to the RDP port: the real RDP clients. */
  const rdpPeers = computed(() => new Set(stats.value?.rdp_peers ?? []))

  // ---- Connections page -------------------------------------------------------------------
  const rows = shallowRef<ConnectionRow[]>([])
  const total = ref(0)
  const truncated = ref(false)
  const sampledAt = ref<number | null>(null)
  const connectionsError = ref<ConnectionsError | null>(null)
  let loading = false

  async function loadConnections(): Promise<void> {
    if (loading) return // never stack requests behind a slow one
    loading = true
    try {
      const response = await fetchConnections()
      rows.value = response.connections.map((connection, id) => ({
        ...connection,
        id,
        process: response.processes[connection.pid] ?? '',
        local: endpointText(connection.local_addr, connection.local_port),
        remote: endpointText(connection.remote_addr, connection.remote_port),
      }))
      total.value = response.total
      truncated.value = response.truncated
      sampledAt.value = response.sampled_unix_ms
      connectionsError.value = null
    } catch (err) {
      connectionsError.value = err instanceof AgentUnsupportedError ? 'unsupported' : 'failed'
    } finally {
      loading = false
    }
  }

  /** Forgets everything when the agent goes away, so nothing stale is shown as live. */
  function reset(): void {
    stats.value = null
    next = 0
    count = 0
    tick.value += 1
    rows.value = []
    total.value = 0
    truncated.value = false
    sampledAt.value = null
    connectionsError.value = null
  }

  return {
    stats,
    tick,
    rdpPeers,
    rows,
    total,
    truncated,
    sampledAt,
    connectionsError,
    applyStats,
    history,
    loadConnections,
    reset,
  }
})

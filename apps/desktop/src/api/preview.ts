// SPDX-License-Identifier: GPL-3.0-or-later
// Synthetic agent data for a plain browser (UI development, screenshots, performance checks).
// Never used inside the Tauri app, where the real agent answers.
import type { Connection } from '@/types/generated/Connection'
import type { ConnectionsResponse } from '@/types/generated/ConnectionsResponse'
import type { LiveStats } from '@/types/generated/LiveStats'
import type { TcpState } from '@/types/generated/TcpState'

const PROCESSES: Record<number, string> = {
  4: 'System',
  1340: 'svchost.exe',
  2204: 'nginx.exe',
  3120: 'sqlservr.exe',
  4408: 'node.exe',
  5120: 'chrome.exe',
  6004: 'MsMpEng.exe',
}
const PIDS = Object.keys(PROCESSES).map(Number)
const STATES: TcpState[] = [
  'established',
  'established',
  'established',
  'time_wait',
  'syn_received',
  'close_wait',
  'fin_wait2',
]
const RDP_PEER = '203.0.113.50'

/** Small deterministic PRNG so the same row count always gives the same table. */
function rng(seed: number): () => number {
  let state = seed >>> 0 || 1
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0
    return state / 0x100000000
  }
}

function remoteAddress(random: () => number): string {
  if (random() < 0.15) {
    const group = (n: number) => Math.floor(random() * n).toString(16)
    return `2001:db8:${group(0xffff)}::${group(0xffff)}`
  }
  return `${198 + Math.floor(random() * 3)}.51.${Math.floor(random() * 256)}.${1 + Math.floor(random() * 254)}`
}

/** A believable connection table with `count` rows (listeners, UDP endpoints, TCP in many states). */
export function previewConnections(count: number): ConnectionsResponse {
  const random = rng(count + 7)
  const rows: Connection[] = []
  for (let i = 0; i < count; i += 1) {
    const kind = random()
    const pid = PIDS[Math.floor(random() * PIDS.length)] ?? 4
    if (kind < 0.05) {
      rows.push({
        proto: 'tcp',
        local_addr: '0.0.0.0',
        local_port: 1000 + (i % 60000),
        remote_addr: '',
        remote_port: 0,
        state: 'listen',
        pid,
      })
    } else if (kind < 0.12) {
      rows.push({
        proto: 'udp',
        local_addr: '0.0.0.0',
        local_port: 1000 + (i % 60000),
        remote_addr: '',
        remote_port: 0,
        pid,
      })
    } else {
      const rdp = random() < 0.01
      rows.push({
        proto: 'tcp',
        local_addr: '10.0.0.5',
        local_port: rdp ? 3389 : 443,
        remote_addr: rdp ? RDP_PEER : remoteAddress(random),
        remote_port: 1024 + Math.floor(random() * 60000),
        state: rdp
          ? 'established'
          : (STATES[Math.floor(random() * STATES.length)] ?? 'established'),
        pid: rdp ? 1340 : pid,
      })
    }
  }
  return {
    connections: rows,
    processes: PROCESSES,
    total: rows.length,
    truncated: false,
    sampled_unix_ms: Date.now(),
  }
}

/** One `live.stats` snapshot of a lightly loaded server; the rates wobble so charts move. */
export function previewStats(seq: number): LiveStats {
  const wave = 0.5 + 0.5 * Math.sin(seq / 6)
  const inBps = 4_000_000 + wave * 30_000_000
  const outBps = 1_000_000 + (1 - wave) * 9_000_000
  return {
    seq,
    unix_ms: Date.now(),
    interfaces: [
      {
        index: 15,
        name: 'Ethernet',
        description: 'Red Hat VirtIO Ethernet Adapter',
        kind: 'ethernet',
        up: true,
        counts_toward_total: true,
        link_speed_bps: 10_000_000_000,
        in_bps: inBps,
        out_bps: outBps,
        in_pps: inBps / 8 / 900,
        out_pps: outBps / 8 / 700,
      },
      {
        index: 31,
        name: 'WireGuard',
        description: 'WireGuard Tunnel',
        kind: 'tunnel',
        up: true,
        counts_toward_total: false,
        link_speed_bps: 0,
        in_bps: 50_000,
        out_bps: 20_000,
        in_pps: 60,
        out_pps: 30,
      },
    ],
    totals: {
      in_bps: inBps,
      out_bps: outBps,
      in_pps: inBps / 8 / 900,
      out_pps: outBps / 8 / 700,
      link_speed_bps: 10_000_000_000,
    },
    connections: {
      total: 312,
      established: 118,
      listen: 40,
      time_wait: 120,
      syn_received: 4,
      other_tcp: 10,
      udp: 20,
    },
    top_remote: [
      { addr: '198.51.100.7', connections: 41 },
      { addr: RDP_PEER, connections: 3 },
      { addr: '2001:db8::17', connections: 2 },
    ],
    rdp_sessions: [
      {
        session_id: 2,
        user: 'Administrator',
        state: 'active',
        reported_addr: '100.64.0.9',
        client_name: 'LAPTOP',
      },
    ],
    rdp_peers: [RDP_PEER],
    rdp_port: 3389,
  }
}

/** How many rows the browser preview serves, from `?rows=N` (default 400, at most 100 000). */
export function previewRowCount(): number {
  if (typeof window === 'undefined') return 400
  const raw = new URLSearchParams(window.location.search).get('rows')
  const parsed = raw === null ? Number.NaN : Number.parseInt(raw, 10)
  return Number.isFinite(parsed) ? Math.min(Math.max(parsed, 0), 100_000) : 400
}

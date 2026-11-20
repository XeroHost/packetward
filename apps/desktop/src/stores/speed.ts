// SPDX-License-Identifier: GPL-3.0-or-later
import { defineStore } from 'pinia'
import { ref, shallowRef } from 'vue'
import * as api from '@/api/speed'
import { AgentCallError } from '@/api/call'
import type { SpeedEvent } from '@/types/generated/SpeedEvent'
import type { SpeedKind } from '@/types/generated/SpeedKind'
import type { SpeedResultView } from '@/types/generated/SpeedResultView'

const STORAGE_KEY = 'pw.speed.servers'
const PROVIDER_KEY = 'pw.speed.provider'

/** The provider groups the agent understands (`speed.start` `provider`). */
export const PROVIDERS = ['auto', 'cloudflare', 'hetzner', 'ovh', 'xerohost', 'custom'] as const
export type SpeedProvider = (typeof PROVIDERS)[number]

/** Largest bin test (in GB) each provider offers; 0 = none. Mirrors the agent's limits so the buttons say so. */
export const BIN_LIMIT_GB: Record<SpeedProvider, number> = {
  auto: 50,
  cloudflare: 0,
  hetzner: 10,
  ovh: 1,
  xerohost: 50,
  custom: 50,
}
/** Results kept on the page (newest first). */
export const KEEP_RESULTS = 10
/** Live rate samples kept for the running test (one per second). */
export const KEEP_SAMPLES = 180

export interface SpeedFailure {
  code: string
  message: string
  retryAfterSecs?: number
}

function loadProvider(): SpeedProvider {
  try {
    const saved = localStorage.getItem(PROVIDER_KEY)
    return (PROVIDERS as readonly string[]).includes(saved ?? '')
      ? (saved as SpeedProvider)
      : 'auto'
  } catch {
    return 'auto'
  }
}

function loadServers(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) ?? ''
  } catch {
    return ''
  }
}

/**
 * The speed test: one run at a time, its live progress, and the last results. Custom servers are a
 * per-viewer convenience kept in the browser storage of this app.
 */
export const useSpeedStore = defineStore('speed', () => {
  const servers = ref(loadServers())
  const provider = ref<SpeedProvider>(loadProvider())
  const jobId = ref<number | null>(null)
  const running = ref(false)
  const phase = ref('')
  const kind = ref<SpeedKind>('quick')
  const pings = shallowRef<(number | null)[]>([])
  /** Download and upload rate samples of the running quick test, and the bin test. */
  const down = shallowRef<number[]>([])
  const up = shallowRef<number[]>([])
  const bin = ref<{ done: number; total: number; mbps: number; avg: number } | null>(null)
  const results = shallowRef<SpeedResultView[]>([])
  const failure = ref<SpeedFailure | null>(null)
  const rejected = ref<string[]>([])

  /** Events that arrive before the start reply names the job are kept for a moment. */
  let early: SpeedEvent[] = []

  function setServers(text: string): void {
    servers.value = text
    try {
      localStorage.setItem(STORAGE_KEY, text)
    } catch {
      // The list simply is not remembered.
    }
  }

  function setProvider(value: SpeedProvider): void {
    provider.value = value
    try {
      localStorage.setItem(PROVIDER_KEY, value)
    } catch {
      // The choice simply is not remembered.
    }
  }

  function list(): string[] {
    return servers.value
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter((s) => s !== '')
  }

  function apply(event: SpeedEvent): void {
    if (event.job_id !== jobId.value) return
    switch (event.type) {
      case 'phase':
        phase.value = event.phase
        break
      case 'ping':
        pings.value = [...pings.value, event.rtt_ms ?? null].slice(-KEEP_SAMPLES)
        break
      case 'rate': {
        if (event.warmup) break
        const target = event.direction === 'download' ? down : up
        target.value = [...target.value, event.mbps].slice(-KEEP_SAMPLES)
        break
      }
      case 'bin':
        bin.value = {
          done: event.bytes_done,
          total: event.bytes_total,
          mbps: event.mbps,
          avg: event.avg_mbps,
        }
        down.value = [...down.value, event.mbps].slice(-KEEP_SAMPLES)
        break
      case 'done':
        results.value = [event.result, ...results.value].slice(0, KEEP_RESULTS)
        running.value = false
        phase.value = ''
        break
      case 'failed':
        running.value = false
        phase.value = ''
        if (event.code !== 'cancelled') {
          failure.value = {
            code: event.code,
            message: event.message,
            retryAfterSecs: event.retry_after_secs,
          }
        }
        break
    }
  }

  /** Called for every `speed.progress` message from the agent. */
  function applyEvent(event: SpeedEvent): void {
    if (jobId.value === null && running.value) {
      early.push(event)
      if (early.length > 64) early = early.slice(-64)
      return
    }
    apply(event)
  }

  async function start(request: {
    kind: SpeedKind
    confirmLarge?: boolean
    streams?: number
    durationSecs?: number
  }): Promise<void> {
    if (running.value) return
    failure.value = null
    rejected.value = []
    pings.value = []
    down.value = []
    up.value = []
    bin.value = null
    kind.value = request.kind
    jobId.value = null
    early = []
    running.value = true
    try {
      const started = await api.startSpeedTest({
        kind: request.kind,
        provider: provider.value,
        servers: list(),
        streams: request.streams,
        duration_secs: request.durationSecs,
        confirm_large: request.confirmLarge ?? false,
      })
      jobId.value = started.job_id
      rejected.value = started.rejected
      const queued = early
      early = []
      for (const event of queued) apply(event)
    } catch (err) {
      running.value = false
      failure.value = {
        code: err instanceof AgentCallError ? err.kind : 'failed',
        message: err instanceof Error ? err.message : String(err),
      }
    }
  }

  async function cancel(): Promise<void> {
    if (jobId.value !== null) await api.cancelSpeedTest(jobId.value).catch(() => undefined)
  }

  /** The agent went away: a test cannot still be running. */
  function reset(): void {
    running.value = false
    jobId.value = null
    phase.value = ''
  }

  return {
    servers,
    provider,
    setProvider,
    jobId,
    running,
    phase,
    kind,
    pings,
    down,
    up,
    bin,
    results,
    failure,
    rejected,
    setServers,
    applyEvent,
    start,
    cancel,
    reset,
  }
})

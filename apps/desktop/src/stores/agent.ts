// SPDX-License-Identifier: GPL-3.0-or-later
import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import {
  elevateAgent,
  watchAgent,
  type AgentConnection,
  type BridgeEvent,
  type ElevatedAction,
} from '@/api/agent'
import type { Heartbeat } from '@/types/generated/Heartbeat'
import { useAlertsStore } from './alerts'
import { useCaptureStore } from './capture'
import { useDiagStore } from './diag'
import { useLiveStore } from './live'

/** What the top-bar pill shows. */
export type AgentPill = 'unknown' | 'connected' | 'unresponsive' | 'disconnected'
export type GuardianMode = 'off' | 'monitor' | 'active'

/** A heartbeat is due every second; this many missed seconds means the agent is not answering. */
export const HEARTBEAT_STALE_MS = 5000

export const useAgentStore = defineStore('agent', () => {
  const connection = ref<AgentConnection>({ state: 'connecting' })
  const heartbeat = ref<Heartbeat | null>(null)
  const lastBeatAt = ref<number | null>(null)
  const now = ref(Date.now())
  const guardianMode = ref<GuardianMode | null>(null)

  const elevating = ref(false)
  const elevationNotice = ref<{ kind: 'cancelled' | 'failed'; message?: string } | null>(null)

  const connected = computed(() => connection.value.state === 'connected')
  const connecting = computed(() => connection.value.state === 'connecting')
  const stale = computed(
    () =>
      connected.value &&
      lastBeatAt.value !== null &&
      now.value - lastBeatAt.value > HEARTBEAT_STALE_MS,
  )
  const secondsSinceBeat = computed(() =>
    lastBeatAt.value === null
      ? null
      : Math.max(0, Math.floor((now.value - lastBeatAt.value) / 1000)),
  )
  const pill = computed<AgentPill>(() => {
    if (connecting.value) return 'unknown'
    if (!connected.value) return 'disconnected'
    return stale.value ? 'unresponsive' : 'connected'
  })

  function apply(event: BridgeEvent): void {
    if (event.type === 'status') {
      connection.value = event.data
      if (event.data.state !== 'connected') {
        heartbeat.value = null
        lastBeatAt.value = null
        // Nothing stale may look live once the agent is gone.
        useLiveStore().reset()
        useDiagStore().reset()
        useCaptureStore().reset()
        useAlertsStore().reset()
      } else {
        // Connecting counts as a sign of life: do not report "unresponsive" before the first beat.
        lastBeatAt.value = Date.now()
        now.value = Date.now()
        // The inbox starts with what the agent already knows about.
        void useAlertsStore().load()
      }
      return
    }
    if (event.type === 'stats') {
      useLiveStore().applyStats(event.data)
      return
    }
    if (event.type === 'alert') {
      useAlertsStore().applyEvent(event.data)
      return
    }
    if (event.type === 'capture') {
      useCaptureStore().applyLive(event.data)
      return
    }
    if (event.type === 'diag') {
      useDiagStore().applyEvent(event.data)
      return
    }
    heartbeat.value = event.data
    lastBeatAt.value = Date.now()
    now.value = Date.now()
  }

  let stopWatch: (() => void) | null = null
  let ticker: ReturnType<typeof setInterval> | null = null

  /** Begins following the agent. Safe to call once at start-up. */
  function start(): void {
    stop()
    stopWatch = watchAgent(apply)
    // Re-evaluates `stale` between events.
    ticker = setInterval(() => {
      now.value = Date.now()
    }, 1000)
  }

  function stop(): void {
    stopWatch?.()
    stopWatch = null
    if (ticker !== null) clearInterval(ticker)
    ticker = null
  }

  /** Start/Repair through a UAC prompt. The supervisor notices the result on its own. */
  async function runElevated(action: ElevatedAction): Promise<void> {
    if (elevating.value) return
    elevating.value = true
    elevationNotice.value = null
    try {
      const outcome = await elevateAgent(action)
      if (outcome.result === 'cancelled') elevationNotice.value = { kind: 'cancelled' }
      else if (outcome.result === 'failed')
        elevationNotice.value = { kind: 'failed', message: outcome.message }
    } catch (err) {
      elevationNotice.value = { kind: 'failed', message: String(err) }
    } finally {
      elevating.value = false
    }
  }

  return {
    connection,
    heartbeat,
    guardianMode,
    elevating,
    elevationNotice,
    connected,
    connecting,
    stale,
    secondsSinceBeat,
    pill,
    apply,
    start,
    stop,
    runElevated,
  }
})

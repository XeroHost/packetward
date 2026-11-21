// SPDX-License-Identifier: GPL-3.0-or-later
import { defineStore } from 'pinia'
import { computed, ref, shallowRef } from 'vue'
import { AgentCallError, type CallErrorKind } from '@/api/call'
import {
  approveMcpAction,
  fetchPendingActions,
  notifyActionRequest,
  rejectMcpAction,
  watchApprovalOpen,
  type McpPendingAction,
  type McpPendingList,
} from '@/api/mcp'
import { i18n } from '@/app/i18n'
import { useSettingsStore } from './settings'

/**
 * The agent's approval queue is small (it refuses new requests when it is full); this bound only
 * guards against a broken snapshot growing the UI's memory.
 */
export const MAX_PENDING = 32

/** Nanoseconds in a millisecond, for the agent's `expires_ts`. */
const NS_PER_MS = 1_000_000

export type McpFailure = { kind: CallErrorKind; message: string }

function failure(err: unknown): McpFailure {
  if (err instanceof AgentCallError) return { kind: err.kind, message: err.message }
  return { kind: 'failed', message: String(err) }
}

/** Milliseconds until this action expires (never negative). */
export function millisecondsLeft(action: McpPendingAction, now: number): number {
  return Math.max(0, action.expires_ts / NS_PER_MS - now)
}

/**
 * The MCP approval queue. The agent publishes the whole queue after every change, so every
 * snapshot replaces the list; the store also drops actions whose five minutes are up, decides
 * which are "new" (for the Windows notification) and drives the banner and the dialog.
 */
export const useMcpStore = defineStore('mcp', () => {
  const actions = shallowRef<McpPendingAction[]>([])
  const loaded = ref(false)
  const failed = ref(false)
  /** Whether the approval dialog is open (the banner can open it from any page). */
  const open = ref(false)
  const error = ref<McpFailure | null>(null)
  const now = ref(Date.now())
  /** Ids with an approve/reject on the way; their buttons are disabled meanwhile. */
  const busy = ref<number[]>([])
  /** Highest id announced to the user; only newer ids raise a notification. */
  const seenUpTo = ref(0)

  /** What still waits for a decision (expired entries disappear without a new snapshot). */
  const pending = computed(() =>
    actions.value.filter((action) => millisecondsLeft(action, now.value) > 0),
  )
  const count = computed(() => pending.value.length)

  function secondsLeft(action: McpPendingAction): number {
    return Math.ceil(millisecondsLeft(action, now.value) / 1000)
  }

  function closeIfEmpty(): void {
    if (pending.value.length === 0) open.value = false
  }

  /** Between snapshots: expire locally so a dead approval never stays on screen. */
  function tick(): void {
    now.value = Date.now()
    if (actions.value.some((action) => millisecondsLeft(action, now.value) <= 0)) {
      actions.value = pending.value
    }
    closeIfEmpty()
  }

  function announce(action: McpPendingAction): void {
    // The notification settings of the alert inbox are the only mute switch there is so far.
    if (!useSettingsStore().notifications.high) return
    const t = i18n.global.t
    void notifyActionRequest(
      t('mcp.approval.toast.title'),
      t('mcp.approval.toast.body', { summary: action.summary }),
    )
  }

  /** Applies a full queue snapshot. The first one after (re)connecting is not "new". */
  function applySnapshot(snapshot: McpPendingList): void {
    const list = snapshot.actions.slice(0, MAX_PENDING)
    actions.value = list
    now.value = Date.now()
    error.value = null
    if (!loaded.value) {
      // What already waited when the app started is shown by the banner, without a toast.
      seenUpTo.value = Math.max(seenUpTo.value, ...list.map((action) => action.id))
    } else {
      const fresh = list.filter((action) => action.id > seenUpTo.value).sort((a, b) => a.id - b.id)
      if (fresh.length > 0) {
        seenUpTo.value = Math.max(seenUpTo.value, ...list.map((action) => action.id))
        if (fresh[0]) announce(fresh[0])
      }
    }
    loaded.value = true
    closeIfEmpty()
  }

  /** First fetch on connect/reconnect (the agent also sends the queue as the first snapshot). */
  async function load(): Promise<void> {
    try {
      applySnapshot(await fetchPendingActions())
      failed.value = false
    } catch (err) {
      failed.value = !(err instanceof AgentCallError && err.kind === 'unsupported')
    }
  }

  async function decide(
    id: number,
    call: (actionId: number) => Promise<unknown>,
  ): Promise<boolean> {
    if (busy.value.includes(id)) return false
    busy.value = [...busy.value, id]
    error.value = null
    try {
      await call(id)
      // The agent publishes a new snapshot right after; dropping it here makes the decision
      // final for the buttons without waiting for the round trip.
      actions.value = actions.value.filter((action) => action.id !== id)
      closeIfEmpty()
      return true
    } catch (err) {
      error.value = failure(err)
      return false
    } finally {
      busy.value = busy.value.filter((pendingId) => pendingId !== id)
    }
  }

  const approve = (id: number) => decide(id, approveMcpAction)
  const reject = (id: number) => decide(id, rejectMcpAction)

  function openDialog(): void {
    if (pending.value.length > 0) open.value = true
  }

  function closeDialog(): void {
    open.value = false
  }

  let ticker: ReturnType<typeof setInterval> | null = null
  let stopListen: (() => void) | null = null
  let listening = false

  /** Starts the countdown tick and the "notification clicked" listener. */
  function start(): void {
    if (ticker === null) ticker = setInterval(tick, 1000)
    if (!listening) {
      listening = true
      void watchApprovalOpen(openDialog).then((off) => {
        // One component mounts once, but a hot reload may stop before this resolves.
        if (listening) stopListen = off
        else off()
      })
    }
  }

  function stop(): void {
    if (ticker !== null) clearInterval(ticker)
    ticker = null
    listening = false
    stopListen?.()
    stopListen = null
  }

  /** The agent went away: nothing it queued can be approved any more. */
  function reset(): void {
    actions.value = []
    loaded.value = false
    failed.value = false
    open.value = false
    error.value = null
    busy.value = []
  }

  return {
    actions,
    loaded,
    failed,
    open,
    error,
    now,
    busy,
    pending,
    count,
    seenUpTo,
    secondsLeft,
    applySnapshot,
    load,
    approve,
    reject,
    openDialog,
    closeDialog,
    tick,
    start,
    stop,
    reset,
  }
})

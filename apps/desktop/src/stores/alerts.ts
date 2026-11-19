// SPDX-License-Identifier: GPL-3.0-or-later
import { defineStore } from 'pinia'
import { computed, ref, shallowRef } from 'vue'
import { fetchAlerts, clearEndedAlerts } from '@/api/alerts'
import { AgentCallError } from '@/api/call'
import { notifyAlert, setTrayState, type TrayState } from '@/api/shell'
import { i18n } from '@/app/i18n'
import type { AlertSeverity } from '@/types/generated/AlertSeverity'
import type { AlertView } from '@/types/generated/AlertView'
import { useSettingsStore } from './settings'

/** Incidents kept in the inbox (the agent keeps the same number). */
export const KEEP_ALERTS = 500

const RANK: Record<AlertSeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 }

export function severityRank(severity: AlertSeverity): number {
  return RANK[severity]
}

/** What the tray icon should show for these incidents: the worst one that is still going on. */
export function trayStateFor(alerts: readonly AlertView[]): TrayState {
  let worst = -1
  for (const alert of alerts) {
    if (alert.phase !== 'ended') worst = Math.max(worst, RANK[alert.severity])
  }
  if (worst >= RANK.high) return 'alert'
  return worst >= 0 ? 'warning' : 'neutral'
}

/**
 * The alert inbox: every incident the agent reports, newest first, bounded. Also decides which
 * incidents deserve a Windows notification (the user's severity settings) and tells the tray.
 */
export const useAlertsStore = defineStore('alerts', () => {
  const items = shallowRef<AlertView[]>([])
  const loaded = ref(false)
  const failed = ref(false)
  /** Highest incident id the user has looked at; anything newer counts as unread. */
  const seenUpTo = ref(0)

  const ongoing = computed(() => items.value.filter((a) => a.phase !== 'ended'))
  const unread = computed(() => items.value.filter((a) => a.id > seenUpTo.value).length)
  const trayState = computed(() => trayStateFor(items.value))

  function describe(alert: AlertView): { title: string; body: string } {
    const t = i18n.global.t
    const summary = t(`alerts.summary.${alert.summary_key}`)
    return {
      title: t('alerts.toast.title', {
        severity: t(`alerts.severity.${alert.severity}`),
        summary,
      }),
      body: alert.source
        ? t('alerts.toast.fromSource', { source: alert.source })
        : t('alerts.toast.distributed'),
    }
  }

  /** A notification for a new incident or a severity increase, when the user wants that severity. */
  function maybeNotify(next: AlertView, previous: AlertView | undefined): void {
    if (next.phase === 'ended') return
    const isNew = previous === undefined
    const escalated = previous !== undefined && RANK[next.severity] > RANK[previous.severity]
    if (!isNew && !escalated) return
    if (!useSettingsStore().notifications[next.severity]) return
    const text = describe(next)
    void notifyAlert(text.title, text.body)
  }

  function applyEvent(event: AlertView): void {
    const list = items.value
    const at = list.findIndex((a) => a.id === event.id)
    const previous = at >= 0 ? list[at] : undefined
    const next =
      at >= 0
        ? [...list.slice(0, at), ...list.slice(at + 1)]
        : list.length >= KEEP_ALERTS
          ? list.slice(0, KEEP_ALERTS - 1)
          : list.slice()
    next.unshift(event)
    items.value = next
    maybeNotify(event, previous)
    syncTray()
  }

  let lastTray: TrayState | null = null
  function syncTray(): void {
    if (lastTray === trayState.value) return
    lastTray = trayState.value
    const t = i18n.global.t
    void setTrayState(trayState.value, t(`alerts.tray.${trayState.value}`))
  }

  async function load(): Promise<void> {
    try {
      items.value = (await fetchAlerts()).alerts
      failed.value = false
      // What is already there when the app starts is not "new".
      seenUpTo.value = Math.max(0, ...items.value.map((a) => a.id))
    } catch (err) {
      failed.value = !(err instanceof AgentCallError && err.kind === 'unsupported')
    } finally {
      loaded.value = true
      syncTray()
    }
  }

  function markSeen(): void {
    seenUpTo.value = Math.max(seenUpTo.value, ...items.value.map((a) => a.id))
  }

  async function clearEnded(): Promise<void> {
    try {
      items.value = (await clearEndedAlerts()).alerts
      failed.value = false
    } catch {
      failed.value = true
    }
    syncTray()
  }

  /** The agent went away: the incidents it reported may be over, so the tray goes neutral. */
  function reset(): void {
    items.value = []
    loaded.value = false
    syncTray()
  }

  return {
    items,
    loaded,
    failed,
    ongoing,
    unread,
    trayState,
    applyEvent,
    load,
    markSeen,
    clearEnded,
    reset,
  }
})

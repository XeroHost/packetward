// SPDX-License-Identifier: GPL-3.0-or-later
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AlertSeverity } from '@/types/generated/AlertSeverity'
import type { AlertView } from '@/types/generated/AlertView'
import { KEEP_ALERTS, trayStateFor, useAlertsStore } from './alerts'
import { useSettingsStore } from './settings'

const shell = vi.hoisted(() => ({
  notifyAlert: vi.fn(),
  setTrayState: vi.fn(),
}))
vi.mock('@/api/shell', () => ({
  ...shell,
  setTrayLocale: vi.fn(),
  getAutostart: vi.fn(),
  setAutostart: vi.fn(),
  getWindowVisible: vi.fn(),
  watchWindowVisible: vi.fn(),
}))
const api = vi.hoisted(() => ({ fetchAlerts: vi.fn(), clearEndedAlerts: vi.fn() }))
vi.mock('@/api/alerts', () => api)

const alert = (
  id: number,
  severity: AlertSeverity = 'high',
  phase: AlertView['phase'] = 'started',
): AlertView => ({
  id,
  phase,
  kind: 'syn_flood',
  severity,
  source: '203.0.113.9',
  summary_key: 'syn_flood',
  metrics: [],
  window_secs: 10,
  first_seen_unix_ms: id,
  last_seen_unix_ms: id,
  protected: false,
  peak_severity: severity,
})

beforeEach(() => {
  setActivePinia(createPinia())
  shell.notifyAlert.mockReset()
  shell.setTrayState.mockReset()
  api.fetchAlerts.mockReset()
  api.clearEndedAlerts.mockReset()
})

describe('tray state', () => {
  it('follows the worst ongoing incident', () => {
    expect(trayStateFor([])).toBe('neutral')
    expect(trayStateFor([alert(1, 'low')])).toBe('warning')
    expect(trayStateFor([alert(1, 'medium'), alert(2, 'critical')])).toBe('alert')
    expect(trayStateFor([alert(1, 'critical', 'ended')])).toBe('neutral')
  })

  it('tells the shell only when it changes', () => {
    const alerts = useAlertsStore()
    alerts.applyEvent(alert(1, 'low'))
    alerts.applyEvent(alert(2, 'low'))
    expect(shell.setTrayState).toHaveBeenCalledTimes(1)
    expect(shell.setTrayState.mock.calls[0]?.[0]).toBe('warning')
    alerts.applyEvent(alert(3, 'critical'))
    expect(shell.setTrayState.mock.calls.at(-1)?.[0]).toBe('alert')
  })
})

describe('notifications', () => {
  it('only critical and high pop up by default, and only once per incident', () => {
    const alerts = useAlertsStore()
    alerts.applyEvent(alert(1, 'low'))
    alerts.applyEvent(alert(2, 'medium'))
    expect(shell.notifyAlert).not.toHaveBeenCalled()
    alerts.applyEvent(alert(3, 'high'))
    expect(shell.notifyAlert).toHaveBeenCalledTimes(1)
    alerts.applyEvent({ ...alert(3, 'high'), last_seen_unix_ms: 99 }) // same incident, same severity
    expect(shell.notifyAlert).toHaveBeenCalledTimes(1)
  })

  it('an escalation notifies again and an ended incident never does', () => {
    const alerts = useAlertsStore()
    alerts.applyEvent(alert(4, 'high'))
    alerts.applyEvent(alert(4, 'critical', 'escalated'))
    expect(shell.notifyAlert).toHaveBeenCalledTimes(2)
    alerts.applyEvent(alert(4, 'critical', 'ended'))
    expect(shell.notifyAlert).toHaveBeenCalledTimes(2)
  })

  it('follows the user settings', async () => {
    const alerts = useAlertsStore()
    const settings = useSettingsStore()
    await settings.setNotification('medium', true)
    await settings.setNotification('critical', false)
    alerts.applyEvent(alert(5, 'medium'))
    alerts.applyEvent(alert(6, 'critical'))
    expect(shell.notifyAlert).toHaveBeenCalledTimes(1)
  })

  it('the notification names the attack and the source', () => {
    const alerts = useAlertsStore()
    alerts.applyEvent(alert(7, 'critical'))
    const [title, body] = shell.notifyAlert.mock.calls[0] ?? []
    expect(title).toContain('SYN flood')
    expect(body).toContain('203.0.113.9')
  })
})

describe('inbox', () => {
  it('updates an incident in place, newest first, and stays bounded', () => {
    const alerts = useAlertsStore()
    alerts.applyEvent(alert(1, 'low'))
    alerts.applyEvent(alert(2, 'low'))
    alerts.applyEvent(alert(1, 'high', 'escalated'))
    expect(alerts.items.map((a) => a.id)).toEqual([1, 2])
    expect(alerts.items[0]?.severity).toBe('high')
    for (let id = 10; id < 10 + KEEP_ALERTS + 20; id += 1) alerts.applyEvent(alert(id, 'low'))
    expect(alerts.items).toHaveLength(KEEP_ALERTS)
    expect(alerts.items[0]?.id).toBe(10 + KEEP_ALERTS + 19)
  })

  it('counts unread until they are seen, and what exists at start is not new', async () => {
    const alerts = useAlertsStore()
    api.fetchAlerts.mockResolvedValue({ alerts: [alert(5), alert(4)], dropped: 0 })
    await alerts.load()
    expect(alerts.unread).toBe(0)
    alerts.applyEvent(alert(6))
    expect(alerts.unread).toBe(1)
    alerts.markSeen()
    expect(alerts.unread).toBe(0)
  })

  it('an older agent without alerts leaves the inbox quietly empty', async () => {
    const alerts = useAlertsStore()
    const { AgentCallError } = await import('@/api/call')
    api.fetchAlerts.mockRejectedValue(new AgentCallError('unsupported', 'unsupported'))
    await alerts.load()
    expect(alerts.failed).toBe(false)
    expect(alerts.items).toEqual([])
  })

  it('reset empties the inbox and the tray goes neutral', () => {
    const alerts = useAlertsStore()
    alerts.applyEvent(alert(1, 'critical'))
    alerts.reset()
    expect(alerts.items).toEqual([])
    expect(shell.setTrayState.mock.calls.at(-1)?.[0]).toBe('neutral')
  })
})

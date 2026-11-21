// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { defineStore } from 'pinia'
import { ref, shallowRef } from 'vue'
import * as api from '@/api/agentSettings'
import type { AgentSettingsView } from '@/types/generated/AgentSettingsView'
import type { AuditEntryView } from '@/types/generated/AuditEntryView'

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** Quotes a CSV field; a leading `=`, `+`, `-` or `@` is neutralised so a spreadsheet never runs it. */
function csvField(value: string): string {
  const safe = /^[=+\-@]/.test(value) ? `'${value}` : value
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe
}

export function auditToCsv(entries: readonly AuditEntryView[]): string {
  const rows = entries.map((e) =>
    [new Date(e.unix_ms).toISOString(), e.actor, e.action, e.target, e.detail, e.result]
      .map(csvField)
      .join(','),
  )
  return ['time,actor,action,target,detail,result', ...rows].join('\n') + '\n'
}

export function auditToJson(entries: readonly AuditEntryView[]): string {
  return JSON.stringify(entries, null, 2)
}

/** The audit log viewer and the agent settings (proxy). */
export const useLogsStore = defineStore('logs', () => {
  const entries = shallowRef<AuditEntryView[]>([])
  const truncated = ref(false)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const settings = ref<AgentSettingsView | null>(null)
  const settingsError = ref<string | null>(null)

  async function load(search = ''): Promise<void> {
    loading.value = true
    error.value = null
    try {
      const view = await api.auditLog(500, search.trim())
      entries.value = view.entries
      truncated.value = view.truncated
    } catch (err) {
      error.value = message(err)
    } finally {
      loading.value = false
    }
  }

  async function loadSettings(): Promise<void> {
    settingsError.value = null
    try {
      settings.value = await api.getAgentSettings()
    } catch (err) {
      settingsError.value = message(err)
    }
  }

  async function saveProxy(
    proxy: string,
    credentials: Omit<api.ProxyUpdate, 'proxy'> = {},
  ): Promise<boolean> {
    settingsError.value = null
    try {
      settings.value = await api.setProxy({
        proxy: proxy.trim() === '' ? null : proxy.trim(),
        ...credentials,
      })
      return true
    } catch (err) {
      settingsError.value = message(err)
      return false
    }
  }

  /** Switches the start-up capture; the agent saves it and applies it at its next start. */
  async function saveCaptureOnStart(enabled: boolean): Promise<boolean> {
    settingsError.value = null
    try {
      settings.value = await api.setCaptureOnStart(enabled)
      return true
    } catch (err) {
      settingsError.value = message(err)
      return false
    }
  }

  function reset(): void {
    entries.value = []
    truncated.value = false
    error.value = null
    settings.value = null
    settingsError.value = null
  }

  return {
    entries,
    truncated,
    loading,
    error,
    settings,
    settingsError,
    load,
    loadSettings,
    saveProxy,
    saveCaptureOnStart,
    reset,
  }
})

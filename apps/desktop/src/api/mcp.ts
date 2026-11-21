// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Typed wrappers for the MCP approval queue (via the shell's `agent_call`) plus the Windows
// notification that announces a new request. This module is the only place that talks to Tauri
// for MCP; components go through the store.
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import type { McpActionStatusView } from '@/types/generated/McpActionStatusView'
import type { McpPendingAction } from '@/types/generated/McpPendingAction'
import type { McpPendingList } from '@/types/generated/McpPendingList'
import type { McpSettingsSetRequest } from '@/types/generated/McpSettingsSetRequest'
import type { McpSettingsView } from '@/types/generated/McpSettingsView'
import { callAgent } from './call'
import { isTauri } from './uiPrefs'

export type {
  McpActionStatusView,
  McpPendingAction,
  McpPendingList,
  McpSettingsSetRequest,
  McpSettingsView,
}

/** The MCP policy (master switch, per-tool level, write limit). */
export const fetchMcpSettings = () => callAgent<McpSettingsView>('mcp.settings.get')
/** Saves only the fields present in `request` and returns the policy as saved. */
export const saveMcpSettings = (request: McpSettingsSetRequest) =>
  callAgent<McpSettingsView>('mcp.settings.set', request)

/** Where the installer put `pwctl.exe` for this copy of the app. */
export interface McpInstallInfo {
  path: string
  exists: boolean
}

/** How the `pwctl mcp` smoke test ended. */
export type McpCheckOutcome = 'ok' | 'missing' | 'timeout' | 'spawn' | 'exit'

export interface McpSelfCheck {
  ok: boolean
  path: string
  outcome: McpCheckOutcome
  detail: string
}

export async function fetchMcpInstallInfo(): Promise<McpInstallInfo> {
  if (!isTauri()) return { path: '', exists: false }
  return invoke<McpInstallInfo>('mcp_install_info')
}

/** Starts the installed `pwctl.exe mcp` with stdin closed and reports how it ended. */
export async function runMcpSelfCheck(): Promise<McpSelfCheck> {
  if (!isTauri()) {
    return { ok: false, path: '', outcome: 'missing', detail: '' }
  }
  return invoke<McpSelfCheck>('mcp_self_check')
}

/** The whole queue; every call is a full snapshot. */
export const fetchPendingActions = () => callAgent<McpPendingList>('mcp.pending.list')
/** Runs the tool; the reply is its own result (a block result, a rules view, …). */
export const approveMcpAction = (id: number) => callAgent<unknown>('mcp.approve', { id })
export const rejectMcpAction = (id: number) => callAgent<unknown>('mcp.reject', { id })
export const fetchMcpActionStatus = (id: number) =>
  callAgent<McpActionStatusView>('mcp.action.status', { id })

/**
 * The notification that asks for an approval. Unlike an alert, a click is reported: the shell
 * brings the window back and emits `mcp-pending-open` (see `watchApprovalOpen`).
 */
export async function notifyActionRequest(title: string, body: string): Promise<void> {
  if (!isTauri()) return
  try {
    await invoke('notify_action_request', { title, body })
  } catch (err) {
    console.warn('Could not show the approval notification', err)
  }
}

/** Calls `handler` when the user clicks the approval notification. Returns the unsubscribe. */
export async function watchApprovalOpen(handler: () => void): Promise<() => void> {
  if (!isTauri()) return () => {}
  return listen('mcp-pending-open', () => handler())
}

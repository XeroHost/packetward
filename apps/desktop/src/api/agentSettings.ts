// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Typed wrappers for the agent settings and the audit log (via the shell's `agent_call`).
import type { AgentSettingsView } from '@/types/generated/AgentSettingsView'
import type { AuditView } from '@/types/generated/AuditView'
import { callAgent } from './call'

export type { AgentSettingsView, AuditView }

export const getAgentSettings = () => callAgent<AgentSettingsView>('settings.get')
/** What the user typed in the proxy form. The credentials travel separately from the address. */
export interface ProxyUpdate {
  /** The proxy address; null goes back to the Windows proxy (and removes the credentials). */
  proxy: string | null
  username?: string
  /** Empty or absent keeps the saved password. */
  password?: string
  clearCredentials?: boolean
}

export const setProxy = (update: ProxyUpdate) =>
  callAgent<AgentSettingsView>('settings.set_proxy', {
    ...(update.proxy === null ? {} : { proxy: update.proxy }),
    ...(update.username ? { username: update.username } : {}),
    ...(update.password ? { password: update.password } : {}),
    ...(update.clearCredentials ? { clear_credentials: true } : {}),
  })
export const setCaptureOnStart = (enabled: boolean) =>
  callAgent<AgentSettingsView>('settings.set_capture_on_start', { enabled })
export const auditLog = (limit?: number, search?: string) =>
  callAgent<AuditView>('logs.audit', { limit, search: search || undefined })

// SPDX-License-Identifier: GPL-3.0-or-later
// Typed wrappers for the agent settings and the audit log (via the shell's `agent_call`).
import type { AgentSettingsView } from '@/types/generated/AgentSettingsView'
import type { AuditView } from '@/types/generated/AuditView'
import { callAgent } from './call'

export type { AgentSettingsView, AuditView }

export const getAgentSettings = () => callAgent<AgentSettingsView>('settings.get')
export const setProxy = (proxy: string | null) =>
  callAgent<AgentSettingsView>('settings.set_proxy', proxy === null ? {} : { proxy })
export const auditLog = (limit?: number, search?: string) =>
  callAgent<AuditView>('logs.audit', { limit, search: search || undefined })

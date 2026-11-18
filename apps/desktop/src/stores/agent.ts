// SPDX-License-Identifier: GPL-3.0-or-later
import { defineStore } from 'pinia'
import { ref } from 'vue'

export type AgentStatus = 'unknown' | 'connected' | 'disconnected'
export type GuardianMode = 'off' | 'monitor' | 'active'

/**
 * Placeholder for M0: the IPC client arrives in M1, so the shell shows a static
 * "not connected" state and never routes away because of it.
 */
export const useAgentStore = defineStore('agent', () => {
  const status = ref<AgentStatus>('unknown')
  const guardianMode = ref<GuardianMode | null>(null)
  return { status, guardianMode }
})

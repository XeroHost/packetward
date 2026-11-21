// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { defineStore } from 'pinia'
import { ref, shallowRef } from 'vue'
import * as api from '@/api/defense'
import { AgentCallError, type CallErrorKind } from '@/api/call'
import type { AllowlistConfig } from '@/types/generated/AllowlistConfig'
import type { BlockResult } from '@/types/generated/BlockResult'
import type { BlockView } from '@/types/generated/BlockView'
import type { FirewallRuleView } from '@/types/generated/FirewallRuleView'
import type { GuardianPolicy } from '@/types/generated/GuardianPolicy'
import type { GuardianStatus } from '@/types/generated/GuardianStatus'
import { useAgentStore } from './agent'

export type DefenseFailure = { kind: CallErrorKind; message: string }

function failure(err: unknown): DefenseFailure {
  if (err instanceof AgentCallError) return { kind: err.kind, message: err.message }
  return { kind: 'failed', message: String(err) }
}

/** Splits free text (one address per line, commas or spaces also work) into trimmed, non-empty items. */
export function splitTargets(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter((item) => item !== '')
}

/**
 * Firewall manager and Guardian: blocks, rules, the protected set and the Guardian's status. Also holds
 * the request of the block dialog (opened from any IP address in the app).
 */
export const useDefenseStore = defineStore('defense', () => {
  const blocks = shallowRef<BlockView[]>([])
  const rulesUsed = ref(0)
  const blocksError = ref<DefenseFailure | null>(null)

  const rules = shallowRef<FirewallRuleView[]>([])
  const rulesTotal = ref(0)
  const rulesTruncated = ref(false)
  const rulesError = ref<DefenseFailure | null>(null)

  const guardian = shallowRef<GuardianStatus | null>(null)
  const guardianError = ref<DefenseFailure | null>(null)
  const allowlist = ref<AllowlistConfig>({ allowlist: [], management: [] })

  /** Address the block dialog is open for, or null. */
  const blockTarget = ref<string | null>(null)
  const lastBlockResult = shallowRef<BlockResult | null>(null)
  const busy = ref(false)

  function syncGuardianMode(): void {
    useAgentStore().guardianMode = guardian.value?.policy.mode ?? null
  }

  async function guarded<T>(
    errorRef: { value: DefenseFailure | null },
    action: () => Promise<T>,
  ): Promise<T | undefined> {
    if (busy.value) return undefined
    busy.value = true
    errorRef.value = null
    try {
      return await action()
    } catch (err) {
      errorRef.value = failure(err)
      return undefined
    } finally {
      busy.value = false
    }
  }

  async function loadBlocks(): Promise<void> {
    try {
      const list = await api.fetchBlocks()
      blocks.value = list.blocks
      rulesUsed.value = list.rules_used
      blocksError.value = null
    } catch (err) {
      blocksError.value = failure(err)
    }
  }

  async function block(
    targets: string[],
    ttlSecs: number | undefined,
    reason: string,
  ): Promise<BlockResult | undefined> {
    const result = await guarded(blocksError, () =>
      api.blockTargets({ targets, ttl_secs: ttlSecs, reason, allow_broad: false }),
    )
    if (result) {
      lastBlockResult.value = result
      await loadBlocks()
    }
    return result
  }

  async function unblock(targets: string[]): Promise<void> {
    const list = await guarded(blocksError, () => api.unblockTargets(targets))
    if (list) {
      blocks.value = list.blocks
      rulesUsed.value = list.rules_used
    }
  }

  async function unblockEverything(): Promise<void> {
    const list = await guarded(blocksError, () => api.unblockAll())
    if (list) {
      blocks.value = list.blocks
      rulesUsed.value = list.rules_used
    }
  }

  async function purge(confirmation: string | undefined): Promise<string[] | undefined> {
    const result = await guarded(blocksError, () => api.purgeRules({ confirmation }))
    if (result) {
      await Promise.all([loadBlocks(), loadRules({ managed_only: false })])
      return result.removed_rules
    }
    return undefined
  }

  async function loadRules(filter: Parameters<typeof api.fetchRules>[0]): Promise<void> {
    try {
      const result = await api.fetchRules(filter)
      rules.value = result.rules
      rulesTotal.value = result.total
      rulesTruncated.value = result.truncated
      rulesError.value = null
    } catch (err) {
      rulesError.value = failure(err)
    }
  }

  async function setRuleEnabled(
    rule: FirewallRuleView,
    enabled: boolean,
    confirmation: string | undefined,
  ): Promise<boolean> {
    const done = await guarded(rulesError, () =>
      api.enableRule({
        name: rule.name,
        enabled,
        allow_foreign_edit: !rule.managed,
        confirmation,
      }),
    )
    return done !== undefined
  }

  async function deleteRule(
    rule: FirewallRuleView,
    confirmation: string | undefined,
  ): Promise<boolean> {
    const done = await guarded(rulesError, () =>
      api.removeRule({
        name: rule.name,
        enabled: false,
        allow_foreign_edit: !rule.managed,
        confirmation,
      }),
    )
    return done !== undefined
  }

  async function createRule(rule: FirewallRuleView): Promise<boolean> {
    const done = await guarded(rulesError, () =>
      api.addRule({ rule, allow_foreign_edit: false, confirmation: undefined }),
    )
    return done !== undefined
  }

  async function loadGuardian(): Promise<void> {
    try {
      guardian.value = await api.fetchGuardian()
      guardianError.value = null
      syncGuardianMode()
    } catch (err) {
      guardianError.value = failure(err)
    }
  }

  async function updatePolicy(policy: GuardianPolicy, confirmActive: boolean): Promise<boolean> {
    const status = await guarded(guardianError, () =>
      api.setGuardianPolicy({ policy, confirm_active: confirmActive }),
    )
    if (status) {
      guardian.value = status
      syncGuardianMode()
    }
    return status !== undefined
  }

  async function loadAllowlist(): Promise<void> {
    try {
      allowlist.value = await api.fetchAllowlist()
    } catch (err) {
      guardianError.value = failure(err)
    }
  }

  async function updateAllowlist(config: AllowlistConfig): Promise<boolean> {
    const saved = await guarded(guardianError, () => api.saveAllowlist(config))
    if (saved) {
      allowlist.value = saved
      await loadGuardian()
    }
    return saved !== undefined
  }

  /** Opens the block dialog for an address (from any IP in the app). */
  function requestBlock(addr: string): void {
    lastBlockResult.value = null
    blockTarget.value = addr
  }

  function closeBlock(): void {
    blockTarget.value = null
  }

  /** The agent went away: nothing may look current. */
  function reset(): void {
    blocks.value = []
    rules.value = []
    guardian.value = null
    useAgentStore().guardianMode = null
  }

  return {
    blocks,
    rulesUsed,
    blocksError,
    rules,
    rulesTotal,
    rulesTruncated,
    rulesError,
    guardian,
    guardianError,
    allowlist,
    blockTarget,
    lastBlockResult,
    busy,
    loadBlocks,
    block,
    unblock,
    unblockEverything,
    purge,
    loadRules,
    setRuleEnabled,
    deleteRule,
    createRule,
    loadGuardian,
    updatePolicy,
    loadAllowlist,
    updateAllowlist,
    requestBlock,
    closeBlock,
    reset,
  }
})

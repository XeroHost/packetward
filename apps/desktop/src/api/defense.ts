// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Typed wrappers for the firewall manager and the Guardian (via the shell's `agent_call`).
import type { AllowlistConfig } from '@/types/generated/AllowlistConfig'
import type { BlockList } from '@/types/generated/BlockList'
import type { BlockRequest } from '@/types/generated/BlockRequest'
import type { BlockResult } from '@/types/generated/BlockResult'
import type { FirewallRuleAction } from '@/types/generated/FirewallRuleAction'
import type { FirewallRuleEdit } from '@/types/generated/FirewallRuleEdit'
import type { FirewallRules } from '@/types/generated/FirewallRules'
import type { FirewallRulesRequest } from '@/types/generated/FirewallRulesRequest'
import type { GuardianStatus } from '@/types/generated/GuardianStatus'
import type { PurgeRequest } from '@/types/generated/PurgeRequest'
import type { PurgeResult } from '@/types/generated/PurgeResult'
import type { SetGuardianPolicy } from '@/types/generated/SetGuardianPolicy'
import { callAgent } from './call'

export type {
  AllowlistConfig,
  BlockList,
  BlockRequest,
  BlockResult,
  FirewallRuleAction,
  FirewallRuleEdit,
  FirewallRules,
  FirewallRulesRequest,
  GuardianStatus,
  PurgeRequest,
  PurgeResult,
  SetGuardianPolicy,
}

/** What a person must type to confirm an action that can cut them off from Remote Desktop. */
export const LOCKOUT_PHRASE = 'I understand this may lock me out of RDP'

export const fetchRules = (request: FirewallRulesRequest) =>
  callAgent<FirewallRules>('firewall.rules', request)
export const addRule = (edit: FirewallRuleEdit) => callAgent<null>('firewall.rule.add', edit)
export const updateRule = (edit: FirewallRuleEdit) => callAgent<null>('firewall.rule.update', edit)
export const removeRule = (action: FirewallRuleAction) =>
  callAgent<null>('firewall.rule.remove', action)
export const enableRule = (action: FirewallRuleAction) =>
  callAgent<null>('firewall.rule.enable', action)
export const fetchBlocks = () => callAgent<BlockList>('firewall.blocks')
export const blockTargets = (request: BlockRequest) =>
  callAgent<BlockResult>('firewall.block', request)
export const unblockTargets = (targets: string[]) =>
  callAgent<BlockList>('firewall.unblock', { targets })
export const unblockAll = () => callAgent<BlockList>('firewall.unblock_all')
export const purgeRules = (request: PurgeRequest) =>
  callAgent<PurgeResult>('firewall.purge', request)
export const fetchGuardian = () => callAgent<GuardianStatus>('guardian.status')
export const setGuardianPolicy = (request: SetGuardianPolicy) =>
  callAgent<GuardianStatus>('guardian.set_policy', request)
export const fetchAllowlist = () => callAgent<AllowlistConfig>('guardian.allowlist')
export const saveAllowlist = (config: AllowlistConfig) =>
  callAgent<AllowlistConfig>('guardian.set_allowlist', config)

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AgentCallError } from '@/api/call'
import type { GuardianStatus } from '@/types/generated/GuardianStatus'
import { useAgentStore } from './agent'
import { splitTargets, useDefenseStore } from './defense'

const api = vi.hoisted(() => ({
  fetchRules: vi.fn(),
  addRule: vi.fn(),
  updateRule: vi.fn(),
  removeRule: vi.fn(),
  enableRule: vi.fn(),
  fetchBlocks: vi.fn(),
  blockTargets: vi.fn(),
  unblockTargets: vi.fn(),
  unblockAll: vi.fn(),
  purgeRules: vi.fn(),
  fetchGuardian: vi.fn(),
  setGuardianPolicy: vi.fn(),
  fetchAllowlist: vi.fn(),
  saveAllowlist: vi.fn(),
  LOCKOUT_PHRASE: 'phrase',
}))
vi.mock('@/api/defense', () => api)
vi.mock('@/api/shell', () => ({
  setTrayLocale: vi.fn(),
  getAutostart: vi.fn(),
  setAutostart: vi.fn(),
  getWindowVisible: vi.fn(),
  watchWindowVisible: vi.fn(),
  setTrayState: vi.fn(),
  notifyAlert: vi.fn(),
}))

const status = (mode: 'off' | 'monitor' | 'active'): GuardianStatus => ({
  policy: {
    mode,
    preset: 'balanced',
    min_severity: 'high',
    ttl_ladder_secs: [900],
    max_blocks_per_hour: 20,
  },
  circuit_open: false,
  blocks_last_hour: 0,
  protected: [],
  decisions: [],
  would_block_24h: 0,
})

beforeEach(() => {
  setActivePinia(createPinia())
  for (const fn of Object.values(api)) if (typeof fn === 'function') fn.mockReset()
})

describe('splitTargets', () => {
  it('accepts lines, commas and spaces and drops empties', () => {
    expect(splitTargets('203.0.113.1\n198.51.100.0/24, 2001:db8::1  ;')).toEqual([
      '203.0.113.1',
      '198.51.100.0/24',
      '2001:db8::1',
    ])
    expect(splitTargets('  \n ')).toEqual([])
  })
})

describe('blocks', () => {
  it('blocks, reports refusals and reloads the list', async () => {
    const defense = useDefenseStore()
    api.blockTargets.mockResolvedValue({
      blocked: ['203.0.113.9/32'],
      refused_protected: [{ target: '1.1.1.1/32', reason: 'dns' }],
      refused_broad: [],
    })
    api.fetchBlocks.mockResolvedValue({ blocks: [], rules_used: 0 })
    const result = await defense.block(['203.0.113.9', '1.1.1.1'], 900, 'test')
    expect(api.blockTargets).toHaveBeenCalledWith({
      targets: ['203.0.113.9', '1.1.1.1'],
      ttl_secs: 900,
      reason: 'test',
      allow_broad: false,
    })
    expect(result?.refused_protected[0]?.reason).toBe('dns')
    expect(defense.lastBlockResult?.blocked).toHaveLength(1)
    expect(api.fetchBlocks).toHaveBeenCalled()
  })

  it('keeps the agent explanation when blocking fails', async () => {
    const defense = useDefenseStore()
    api.blockTargets.mockRejectedValue(new AgentCallError('bad_request', 'not an IP'))
    expect(await defense.block(['x'], undefined, '')).toBeUndefined()
    expect(defense.blocksError?.message).toBe('not an IP')
    expect(defense.busy).toBe(false)
  })

  it('the block dialog opens for an address and closes', () => {
    const defense = useDefenseStore()
    defense.requestBlock('203.0.113.9')
    expect(defense.blockTarget).toBe('203.0.113.9')
    defense.closeBlock()
    expect(defense.blockTarget).toBeNull()
  })
})

describe('rules', () => {
  it('sends the typed phrase only for the rule it was asked for, and flags foreign rules', async () => {
    const defense = useDefenseStore()
    api.enableRule.mockResolvedValue(null)
    const rule = {
      name: 'Remote Desktop - User Mode (TCP-In)',
      description: '',
      group: 'x',
      direction: 'inbound' as const,
      action: 'allow' as const,
      enabled: true,
      protocol: 'tcp',
      local_ports: '3389',
      remote_ports: '*',
      local_addresses: '*',
      remote_addresses: '*',
      managed: false,
      builtin_rdp: true,
    }
    expect(await defense.setRuleEnabled(rule, false, 'phrase')).toBe(true)
    expect(api.enableRule).toHaveBeenCalledWith({
      name: rule.name,
      enabled: false,
      allow_foreign_edit: true,
      confirmation: 'phrase',
    })
  })

  it('a refused change is reported, not swallowed', async () => {
    const defense = useDefenseStore()
    api.removeRule.mockRejectedValue(
      new AgentCallError('bad_request', 'typed confirmation required'),
    )
    const ok = await defense.deleteRule(
      {
        name: 'r',
        description: '',
        group: '',
        direction: 'inbound',
        action: 'allow',
        enabled: true,
        protocol: 'tcp',
        local_ports: '*',
        remote_ports: '*',
        local_addresses: '*',
        remote_addresses: '*',
        managed: true,
        builtin_rdp: false,
      },
      undefined,
    )
    expect(ok).toBe(false)
    expect(defense.rulesError?.message).toContain('confirmation')
  })
})

describe('guardian', () => {
  it('the mode shows in the top bar and goes away with the agent', async () => {
    const defense = useDefenseStore()
    const agent = useAgentStore()
    api.fetchGuardian.mockResolvedValue(status('monitor'))
    await defense.loadGuardian()
    expect(agent.guardianMode).toBe('monitor')
    defense.reset()
    expect(agent.guardianMode).toBeNull()
  })

  it('switching to active passes the confirmation and updates the status', async () => {
    const defense = useDefenseStore()
    api.setGuardianPolicy.mockResolvedValue(status('active'))
    const policy = status('active').policy
    expect(await defense.updatePolicy(policy, true)).toBe(true)
    expect(api.setGuardianPolicy).toHaveBeenCalledWith({ policy, confirm_active: true })
    expect(defense.guardian?.policy.mode).toBe('active')
  })

  it('a refused policy leaves the previous status', async () => {
    const defense = useDefenseStore()
    api.fetchGuardian.mockResolvedValue(status('monitor'))
    await defense.loadGuardian()
    api.setGuardianPolicy.mockRejectedValue(new AgentCallError('bad_request', 'needs confirmation'))
    expect(await defense.updatePolicy(status('active').policy, false)).toBe(false)
    expect(defense.guardian?.policy.mode).toBe('monitor')
    expect(defense.guardianError?.message).toBe('needs confirmation')
  })
})

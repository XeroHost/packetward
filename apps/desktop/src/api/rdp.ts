// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Typed wrappers for the RDP Shield (via the shell's `agent_call`).
import type { RdpAttempts } from '@/types/generated/RdpAttempts'
import type { RdpAudit } from '@/types/generated/RdpAudit'
import type { RdpCountryPolicy } from '@/types/generated/RdpCountryPolicy'
import type { RdpCountryStatus } from '@/types/generated/RdpCountryStatus'
import type { RdpLockoutRequest } from '@/types/generated/RdpLockoutRequest'
import type { RdpPortRequest } from '@/types/generated/RdpPortRequest'
import type { RdpRestrictRequest } from '@/types/generated/RdpRestrictRequest'
import { callAgent } from './call'

export type {
  RdpAttempts,
  RdpAudit,
  RdpCountryPolicy,
  RdpCountryStatus,
  RdpLockoutRequest,
  RdpPortRequest,
  RdpRestrictRequest,
}

export const fetchRdpAudit = () => callAgent<RdpAudit>('rdp.audit')
export const fetchRdpCountry = () => callAgent<RdpCountryStatus>('rdp.country.get')
export const setRdpCountry = (policy: RdpCountryPolicy) =>
  callAgent<RdpCountryStatus>('rdp.country.set', policy)
export const restrictRdp = (request: RdpRestrictRequest) =>
  callAgent<RdpAudit>('rdp.restrict', request)
export const unrestrictRdp = () => callAgent<RdpAudit>('rdp.unrestrict')
export const changeRdpPort = (request: RdpPortRequest) => callAgent<RdpAudit>('rdp.port', request)
export const setRdpNla = (required: boolean) => callAgent<RdpAudit>('rdp.nla', { required })
export const setRdpLockout = (request: RdpLockoutRequest) =>
  callAgent<RdpAudit>('rdp.lockout', request)
export const setRdpAttempts = (attempts: RdpAttempts) =>
  callAgent<RdpAudit>('rdp.attempts', attempts)
export const confirmRdp = (id: number) => callAgent<RdpAudit>('rdp.confirm', { id })
export const cancelRdp = (id: number) => callAgent<RdpAudit>('rdp.cancel', { id })
export const resetRdp = () => callAgent<RdpAudit>('rdp.reset')
export const endRdpSession = (sessionId: number, logoff: boolean) =>
  callAgent<null>('rdp.end_session', { session_id: sessionId, logoff })

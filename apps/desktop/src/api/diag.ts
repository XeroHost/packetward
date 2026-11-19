// SPDX-License-Identifier: GPL-3.0-or-later
// Typed wrappers for the diagnostics methods of the agent (via the shell's `agent_call` command).
import type { DiagEvent } from '@/types/generated/DiagEvent'
import type { DiagStartResponse } from '@/types/generated/DiagStartResponse'
import type { DnsLookupRequest } from '@/types/generated/DnsLookupRequest'
import type { DnsLookupView } from '@/types/generated/DnsLookupView'
import type { LocalPorts } from '@/types/generated/LocalPorts'
import type { MtrReport } from '@/types/generated/MtrReport'
import type { MtrStartRequest } from '@/types/generated/MtrStartRequest'
import type { PingStartRequest } from '@/types/generated/PingStartRequest'
import type { PortCheckRequest } from '@/types/generated/PortCheckRequest'
import type { PortCheckView } from '@/types/generated/PortCheckView'
import { AgentCallError, callAgent, parseCallError, type CallErrorKind } from './call'

export type {
  DiagEvent,
  DiagStartResponse,
  DnsLookupRequest,
  DnsLookupView,
  LocalPorts,
  MtrReport,
  MtrStartRequest,
  PingStartRequest,
  PortCheckRequest,
  PortCheckView,
}

export type DiagErrorKind = CallErrorKind
/** Diagnostics requests fail with the shared agent-call error. */
export const DiagError = AgentCallError
export type DiagError = AgentCallError
export { parseCallError }

const call = callAgent

export const startPing = (request: PingStartRequest) =>
  call<DiagStartResponse>('diag.ping.start', request)
export const startMtr = (request: MtrStartRequest) =>
  call<DiagStartResponse>('diag.mtr.start', request)
export const cancelJob = (jobId: number) => call<null>('diag.cancel', { job_id: jobId })
export const fetchMtrReport = (jobId: number) =>
  call<MtrReport>('diag.mtr.report', { job_id: jobId })
export const dnsLookup = (request: DnsLookupRequest) =>
  call<DnsLookupView>('diag.dns.lookup', request)
export const portCheck = (request: PortCheckRequest) =>
  call<PortCheckView>('diag.port.check', request)
export const fetchLocalPorts = () => call<LocalPorts>('diag.ports.local')

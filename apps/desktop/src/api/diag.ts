// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Typed wrappers for the diagnostics methods of the agent (via the shell's `agent_call` command).
import type { DiagEvent } from '@/types/generated/DiagEvent'
import type { DiagStartResponse } from '@/types/generated/DiagStartResponse'
import type { DnsLookupRequest } from '@/types/generated/DnsLookupRequest'
import type { DnsLookupView } from '@/types/generated/DnsLookupView'
import type { LocalPorts } from '@/types/generated/LocalPorts'
import type { MtrExport } from '@/types/generated/MtrExport'
import type { MtrExportFormat } from '@/types/generated/MtrExportFormat'
import type { MtrExportRequest } from '@/types/generated/MtrExportRequest'
import type { MtrModeView } from '@/types/generated/MtrModeView'
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
  MtrExport,
  MtrExportFormat,
  MtrExportRequest,
  MtrModeView,
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
/** Agents older than protocol 1.10 have no advanced MTR modes and no export. */
export const MTR_ADVANCED_MIN_MINOR = 10
export const exportMtr = (request: MtrExportRequest) => call<MtrExport>('diag.mtr.export', request)
export const dnsLookup = (request: DnsLookupRequest) =>
  call<DnsLookupView>('diag.dns.lookup', request)
export const portCheck = (request: PortCheckRequest) =>
  call<PortCheckView>('diag.port.check', request)
export const fetchLocalPorts = () => call<LocalPorts>('diag.ports.local')

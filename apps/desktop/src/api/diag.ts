// SPDX-License-Identifier: GPL-3.0-or-later
// Typed wrappers for the diagnostics methods of the agent (via the shell's `agent_call` command).
import { invoke } from '@tauri-apps/api/core'
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
import { isTauri } from './uiPrefs'

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

export type DiagErrorKind = 'not_connected' | 'unsupported' | 'busy' | 'bad_request' | 'failed'

/** A diagnostics request that failed; `message` is the agent's own explanation when it gave one. */
export class DiagError extends Error {
  constructor(
    readonly kind: DiagErrorKind,
    message: string,
  ) {
    super(message)
  }
}

/** The shell reports agent errors as `<Code>: <message>` (see `agent_call` in bridge.rs). */
export function parseCallError(raw: unknown): DiagError {
  const text = String(raw)
  if (text === 'not_connected') return new DiagError('not_connected', text)
  if (text === 'unsupported' || text === 'forbidden') return new DiagError('unsupported', text)
  const match = /^(\w+): ([\s\S]*)$/.exec(text)
  if (match?.[1] === 'Busy') return new DiagError('busy', match[2] ?? text)
  if (match?.[1] === 'BadRequest') return new DiagError('bad_request', match[2] ?? text)
  return new DiagError('failed', match?.[2] ?? text)
}

async function call<T>(method: string, payload?: unknown): Promise<T> {
  if (!isTauri()) throw new DiagError('unsupported', 'Not available in the browser preview.')
  try {
    return await invoke<T>('agent_call', { method, payload: payload ?? null })
  } catch (err) {
    throw parseCallError(err)
  }
}

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

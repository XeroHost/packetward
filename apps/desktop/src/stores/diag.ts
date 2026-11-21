// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { defineStore } from 'pinia'
import { ref, shallowRef } from 'vue'
import * as api from '@/api/diag'
import { DiagError, type DiagEvent } from '@/api/diag'
import type { DnsLookupView } from '@/types/generated/DnsLookupView'
import type { LocalPort } from '@/types/generated/LocalPort'
import type { MtrView } from '@/types/generated/MtrView'
import type { PingReplyView } from '@/types/generated/PingReplyView'
import type { PingSummaryView } from '@/types/generated/PingSummaryView'
import type { PortCheckView } from '@/types/generated/PortCheckView'

/** Replies kept on screen for the running ping; older ones scroll out. */
export const PING_VISIBLE = 100
/** Events that arrived before their job id was known (the start reply races the first events). */
const PENDING_LIMIT = 64

export type DiagFailure = { kind: api.DiagErrorKind; message: string }

/** The MTR options beyond target, rounds and name lookup. Anything left out keeps the agent's default. */
export interface MtrAdvanced {
  mode?: api.MtrModeView
  /** Destination port of UDP and TCP probes. */
  port?: number
  packetSize?: number
  intervalMs?: number
  maxHops?: number
  preferIpv6?: boolean
}

/** Default destination ports the agent uses when none is given (shown as placeholders). */
export const MTR_DEFAULT_PORT = { udp: 33434, tcp: 443 } as const

/**
 * The `diag.mtr.start` payload. Only options that differ from the defaults are sent, so a plain ICMP
 * trace is byte-for-byte the request older agents already understand.
 */
export function buildMtrRequest(
  target: string,
  cycles: number,
  resolveNames: boolean,
  advanced: MtrAdvanced = {},
): api.MtrStartRequest {
  const request: api.MtrStartRequest = { target, cycles, resolve_names: resolveNames }
  const mode = advanced.mode ?? 'icmp'
  if (mode !== 'icmp') {
    request.mode = mode
    if (advanced.port !== undefined) request.port = advanced.port
  }
  if (advanced.packetSize !== undefined) request.packet_size = advanced.packetSize
  if (advanced.intervalMs !== undefined) request.interval_ms = advanced.intervalMs
  if (advanced.maxHops !== undefined) request.max_hops = advanced.maxHops
  if (advanced.preferIpv6) request.prefer_ipv6 = true
  return request
}

function failure(err: unknown): DiagFailure {
  if (err instanceof DiagError) return { kind: err.kind, message: err.message }
  return { kind: 'failed', message: String(err) }
}

export const useDiagStore = defineStore('diag', () => {
  // ---- ping -----------------------------------------------------------------------------
  const pingJob = ref<number | null>(null)
  const pingTarget = ref('')
  const pingResolved = ref('')
  const pingRunning = ref(false)
  const pingReplies = shallowRef<PingReplyView[]>([])
  const pingSent = ref(0)
  const pingReceived = ref(0)
  const pingSummary = ref<PingSummaryView | null>(null)
  const pingError = ref<DiagFailure | null>(null)

  // ---- mtr ------------------------------------------------------------------------------
  const mtrJob = ref<number | null>(null)
  const mtrTarget = ref('')
  const mtrResolved = ref('')
  const mtrRunning = ref(false)
  const mtrSnapshot = shallowRef<MtrView | null>(null)
  const mtrCancelled = ref(false)
  const mtrError = ref<DiagFailure | null>(null)

  // ---- one-shot tools -------------------------------------------------------------------
  const dnsBusy = ref(false)
  const dnsResult = ref<DnsLookupView | null>(null)
  const dnsError = ref<DiagFailure | null>(null)
  const portBusy = ref(false)
  const portResult = ref<PortCheckView | null>(null)
  const portError = ref<DiagFailure | null>(null)
  const localPorts = shallowRef<LocalPort[]>([])
  const localPortsError = ref<DiagFailure | null>(null)
  const localPortsLoaded = ref(false)

  let pending: DiagEvent[] = []

  function dispatch(event: DiagEvent): boolean {
    if (event.job_id === pingJob.value) {
      applyPing(event)
      return true
    }
    if (event.job_id === mtrJob.value) {
      applyMtr(event)
      return true
    }
    return false
  }

  function applyPing(event: DiagEvent): void {
    if (event.type === 'ping_reply') {
      pingSent.value += 1
      if (event.reply.outcome === 'success') pingReceived.value += 1
      const next =
        pingReplies.value.length >= PING_VISIBLE
          ? pingReplies.value.slice(pingReplies.value.length - PING_VISIBLE + 1)
          : pingReplies.value.slice()
      next.push(event.reply)
      pingReplies.value = next
    } else if (event.type === 'ping_done') {
      pingSummary.value = event.summary
      pingRunning.value = false
    } else if (event.type === 'failed') {
      pingError.value = { kind: 'failed', message: event.message }
      pingRunning.value = false
    }
  }

  function applyMtr(event: DiagEvent): void {
    if (event.type === 'mtr_snapshot') {
      mtrSnapshot.value = event.snapshot
    } else if (event.type === 'mtr_done') {
      mtrCancelled.value = event.cancelled
      mtrRunning.value = false
    } else if (event.type === 'failed') {
      mtrError.value = { kind: 'failed', message: event.message }
      mtrRunning.value = false
    }
  }

  /** Called for every `diag.progress` message from the agent. */
  function applyEvent(event: DiagEvent): void {
    if (dispatch(event)) return
    // Not ours (yet): keep a few in case the start reply is still on its way.
    pending.push(event)
    if (pending.length > PENDING_LIMIT) pending = pending.slice(-PENDING_LIMIT)
  }

  function replayPending(): void {
    const queued = pending
    pending = []
    for (const event of queued) if (!dispatch(event)) pending.push(event)
  }

  async function runPing(target: string, count: number): Promise<void> {
    if (pingRunning.value) return
    pingError.value = null
    pingSummary.value = null
    pingReplies.value = []
    pingSent.value = 0
    pingReceived.value = 0
    pingTarget.value = target
    pingResolved.value = ''
    pingJob.value = null
    pingRunning.value = true
    try {
      const started = await api.startPing({ target, count })
      pingJob.value = started.job_id
      pingResolved.value = started.target_ip
      replayPending()
    } catch (err) {
      pingError.value = failure(err)
      pingRunning.value = false
    }
  }

  async function runMtr(
    target: string,
    cycles: number,
    resolveNames: boolean,
    advanced: MtrAdvanced = {},
  ): Promise<void> {
    if (mtrRunning.value) return
    mtrError.value = null
    mtrSnapshot.value = null
    mtrCancelled.value = false
    mtrTarget.value = target
    mtrResolved.value = ''
    mtrJob.value = null
    mtrRunning.value = true
    try {
      const started = await api.startMtr(buildMtrRequest(target, cycles, resolveNames, advanced))
      mtrJob.value = started.job_id
      mtrResolved.value = started.target_ip
      replayPending()
    } catch (err) {
      mtrError.value = failure(err)
      mtrRunning.value = false
    }
  }

  async function stopPing(): Promise<void> {
    if (pingJob.value !== null) await api.cancelJob(pingJob.value).catch(() => undefined)
  }

  async function stopMtr(): Promise<void> {
    if (mtrJob.value !== null) await api.cancelJob(mtrJob.value).catch(() => undefined)
  }

  /** The plain-text MTR report for support, or null when there is nothing to report yet. */
  async function mtrReportText(): Promise<string | null> {
    if (mtrJob.value === null || mtrSnapshot.value === null) return null
    try {
      return (await api.fetchMtrReport(mtrJob.value)).text
    } catch (err) {
      mtrError.value = failure(err)
      return null
    }
  }

  /**
   * The latest table of the current MTR job as a file (CSV, JSON or the support text), or null when
   * there is nothing to export yet. `sourceIp` is this machine's public address when known.
   */
  async function mtrExport(
    format: api.MtrExportFormat,
    sourceIp?: string,
  ): Promise<api.MtrExport | null> {
    if (mtrJob.value === null || mtrSnapshot.value === null) return null
    try {
      return await api.exportMtr({
        job_id: mtrJob.value,
        format,
        ...(sourceIp ? { source_ip: sourceIp } : {}),
      })
    } catch (err) {
      mtrError.value = failure(err)
      return null
    }
  }

  async function runDns(request: api.DnsLookupRequest): Promise<void> {
    if (dnsBusy.value) return
    dnsBusy.value = true
    dnsError.value = null
    try {
      dnsResult.value = await api.dnsLookup(request)
    } catch (err) {
      dnsResult.value = null
      dnsError.value = failure(err)
    } finally {
      dnsBusy.value = false
    }
  }

  async function runPortCheck(request: api.PortCheckRequest): Promise<void> {
    if (portBusy.value) return
    portBusy.value = true
    portError.value = null
    try {
      portResult.value = await api.portCheck(request)
    } catch (err) {
      portResult.value = null
      portError.value = failure(err)
    } finally {
      portBusy.value = false
    }
  }

  async function loadLocalPorts(): Promise<void> {
    try {
      localPorts.value = (await api.fetchLocalPorts()).ports
      localPortsError.value = null
    } catch (err) {
      localPortsError.value = failure(err)
    } finally {
      localPortsLoaded.value = true
    }
  }

  /** Jobs belong to a connection: once the agent is gone nothing may look like it is still running. */
  function reset(): void {
    pingRunning.value = false
    mtrRunning.value = false
    pingJob.value = null
    mtrJob.value = null
    pending = []
    localPortsLoaded.value = false
    localPorts.value = []
  }

  return {
    pingTarget,
    pingResolved,
    pingRunning,
    pingReplies,
    pingSent,
    pingReceived,
    pingSummary,
    pingError,
    mtrTarget,
    mtrResolved,
    mtrRunning,
    mtrSnapshot,
    mtrCancelled,
    mtrError,
    dnsBusy,
    dnsResult,
    dnsError,
    portBusy,
    portResult,
    portError,
    localPorts,
    localPortsError,
    localPortsLoaded,
    applyEvent,
    runPing,
    stopPing,
    runMtr,
    stopMtr,
    mtrReportText,
    mtrExport,
    runDns,
    runPortCheck,
    loadLocalPorts,
    reset,
  }
})

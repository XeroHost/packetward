// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import type { MtrHopView } from '@/types/generated/MtrHopView'

/** 12.345 -> "12.3 ms", 0.42 -> "0.42 ms", undefined -> "—". */
export function formatMs(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—'
  if (value >= 100) return `${value.toFixed(0)} ms`
  if (value >= 10) return `${value.toFixed(1)} ms`
  return `${value.toFixed(2)} ms`
}

/** 0 -> "0%", 12.34 -> "12%", 3.33 -> "3.3%". */
export function formatLoss(percent: number): string {
  if (!Number.isFinite(percent) || percent <= 0) return '0%'
  return `${percent < 10 ? percent.toFixed(1) : percent.toFixed(0)}%`
}

export type LossLevel = 'ok' | 'warn' | 'bad'

/** Loss on one hop: a little is normal on a router that deprioritises ICMP, a lot is not. */
export function lossLevel(percent: number): LossLevel {
  if (percent >= 20) return 'bad'
  if (percent >= 5) return 'warn'
  return 'ok'
}

/**
 * A hop whose own loss is high but whose later hops are clean is only rate-limiting its ICMP
 * replies; it is not dropping traffic. True when this hop has loss and every later hop that
 * answered does not.
 */
export function isIcmpRateLimited(hops: readonly MtrHopView[], index: number): boolean {
  const hop = hops[index]
  if (!hop || hop.loss_percent < 5) return false
  const later = hops.slice(index + 1).filter((h) => h.received > 0)
  return later.length > 0 && later.every((h) => h.loss_percent < 5)
}

/** Where a listening socket can be reached from. */
export type PortScope = 'all' | 'local' | 'specific'

export function portScope(addr: string): PortScope {
  if (addr === '0.0.0.0' || addr === '::' || addr === '') return 'all'
  if (addr === '::1' || addr.startsWith('127.')) return 'local'
  return 'specific'
}

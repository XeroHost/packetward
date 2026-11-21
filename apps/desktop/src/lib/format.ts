// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0

/** 93784 -> "1d 2h 3m 4s"; drops leading zero units, always shows seconds. */
export function formatUptime(totalSeconds: number): string {
  const secs = Math.max(0, Math.floor(totalSeconds))
  const days = Math.floor(secs / 86400)
  const hours = Math.floor((secs % 86400) / 3600)
  const minutes = Math.floor((secs % 3600) / 60)
  const seconds = secs % 60
  const parts: string[] = []
  if (days > 0) parts.push(`${days}d`)
  if (days > 0 || hours > 0) parts.push(`${hours}h`)
  if (days > 0 || hours > 0 || minutes > 0) parts.push(`${minutes}m`)
  parts.push(`${seconds}s`)
  return parts.join(' ')
}

const BIT_UNITS = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'] as const

/** Three significant digits: 1.23, 12.3, 123. */
function threeDigits(value: number): string {
  if (value >= 100) return value.toFixed(0)
  if (value >= 10) return value.toFixed(1)
  return value.toFixed(2)
}

/**
 * Bits per second the way Task Manager shows them (decimal units): 1_500_000 -> "1.50 Mbps".
 * Negative or non-finite input is shown as zero.
 */
export function formatBitrate(bitsPerSecond: number): string {
  const bps = Number.isFinite(bitsPerSecond) && bitsPerSecond > 0 ? bitsPerSecond : 0
  if (bps < 1000) return `${Math.round(bps)} bps`
  let value = bps
  let unit = 0
  while (value >= 1000 && unit < BIT_UNITS.length - 1) {
    value /= 1000
    unit += 1
  }
  return `${threeDigits(value)} ${BIT_UNITS[unit]}`
}

/** Packets per second, abbreviated: 950 -> "950", 12_400 -> "12.4 K". */
export function formatRate(perSecond: number): string {
  const value = Number.isFinite(perSecond) && perSecond > 0 ? perSecond : 0
  if (value < 1000) return String(Math.round(value))
  if (value < 1_000_000) return `${threeDigits(value / 1000)} K`
  return `${threeDigits(value / 1_000_000)} M`
}

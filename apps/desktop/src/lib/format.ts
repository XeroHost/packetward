// SPDX-License-Identifier: GPL-3.0-or-later

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

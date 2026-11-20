// SPDX-License-Identifier: GPL-3.0-or-later
// Who is attacking, by country: the sources of alerts and the addresses that were blocked, placed
// with the local GeoIP database. Pure, so it is tested without a map.
import type { GeoPlace } from '@/stores/geo'
import type { AlertView } from '@/types/generated/AlertView'
import type { BlockView } from '@/types/generated/BlockView'

export interface AttackerCountry {
  /** ISO 3166-1 alpha-2, upper case. */
  code: string
  /** Different addresses behind alerts or blocks. */
  addrs: number
  alerts: number
  blocked: number
}

/** `203.0.113.0/24` -> `203.0.113.0`: a block is placed by its first address. */
export const baseAddress = (target: string): string => target.split('/')[0] ?? ''

/** Every distinct address that is, or was, a source of trouble. Trusted (protected) sources are not attackers. */
export function attackerAddresses(
  alerts: readonly AlertView[],
  blocks: readonly BlockView[],
): string[] {
  const found = new Set<string>()
  for (const alert of alerts) {
    if (alert.source && !alert.protected) found.add(baseAddress(alert.source))
  }
  for (const block of blocks) found.add(baseAddress(block.cidr))
  found.delete('')
  return [...found]
}

export function summarizeAttackers(
  alerts: readonly AlertView[],
  blocks: readonly BlockView[],
  placeOf: (addr: string) => GeoPlace | null | undefined,
): AttackerCountry[] {
  const rows = new Map<string, AttackerCountry & { seen: Set<string> }>()
  const row = (code: string) => {
    let entry = rows.get(code)
    if (!entry) {
      entry = { code, addrs: 0, alerts: 0, blocked: 0, seen: new Set() }
      rows.set(code, entry)
    }
    return entry
  }
  for (const alert of alerts) {
    if (!alert.source || alert.protected) continue
    const addr = baseAddress(alert.source)
    const place = placeOf(addr)
    if (!place) continue
    const entry = row(place.code)
    entry.alerts += 1
    if (!entry.seen.has(addr)) {
      entry.seen.add(addr)
      entry.addrs += 1
    }
  }
  for (const block of blocks) {
    const addr = baseAddress(block.cidr)
    const place = placeOf(addr)
    if (!place) continue
    const entry = row(place.code)
    entry.blocked += 1
    if (!entry.seen.has(addr)) {
      entry.seen.add(addr)
      entry.addrs += 1
    }
  }
  return [...rows.values()]
    .map(({ code, addrs, alerts: a, blocked }) => ({ code, addrs, alerts: a, blocked }))
    .sort((x, y) => y.addrs - x.addrs || y.alerts - x.alerts || x.code.localeCompare(y.code))
}

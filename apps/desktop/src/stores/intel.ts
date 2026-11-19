// SPDX-License-Identifier: GPL-3.0-or-later
import { defineStore } from 'pinia'
import { computed, ref, shallowRef } from 'vue'
import * as api from '@/api/intel'
import type { AbuseCheckView } from '@/types/generated/AbuseCheckView'
import type { AbuseStatusView } from '@/types/generated/AbuseStatusView'
import type { GeoEntry } from '@/types/generated/GeoEntry'
import type { GeoStatusView } from '@/types/generated/GeoStatusView'
import type { ListStatusView } from '@/types/generated/ListStatusView'
import type { RemoteTalker } from '@/types/generated/RemoteTalker'

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

export interface CountryRow {
  code: string
  name: string
  sources: number
  connections: number
}

/** Pure: groups remote talkers by country (reserved and unknown addresses are left out). */
export function countryLeaderboard(
  talkers: readonly RemoteTalker[],
  entries: readonly GeoEntry[],
): CountryRow[] {
  const byAddr = new Map(entries.map((e) => [e.addr, e]))
  const rows = new Map<string, CountryRow>()
  for (const talker of talkers) {
    const entry = byAddr.get(talker.addr)
    if (!entry || entry.reserved || !entry.country_code) continue
    const row = rows.get(entry.country_code) ?? {
      code: entry.country_code,
      name: entry.country_name ?? entry.country_code,
      sources: 0,
      connections: 0,
    }
    row.sources += 1
    row.connections += talker.connections
    rows.set(entry.country_code, row)
  }
  return [...rows.values()].sort((a, b) => b.connections - a.connections || b.sources - a.sources)
}

/** Threat intelligence: GeoIP status, the blocklists and the optional AbuseIPDB check. */
export const useIntelStore = defineStore('intel', () => {
  const geo = ref<GeoStatusView | null>(null)
  const lists = shallowRef<ListStatusView[]>([])
  const abuse = ref<AbuseStatusView | null>(null)
  const countries = shallowRef<CountryRow[]>([])
  const check = ref<AbuseCheckView | null>(null)
  const error = ref<string | null>(null)
  const busy = ref(false)

  const geoReady = computed(() => geo.value?.state === 'ready')

  async function guarded<T>(job: () => Promise<T>): Promise<T | undefined> {
    error.value = null
    try {
      return await job()
    } catch (err) {
      error.value = message(err)
      return undefined
    }
  }

  async function refresh(): Promise<void> {
    await guarded(async () => {
      const [g, l, a] = await Promise.all([api.geoStatus(), api.blocklists(), api.abuseStatus()])
      geo.value = g
      lists.value = l.lists
      abuse.value = a
    })
  }

  async function updateGeo(): Promise<void> {
    const status = await guarded(api.geoUpdate)
    if (status) geo.value = status
  }

  async function toggleList(id: string, enabled: boolean): Promise<void> {
    busy.value = true
    const view = await guarded(() => api.setListEnabled(id, enabled))
    busy.value = false
    if (view) lists.value = view.lists
  }

  async function refreshList(id: string): Promise<void> {
    busy.value = true
    const view = await guarded(() => api.refreshList(id))
    busy.value = false
    if (view) lists.value = view.lists
  }

  async function saveKey(key: string | null): Promise<void> {
    const status = await guarded(() => api.setAbuseKey(key))
    if (status) abuse.value = status
  }

  async function checkAddress(addr: string): Promise<void> {
    check.value = null
    const view = await guarded(() => api.abuseCheck(addr.trim()))
    if (view) check.value = view
    await guarded(async () => {
      abuse.value = await api.abuseStatus()
    })
  }

  /** Looks the live remote addresses up (locally, in the agent) and rebuilds the leaderboard. */
  async function updateCountries(talkers: readonly RemoteTalker[]): Promise<void> {
    if (talkers.length === 0) {
      countries.value = []
      return
    }
    const result = await guarded(() => api.geoLookup(talkers.map((t) => t.addr).slice(0, 500)))
    if (result) countries.value = countryLeaderboard(talkers, result.entries)
  }

  /** The agent went away: forget what we showed. */
  function reset(): void {
    geo.value = null
    lists.value = []
    abuse.value = null
    countries.value = []
    check.value = null
    error.value = null
    busy.value = false
  }

  return {
    geo,
    lists,
    abuse,
    countries,
    check,
    error,
    busy,
    geoReady,
    refresh,
    updateGeo,
    toggleList,
    refreshList,
    saveKey,
    checkAddress,
    updateCountries,
    reset,
  }
})

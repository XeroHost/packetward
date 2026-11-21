// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Where an address is, for flags and the attack map. The lookup is local to the agent (the GeoIP
// database), never a web service; addresses are asked for in batches and remembered. Without a
// database nothing is asked and nothing is shown.
import { defineStore } from 'pinia'
import { ref, shallowReactive } from 'vue'
import * as api from '@/api/intel'

/** What is known about one address: its country, or `null` for a private/unknown one. */
export interface GeoPlace {
  code: string
}

const BATCH = 500
const FLUSH_MS = 150
/** A missing database is looked for again after this long (the user may have downloaded it). */
const RECHECK_MS = 30_000

export const useGeoStore = defineStore('geo', () => {
  /** `undefined` = not asked yet, `null` = nothing to show for it. */
  const places = shallowReactive(new Map<string, GeoPlace | null>())
  const ready = ref<boolean | null>(null)

  const queue = new Set<string>()
  const asked = new Set<string>()
  let timer: ReturnType<typeof setTimeout> | undefined
  let checkedAt = 0

  async function checkReady(): Promise<boolean> {
    const now = Date.now()
    if (ready.value !== null && (ready.value || now - checkedAt < RECHECK_MS)) return ready.value
    checkedAt = now
    try {
      ready.value = (await api.geoStatus()).state === 'ready'
    } catch {
      ready.value = false
    }
    return ready.value
  }

  async function flush(): Promise<void> {
    timer = undefined
    const batch = [...queue].slice(0, BATCH)
    for (const addr of batch) queue.delete(addr)
    if (batch.length === 0) return
    if (!(await checkReady())) {
      // Try again later; the addresses stay unknown (undefined), not "nothing to show".
      for (const addr of batch) asked.delete(addr)
      return
    }
    try {
      const result = await api.geoLookup(batch)
      for (const entry of result.entries) {
        places.set(
          entry.addr,
          !entry.reserved && entry.country_code ? { code: entry.country_code.toUpperCase() } : null,
        )
      }
      // Anything the agent did not answer is final too: do not ask again and again.
      for (const addr of batch) if (!places.has(addr)) places.set(addr, null)
    } catch {
      for (const addr of batch) asked.delete(addr)
    }
    if (queue.size > 0) schedule()
  }

  function schedule(): void {
    if (timer === undefined) timer = setTimeout(() => void flush(), FLUSH_MS)
  }

  /**
   * The country of `addr` if it is known yet. Reading it also asks for it (once): a component that
   * shows a flag just calls this and re-renders when the answer lands.
   */
  function place(addr: string): GeoPlace | null | undefined {
    const known = places.get(addr)
    if (known !== undefined) return known
    if (addr !== '' && !asked.has(addr)) {
      asked.add(addr)
      queue.add(addr)
      schedule()
    }
    return undefined
  }

  /** Asks for many addresses at once (the attack map). */
  function warm(addrs: readonly string[]): void {
    for (const addr of addrs) place(addr)
  }

  function reset(): void {
    places.clear()
    queue.clear()
    asked.clear()
    ready.value = null
    checkedAt = 0
    if (timer !== undefined) clearTimeout(timer)
    timer = undefined
  }

  return { places, ready, place, warm, reset }
})

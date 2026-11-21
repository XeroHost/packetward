// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { defineStore } from 'pinia'
import { computed, ref, shallowRef } from 'vue'
import * as api from '@/api/rdp'
import { AgentCallError, type CallErrorKind } from '@/api/call'
import type { RdpAudit } from '@/types/generated/RdpAudit'
import type { RdpCountryPolicy } from '@/types/generated/RdpCountryPolicy'
import type { RdpCountryStatus } from '@/types/generated/RdpCountryStatus'

export type RdpFailure = { kind: CallErrorKind; message: string }

function failure(err: unknown): RdpFailure {
  if (err instanceof AgentCallError) return { kind: err.kind, message: err.message }
  return { kind: 'failed', message: String(err) }
}

/**
 * RDP Shield: the exposure audit and the guarded changes. A change waits for confirmation from a new
 * connection; the agent reverts it by itself when the time runs out, and `pending` drives the
 * countdown shown on every page.
 */
export const useRdpStore = defineStore('rdp', () => {
  const audit = shallowRef<RdpAudit | null>(null)
  const error = ref<RdpFailure | null>(null)
  const busy = ref(false)
  const country = shallowRef<RdpCountryStatus | null>(null)
  const countryError = ref<RdpFailure | null>(null)
  const now = ref(Date.now())

  const pending = computed(() => audit.value?.pending ?? null)
  /** Whole seconds left to confirm the pending change (never negative). */
  const secondsLeft = computed(() =>
    pending.value ? Math.max(0, Math.ceil((pending.value.deadline_unix_ms - now.value) / 1000)) : 0,
  )

  let poll: ReturnType<typeof setInterval> | null = null

  async function load(): Promise<void> {
    try {
      audit.value = await api.fetchRdpAudit()
      error.value = null
    } catch (err) {
      const f = failure(err)
      // An older agent without the Shield is not an error worth showing on every page.
      if (f.kind !== 'unsupported') error.value = f
    }
  }

  /** Keeps the audit (and so the countdown) current while the agent is connected. */
  function startWatch(): void {
    stopWatch()
    void load()
    poll = setInterval(() => {
      now.value = Date.now()
      // Faster while a change is waiting: the countdown must be accurate.
      if (pending.value || Math.floor(now.value / 1000) % 5 === 0) void load()
    }, 1000)
  }

  function stopWatch(): void {
    if (poll !== null) clearInterval(poll)
    poll = null
  }

  async function run(action: () => Promise<RdpAudit>): Promise<boolean> {
    if (busy.value) return false
    busy.value = true
    error.value = null
    try {
      audit.value = await action()
      now.value = Date.now()
      return true
    } catch (err) {
      error.value = failure(err)
      return false
    } finally {
      busy.value = false
    }
  }

  const restrict = (request: api.RdpRestrictRequest) => run(() => api.restrictRdp(request))
  const unrestrict = () => run(() => api.unrestrictRdp())
  const changePort = (request: api.RdpPortRequest) => run(() => api.changeRdpPort(request))
  const setNla = (required: boolean) => run(() => api.setRdpNla(required))
  const setLockout = (request: api.RdpLockoutRequest) => run(() => api.setRdpLockout(request))
  const setAttempts = (attempts: api.RdpAttempts) => run(() => api.setRdpAttempts(attempts))
  const confirm = () =>
    pending.value ? run(() => api.confirmRdp(pending.value!.id)) : Promise.resolve(false)
  const cancel = () =>
    pending.value ? run(() => api.cancelRdp(pending.value!.id)) : Promise.resolve(false)
  const reset = () => run(() => api.resetRdp())

  async function loadCountry(): Promise<void> {
    try {
      country.value = await api.fetchRdpCountry()
      countryError.value = null
    } catch (err) {
      const f = failure(err)
      // An older agent without the restriction just has no such row.
      if (f.kind !== 'unsupported') countryError.value = f
    }
  }

  /** Saves the country policy; false when the agent refused it (the reason is in `countryError`). */
  async function saveCountry(policy: RdpCountryPolicy): Promise<boolean> {
    countryError.value = null
    try {
      country.value = await api.setRdpCountry(policy)
      return true
    } catch (err) {
      countryError.value = failure(err)
      return false
    }
  }

  async function endSession(sessionId: number, logoff: boolean): Promise<boolean> {
    try {
      await api.endRdpSession(sessionId, logoff)
      return true
    } catch (err) {
      error.value = failure(err)
      return false
    }
  }

  function reset_(): void {
    stopWatch()
    audit.value = null
  }

  return {
    audit,
    error,
    busy,
    country,
    countryError,
    pending,
    secondsLeft,
    load,
    loadCountry,
    saveCountry,
    startWatch,
    stopWatch,
    restrict,
    unrestrict,
    changePort,
    setNla,
    setLockout,
    setAttempts,
    confirm,
    cancel,
    reset,
    endSession,
    disconnect: reset_,
  }
})

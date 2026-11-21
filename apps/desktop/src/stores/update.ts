// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import {
  checkForUpdate,
  getUpdateInfo,
  installUpdate,
  type InstallEvent,
  type UpdateCheck,
  type UpdateInfo,
} from '@/api/update'
import { useSettingsStore } from './settings'

export type UpdateStatus =
  'idle' | 'checking' | 'notConfigured' | 'upToDate' | 'available' | 'installing' | 'error'

/** Wait before the start-up check so it never competes with the first paint. */
export const START_CHECK_DELAY_MS = 5000
/** How often the automatic check repeats while the app stays open. */
export const AUTO_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000

type Available = Extract<UpdateCheck, { state: 'available' }>

/**
 * Update state. The channel and "check at start" live in the settings store (persisted in ui.json);
 * this store only runs checks and installs. Checks run when the user presses the button and, while
 * "check automatically" is on (the default), at start and every 24 hours. An install only ever starts
 * from the button.
 */
export const useUpdateStore = defineStore('update', () => {
  const settings = useSettingsStore()

  const info = ref<UpdateInfo | null>(null)
  const status = ref<UpdateStatus>('idle')
  const available = ref<Available | null>(null)
  const error = ref<string | null>(null)
  /** 0..1 while downloading; null while the size is not known. */
  const progress = ref<number | null>(null)
  const checkedAt = ref<number | null>(null)

  const configured = computed(() => info.value?.configured ?? false)
  const busy = computed(() => status.value === 'checking' || status.value === 'installing')

  async function load(): Promise<void> {
    try {
      info.value = await getUpdateInfo()
      if (!info.value.configured) status.value = 'notConfigured'
    } catch (err) {
      error.value = String(err)
      status.value = 'error'
    }
  }

  /** Forgets the last result, for example because the channel changed. */
  function reset(): void {
    if (busy.value) return
    available.value = null
    error.value = null
    progress.value = null
    status.value = info.value && !info.value.configured ? 'notConfigured' : 'idle'
  }

  async function check(): Promise<void> {
    if (busy.value) return
    status.value = 'checking'
    error.value = null
    available.value = null
    if (!info.value) await load()
    if (!info.value) return // load() already reported the failure
    if (!info.value.configured) {
      status.value = 'notConfigured'
      return
    }
    status.value = 'checking'
    try {
      const result = await checkForUpdate(settings.updates.channel)
      checkedAt.value = Date.now()
      switch (result.state) {
        case 'notConfigured':
          status.value = 'notConfigured'
          break
        case 'upToDate':
          status.value = 'upToDate'
          break
        case 'available':
          available.value = result
          status.value = 'available'
          break
      }
    } catch (err) {
      error.value = String(err)
      status.value = 'error'
    }
  }

  function onInstallEvent(event: InstallEvent): void {
    if (event.event === 'progress') {
      progress.value =
        event.total && event.total > 0 ? Math.min(1, event.downloaded / event.total) : null
    }
  }

  async function install(): Promise<void> {
    if (status.value !== 'available' || !available.value) return
    status.value = 'installing'
    error.value = null
    progress.value = null
    try {
      await installUpdate(onInstallEvent)
      // Only reached when the installer could not take over; Windows normally ends the app first.
    } catch (err) {
      error.value = String(err)
      status.value = 'error'
    }
  }

  let timer: ReturnType<typeof setInterval> | null = null

  /** Stops the 24-hour repetition (the window is going away, or tests). */
  function stopAutoCheck(): void {
    if (timer !== null) clearInterval(timer)
    timer = null
  }

  /**
   * The automatic check: one a few seconds after start and then every 24 hours, while the user keeps
   * the switch on and this build can update at all. It only looks; failures stay silent (the Settings
   * page shows them when the user looks) and nothing is ever installed from here.
   */
  let starting = false
  async function checkAtStart(): Promise<void> {
    if (!settings.updates.checkOnStart || starting) return
    starting = true
    try {
      await load()
      if (!configured.value) return
      await new Promise((resolve) => setTimeout(resolve, START_CHECK_DELAY_MS))
      // The user may have switched it off while we waited.
      if (!settings.updates.checkOnStart) return
      await check()
    } finally {
      starting = false
    }
    if (!settings.updates.checkOnStart) return
    stopAutoCheck()
    timer = setInterval(() => {
      // The switch may have been turned off since: it applies at once.
      if (!settings.updates.checkOnStart || busy.value || status.value === 'available') return
      void check()
    }, AUTO_CHECK_INTERVAL_MS)
  }

  // The schedule follows the switch while the app is open: on starts it, off stops it.
  watch(
    () => settings.updates.checkOnStart,
    (on) => {
      if (on) void checkAtStart()
      else stopAutoCheck()
    },
  )

  return {
    info,
    status,
    available,
    error,
    progress,
    checkedAt,
    configured,
    busy,
    load,
    reset,
    check,
    install,
    checkAtStart,
    stopAutoCheck,
  }
})

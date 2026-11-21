// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { defineStore } from 'pinia'
import { ref, shallowRef } from 'vue'
import * as api from '@/api/capture'
import { AgentCallError, type CallErrorKind } from '@/api/call'
import type { CaptureFile } from '@/types/generated/CaptureFile'
import type { CaptureLive } from '@/types/generated/CaptureLive'
import type { CaptureStatus } from '@/types/generated/CaptureStatus'
import type { RecordStartRequest } from '@/types/generated/RecordStartRequest'
import type { SavedBundle } from '@/types/generated/SavedBundle'
import type { SupportBundleRequest } from '@/types/generated/SupportBundleRequest'
import type { SupportPreview } from '@/types/generated/SupportPreview'

/** Seconds of capture history the Traffic chart keeps (one point per second). */
export const CAPTURE_HISTORY = 120

export type CaptureFailure = { kind: CallErrorKind; message: string }

function failure(err: unknown): CaptureFailure {
  if (err instanceof AgentCallError) return { kind: err.kind, message: err.message }
  return { kind: 'failed', message: String(err) }
}

export interface CaptureHistory {
  /** Unix ms of each sample, oldest first. */
  t: number[]
  inBps: number[]
  outBps: number[]
}

/**
 * Packet capture: the backend explanation, the live per-second statistics (with a bounded history),
 * recordings, their files and the support bundle.
 */
export const useCaptureStore = defineStore('capture', () => {
  const status = shallowRef<CaptureStatus | null>(null)
  const live = shallowRef<CaptureLive | null>(null)
  const history = shallowRef<CaptureHistory>({ t: [], inBps: [], outBps: [] })
  /** Bumped on every live sample so charts know to redraw. */
  const tick = ref(0)
  const error = ref<CaptureFailure | null>(null)
  const busy = ref(false)

  const files = shallowRef<CaptureFile[]>([])
  const filesDir = ref('')
  const filesError = ref<CaptureFailure | null>(null)

  const bundlePreview = shallowRef<SupportPreview | null>(null)
  const bundleBusy = ref(false)
  const bundleError = ref<CaptureFailure | null>(null)
  const bundleSaved = ref<SavedBundle | null>(null)

  function applyLive(sample: CaptureLive): void {
    live.value = sample
    const h = history.value
    const keep = h.t.length >= CAPTURE_HISTORY ? h.t.length - CAPTURE_HISTORY + 1 : 0
    history.value = {
      t: [...h.t.slice(keep), sample.unix_ms],
      inBps: [...h.inBps.slice(keep), sample.inbound.bps],
      outBps: [...h.outBps.slice(keep), sample.outbound.bps],
    }
    tick.value += 1
  }

  async function guarded(action: () => Promise<void>): Promise<void> {
    if (busy.value) return
    busy.value = true
    error.value = null
    try {
      await action()
    } catch (err) {
      error.value = failure(err)
    } finally {
      busy.value = false
    }
  }

  async function refresh(): Promise<void> {
    try {
      status.value = await api.fetchCaptureStatus()
      error.value = null
    } catch (err) {
      error.value = failure(err)
    }
  }

  const start = (interfaceName?: string) =>
    guarded(async () => {
      status.value = await api.startCapture(interfaceName ? { interface: interfaceName } : {})
    })

  const stop = () =>
    guarded(async () => {
      status.value = await api.stopCapture()
      live.value = null
    })

  const record = (request: RecordStartRequest) =>
    guarded(async () => {
      status.value = await api.startRecording(request)
    })

  const stopRecord = () =>
    guarded(async () => {
      status.value = await api.stopRecording()
      await loadFiles()
    })

  async function loadFiles(): Promise<void> {
    try {
      const result = await api.fetchCaptureFiles()
      files.value = result.files
      filesDir.value = result.dir
      filesError.value = null
    } catch (err) {
      filesError.value = failure(err)
    }
  }

  async function removeFile(name: string): Promise<void> {
    try {
      const result = await api.deleteCaptureFile(name)
      files.value = result.files
      filesError.value = null
    } catch (err) {
      filesError.value = failure(err)
    }
  }

  async function previewBundle(request: SupportBundleRequest): Promise<void> {
    bundleError.value = null
    bundleSaved.value = null
    try {
      bundlePreview.value = await api.previewSupportBundle(request)
    } catch (err) {
      bundlePreview.value = null
      bundleError.value = failure(err)
    }
  }

  async function saveBundle(request: SupportBundleRequest): Promise<void> {
    if (bundleBusy.value) return
    bundleBusy.value = true
    bundleError.value = null
    try {
      bundleSaved.value = await api.saveSupportBundle(request)
    } catch (err) {
      bundleSaved.value = null
      bundleError.value = failure(err)
    } finally {
      bundleBusy.value = false
    }
  }

  /** The agent went away: nothing may look live. */
  function reset(): void {
    status.value = null
    live.value = null
    history.value = { t: [], inBps: [], outBps: [] }
    tick.value += 1
    bundlePreview.value = null
    bundleSaved.value = null
  }

  return {
    status,
    live,
    history,
    tick,
    error,
    busy,
    files,
    filesDir,
    filesError,
    bundlePreview,
    bundleBusy,
    bundleError,
    bundleSaved,
    applyLive,
    refresh,
    start,
    stop,
    record,
    stopRecord,
    loadFiles,
    removeFile,
    previewBundle,
    saveBundle,
    reset,
  }
})

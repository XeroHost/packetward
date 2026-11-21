// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Typed wrappers for packet capture and the support bundle (via the shell's `agent_call`).
import { invoke } from '@tauri-apps/api/core'
import type { CaptureFiles } from '@/types/generated/CaptureFiles'
import type { CaptureLive } from '@/types/generated/CaptureLive'
import type { CaptureStartRequest } from '@/types/generated/CaptureStartRequest'
import type { CaptureStatus } from '@/types/generated/CaptureStatus'
import type { RecordStartRequest } from '@/types/generated/RecordStartRequest'
import type { SavedBundle } from '@/types/generated/SavedBundle'
import type { SupportBundleRequest } from '@/types/generated/SupportBundleRequest'
import type { SupportPreview } from '@/types/generated/SupportPreview'
import { callAgent, parseCallError } from './call'
import { isTauri } from './uiPrefs'

export type {
  CaptureFiles,
  CaptureLive,
  CaptureStartRequest,
  CaptureStatus,
  RecordStartRequest,
  SavedBundle,
  SupportBundleRequest,
  SupportPreview,
}

export const fetchCaptureStatus = () => callAgent<CaptureStatus>('capture.status')
export const startCapture = (request: CaptureStartRequest = {}) =>
  callAgent<CaptureStatus>('capture.start', request)
export const stopCapture = () => callAgent<CaptureStatus>('capture.stop')
export const startRecording = (request: RecordStartRequest) =>
  callAgent<CaptureStatus>('capture.record.start', request)
export const stopRecording = () => callAgent<CaptureStatus>('capture.record.stop')
export const fetchCaptureFiles = () => callAgent<CaptureFiles>('capture.files')
export const deleteCaptureFile = (name: string) =>
  callAgent<CaptureFiles>('capture.files.delete', { name })
export const previewSupportBundle = (request: SupportBundleRequest) =>
  callAgent<SupportPreview>('support.bundle.preview', request)

/** Builds the bundle and saves it in this user's Documents folder. Nothing is uploaded. */
export async function saveSupportBundle(request: SupportBundleRequest): Promise<SavedBundle> {
  if (!isTauri()) throw parseCallError('unsupported')
  try {
    return await invoke<SavedBundle>('support_bundle_save', { request })
  } catch (err) {
    throw parseCallError(err)
  }
}

// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Typed wrappers for the speed test (via the shell's `agent_call`).
import type { SpeedEvent } from '@/types/generated/SpeedEvent'
import type { SpeedRequest } from '@/types/generated/SpeedRequest'
import type { SpeedResultView } from '@/types/generated/SpeedResultView'
import type { SpeedStarted } from '@/types/generated/SpeedStarted'
import { callAgent } from './call'

export type { SpeedEvent, SpeedRequest, SpeedResultView, SpeedStarted }

export const startSpeedTest = (request: SpeedRequest) =>
  callAgent<SpeedStarted>('speed.start', request)
export const cancelSpeedTest = (jobId: number) => callAgent<null>('speed.cancel', { job_id: jobId })

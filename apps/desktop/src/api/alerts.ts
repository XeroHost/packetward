// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Typed wrappers for the alert inbox of the agent (via the shell's `agent_call`).
import type { AlertList } from '@/types/generated/AlertList'
import type { AlertView } from '@/types/generated/AlertView'
import { callAgent } from './call'

export type { AlertList, AlertView }

export const fetchAlerts = () => callAgent<AlertList>('alerts.list')
/** Removes the incidents that already ended; ongoing ones stay. */
export const clearEndedAlerts = () => callAgent<AlertList>('alerts.clear')

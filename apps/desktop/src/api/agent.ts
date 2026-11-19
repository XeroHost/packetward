// SPDX-License-Identifier: GPL-3.0-or-later
// Typed wrappers for the agent connection owned by the desktop shell (src-tauri/src/bridge.rs).
// This module is the only place that talks to Tauri for the agent.
import { Channel, invoke } from '@tauri-apps/api/core'
import type { AccessReason } from '@/types/generated/AccessReason'
import type { AgentConnection } from '@/types/generated/AgentConnection'
import type { BridgeEvent } from '@/types/generated/BridgeEvent'
import type { ElevatedAction } from '@/types/generated/ElevatedAction'
import type { ConnectionsResponse } from '@/types/generated/ConnectionsResponse'
import type { ElevationOutcome } from '@/types/generated/ElevationOutcome'
import { previewConnections, previewRowCount, previewRowsRequested, previewStats } from './preview'
import { isTauri } from './uiPrefs'

export type {
  AccessReason,
  AgentConnection,
  BridgeEvent,
  ConnectionsResponse,
  ElevatedAction,
  ElevationOutcome,
}

/** Version string reported while running in a plain browser, where there is no agent. */
export const PREVIEW_AGENT_VERSION = 'browser-preview'

/**
 * Starts watching the agent: `onEvent` receives every status change and every heartbeat.
 * Returns a function that stops the watch.
 *
 * Outside Tauri (plain browser during UI work, unit tests) there is no agent; a connected
 * preview with synthetic heartbeats is emitted so the rest of the UI can be developed.
 */
export function watchAgent(onEvent: (event: BridgeEvent) => void): () => void {
  if (!isTauri()) return previewWatch(onEvent)
  const channel = new Channel<BridgeEvent>()
  channel.onmessage = onEvent
  void invoke('agent_watch', { onEvent: channel })
  // The shell replaces its previous watcher on the next call, so there is nothing to cancel.
  return () => {
    channel.onmessage = () => {}
  }
}

function previewWatch(onEvent: (event: BridgeEvent) => void): () => void {
  const started = Date.now()
  let seq = 0
  onEvent({
    type: 'status',
    data: {
      state: 'connected',
      agent_version: PREVIEW_AGENT_VERSION,
      protocol_major: 1,
      protocol_minor: 0,
    },
  })
  const timer = setInterval(() => {
    seq += 1
    onEvent({ type: 'stats', data: previewStats(seq) })
    onEvent({
      type: 'heartbeat',
      data: {
        seq,
        uptime_secs: Math.floor((Date.now() - started) / 1000),
        unix_ms: Date.now(),
      },
    })
  }, 1000)
  return () => clearInterval(timer)
}

/** Runs `packetward-agent start|repair` elevated; the user sees a Windows (UAC) prompt. */
export async function elevateAgent(action: ElevatedAction): Promise<ElevationOutcome> {
  if (!isTauri()) return { result: 'failed', message: 'Not available in the browser preview.' }
  return invoke<ElevationOutcome>('agent_elevate', { action })
}

/** Raised by `fetchConnections` when the agent is too old to provide the connection table. */
export class AgentUnsupportedError extends Error {
  constructor() {
    super('The installed agent does not provide the connection table.')
  }
}

/**
 * The agent's connection table (capped on the agent side; `truncated` says when). Throws
 * `AgentUnsupportedError` for an agent older than the app and an Error for anything else.
 */
export async function fetchConnections(limit?: number): Promise<ConnectionsResponse> {
  // `?rows=N` forces synthetic data in a dev build, even inside Tauri (performance checks). The
  // check is a compile-time constant, so production builds drop it.
  if (!isTauri() || (import.meta.env.DEV && previewRowsRequested())) {
    return previewConnections(previewRowCount())
  }
  try {
    return await invoke<ConnectionsResponse>('agent_connections', { limit: limit ?? null })
  } catch (err) {
    if (err === 'unsupported') throw new AgentUnsupportedError()
    throw new Error(String(err), { cause: err })
  }
}

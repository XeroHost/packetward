// SPDX-License-Identifier: GPL-3.0-or-later
// Typed wrappers for the agent connection owned by the desktop shell (src-tauri/src/bridge.rs).
// This module is the only place that talks to Tauri for the agent.
import { Channel, invoke } from '@tauri-apps/api/core'
import type { AccessReason } from '@/types/generated/AccessReason'
import type { AgentConnection } from '@/types/generated/AgentConnection'
import type { BridgeEvent } from '@/types/generated/BridgeEvent'
import type { ElevatedAction } from '@/types/generated/ElevatedAction'
import type { ElevationOutcome } from '@/types/generated/ElevationOutcome'
import { isTauri } from './uiPrefs'

export type { AccessReason, AgentConnection, BridgeEvent, ElevatedAction, ElevationOutcome }

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

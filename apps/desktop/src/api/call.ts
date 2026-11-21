// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// One typed way to call allowlisted agent methods through the shell's `agent_call` command.
import { invoke } from '@tauri-apps/api/core'
import { isTauri } from './uiPrefs'

export type CallErrorKind =
  'not_connected' | 'unsupported' | 'busy' | 'bad_request' | 'mode_unavailable' | 'failed'

/** An agent request that failed; `message` is the agent's own explanation when it gave one. */
export class AgentCallError extends Error {
  constructor(
    readonly kind: CallErrorKind,
    message: string,
  ) {
    super(message)
  }
}

/** The shell reports agent errors as `<Code>: <message>` (see `agent_call` in bridge.rs). */
export function parseCallError(raw: unknown): AgentCallError {
  const text = String(raw)
  if (text === 'not_connected') return new AgentCallError('not_connected', text)
  if (text === 'unsupported' || text === 'forbidden') return new AgentCallError('unsupported', text)
  const match = /^(\w+): ([\s\S]*)$/.exec(text)
  if (match?.[1] === 'Busy') return new AgentCallError('busy', match[2] ?? text)
  if (match?.[1] === 'BadRequest') return new AgentCallError('bad_request', match[2] ?? text)
  if (match?.[1] === 'ModeUnavailable') {
    return new AgentCallError('mode_unavailable', match[2] ?? text)
  }
  return new AgentCallError('failed', match?.[2] ?? text)
}

export async function callAgent<T>(method: string, payload?: unknown): Promise<T> {
  if (!isTauri()) throw new AgentCallError('unsupported', 'Not available in the browser preview.')
  try {
    return await invoke<T>('agent_call', { method, payload: payload ?? null })
  } catch (err) {
    throw parseCallError(err)
  }
}

<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
// Settings → MCP: the master switch, the level of every execution tool, the write limit and the
// configuration snippet for the supported AI clients. The policy lives in the agent
// (`mcp.settings.get/set`); the shell only supplies the installed `pwctl.exe` path and a smoke test.
import SettingRow from '@/components/pw/SettingRow.vue'
import PwSelect from '@/components/pw/PwSelect.vue'
import { TriangleAlert } from '@/components/pw/icons'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { AgentCallError } from '@/api/call'
import {
  fetchMcpInstallInfo,
  fetchMcpSettings,
  runMcpSelfCheck,
  saveMcpSettings,
  type McpInstallInfo,
  type McpSelfCheck,
} from '@/api/mcp'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { FIELD } from '@/features/diagnostics/fieldClass'
import type { McpSettingsSetRequest } from '@/types/generated/McpSettingsSetRequest'
import type { McpSettingsView } from '@/types/generated/McpSettingsView'
import type { McpToolLevel } from '@/types/generated/McpToolLevel'

/**
 * Tools the agent never runs without an approval, whatever the client asks for. Kept in sync with
 * `APPROVAL_ONLY_TOOLS` in `crates/pw-engine/src/mcp.rs`; the agent refuses `automatic` for them
 * anyway, so a stale copy here cannot widen anything.
 */
const APPROVAL_ONLY = new Set([
  'unblock_ip',
  'set_guardian_mode',
  'create_firewall_rule',
  'delete_firewall_rule',
])

type ClientId = 'claudeDesktop' | 'claudeCode' | 'opencode' | 'cursor'
const CLIENTS: readonly ClientId[] = ['claudeCode', 'claudeDesktop', 'opencode', 'cursor']

/** Where each client keeps its configuration file (shown under the snippet). */
const CLIENT_FILES: Record<ClientId, string> = {
  claudeDesktop: '%APPDATA%\\Claude\\claude_desktop_config.json',
  claudeCode: '.mcp.json (project) or %USERPROFILE%\\.claude.json',
  opencode: 'opencode.json (project) or %USERPROFILE%\\.config\\opencode\\opencode.json',
  cursor: '.cursor\\mcp.json (project) or %USERPROFILE%\\.cursor\\mcp.json',
}

const { t } = useI18n()

const view = ref<McpSettingsView | null>(null)
const install = ref<McpInstallInfo | null>(null)
const loadError = ref<string | null>(null)
const saveError = ref<string | null>(null)
const saving = ref(false)
const limit = ref('6')
const limitError = ref<string | null>(null)
const dialog = ref<HTMLDialogElement | null>(null)
const client = ref<ClientId>('claudeCode')
const copied = ref(false)
const check = ref<McpSelfCheck | null>(null)
const checking = ref(false)

const enabled = computed(() => view.value?.enabled ?? false)
const tools = computed(() => view.value?.tools ?? [])

/** The "old agent" sentence already says what happened; other errors keep the reason prefix. */
function message(prefix: string, reason: string | null): string {
  if (!reason) return ''
  const friendly = t('settings.mcp.oldAgent')
  return reason === friendly ? reason : t(prefix, { reason })
}

const loadMessage = computed(() => message('settings.mcp.loadError', loadError.value))
const saveMessage = computed(() => message('settings.mcp.saveError', saveError.value))

function failure(err: unknown): string {
  if (err instanceof AgentCallError) {
    // The bridge maps `forbidden` to `unsupported`; the old agent has no MCP methods at all.
    // Showing that raw code in a settings page is not useful to the owner.
    if (err.kind === 'unsupported') return t('settings.mcp.oldAgent')
    return err.message
  }
  return String(err)
}

onMounted(async () => {
  const [settings, info] = await Promise.allSettled([fetchMcpSettings(), fetchMcpInstallInfo()])
  if (settings.status === 'fulfilled') {
    view.value = settings.value
    limit.value = String(settings.value.write_limit_per_min)
  } else {
    loadError.value = failure(settings.reason)
  }
  if (info.status === 'fulfilled') install.value = info.value
})

/** Saves only the given fields and adopts the policy the agent returns. */
async function apply(request: McpSettingsSetRequest): Promise<boolean> {
  saving.value = true
  saveError.value = null
  try {
    const saved = await saveMcpSettings(request)
    view.value = saved
    limit.value = String(saved.write_limit_per_min)
    return true
  } catch (err) {
    saveError.value = failure(err)
    return false
  } finally {
    saving.value = false
  }
}

function onEnabled(on: boolean): void {
  if (on) {
    // Giving an AI write access is the one decision of this page that needs a deliberate OK.
    dialog.value?.showModal()
    return
  }
  void apply({ enabled: false })
}

async function confirmEnable(): Promise<void> {
  dialog.value?.close()
  await apply({ enabled: true })
}

function levelOf(tool: string): McpToolLevel {
  return tools.value.find((setting) => setting.tool === tool)?.level ?? 'disabled'
}

function levelOptions(tool: string): { value: McpToolLevel; label: string }[] {
  const values: McpToolLevel[] = APPROVAL_ONLY.has(tool)
    ? ['disabled', 'approval']
    : ['disabled', 'automatic', 'approval']
  return values.map((value) => ({ value, label: t(`settings.mcp.level.${value}`) }))
}

function onLevel(tool: string, level: unknown): void {
  if (typeof level !== 'string' || level === levelOf(tool)) return
  void apply({ tools: [{ tool, level: level as McpToolLevel }] })
}

async function saveLimit(): Promise<void> {
  const value = Number(limit.value)
  if (!Number.isInteger(value) || value < 1 || value > 60) {
    limitError.value = t('settings.mcp.limit.range')
    return
  }
  limitError.value = null
  await apply({ write_limit_per_min: value })
}

/** `C:\Program Files\PacketWard\pwctl.exe` as a JSON string literal, backslashes escaped. */
const pathLiteral = computed(() => JSON.stringify(install.value?.path ?? ''))

const snippet = computed(() => {
  const path = pathLiteral.value
  switch (client.value) {
    case 'opencode':
      return `{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "packetward": {
      "type": "local",
      "command": [${path}, "mcp"],
      "enabled": true
    }
  }
}`
    case 'claudeCode':
      return `{
  "mcpServers": {
    "packetward": {
      "type": "stdio",
      "command": ${path},
      "args": ["mcp"]
    }
  }
}`
    default:
      return `{
  "mcpServers": {
    "packetward": {
      "command": ${path},
      "args": ["mcp"]
    }
  }
}`
  }
})

async function copySnippet(): Promise<void> {
  try {
    await navigator.clipboard.writeText(snippet.value)
    copied.value = true
    setTimeout(() => {
      copied.value = false
    }, 1500)
  } catch (err) {
    saveError.value = failure(err)
  }
}

async function runCheck(): Promise<void> {
  checking.value = true
  try {
    check.value = await runMcpSelfCheck()
  } catch (err) {
    check.value = { ok: false, path: '', outcome: 'spawn', detail: failure(err) }
  } finally {
    checking.value = false
  }
}

const checkMessage = computed(() => {
  const result = check.value
  if (!result) return ''
  switch (result.outcome) {
    case 'ok':
      return t('settings.mcp.client.checkOk')
    case 'missing':
      return t('settings.mcp.client.checkMissing', { path: result.path })
    case 'timeout':
      return t('settings.mcp.client.checkTimeout')
    case 'exit':
      return t('settings.mcp.client.checkExit', { detail: result.detail })
    default:
      return t('settings.mcp.client.checkSpawn', { detail: result.detail })
  }
})
</script>

<template>
  <!-- Master switch -->
  <SettingRow :title="t('settings.mcp.title')" :description="t('settings.mcp.description')">
    <div class="grid grid-cols-[12rem_1fr] items-center gap-x-4">
      <label for="sw-mcp" class="text-sm">{{ t('settings.mcp.switch') }}</label>
      <div class="flex items-center gap-3">
        <Switch
          id="sw-mcp"
          data-testid="mcp-enabled"
          :model-value="enabled"
          :disabled="saving || view === null"
          @update:model-value="onEnabled"
        />
        <span class="text-text-muted text-xs">{{ t('settings.mcp.switchHint') }}</span>
      </div>
    </div>
    <p
      v-if="!enabled && view !== null"
      class="pw-note"
      data-tone="info"
      role="status"
      data-testid="mcp-off-note"
    >
      {{ t('settings.mcp.offNote') }}
    </p>
    <p v-if="loadError" class="text-danger text-sm" role="alert">
      {{ loadMessage }}
    </p>
    <p v-if="saveError" class="text-danger text-sm" role="alert" data-testid="mcp-save-error">
      {{ saveMessage }}
    </p>
  </SettingRow>

  <!-- Per-tool levels -->
  <SettingRow
    :title="t('settings.mcp.tools.title')"
    :description="t('settings.mcp.tools.description')"
  >
    <div class="flex flex-col gap-3" data-testid="mcp-tools">
      <div
        v-for="setting in tools"
        :key="setting.tool"
        class="grid grid-cols-[minmax(0,1fr)_11rem] items-center gap-4"
      >
        <div class="min-w-0">
          <p class="text-sm font-medium">{{ t(`settings.mcp.tools.${setting.tool}.name`) }}</p>
          <p class="text-text-muted text-xs">
            {{ t(`settings.mcp.tools.${setting.tool}.description`) }}
          </p>
          <p v-if="APPROVAL_ONLY.has(setting.tool)" class="text-text-muted text-xs italic">
            {{ t('settings.mcp.tools.approvalOnly') }}
          </p>
        </div>
        <PwSelect
          :model-value="setting.level"
          :options="levelOptions(setting.tool)"
          :disabled="saving"
          :aria-label="t(`settings.mcp.tools.${setting.tool}.name`)"
          :data-testid="`mcp-level-${setting.tool}`"
          @update:model-value="(level) => onLevel(setting.tool, level)"
        />
      </div>
    </div>
  </SettingRow>

  <!-- Write limit -->
  <SettingRow
    :title="t('settings.mcp.limit.title')"
    :description="t('settings.mcp.limit.description')"
  >
    <form class="flex flex-wrap items-end gap-3" @submit.prevent="saveLimit">
      <label class="flex w-40 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('settings.mcp.limit.label') }}</span>
        <input
          v-model="limit"
          :class="[FIELD, 'font-mono']"
          type="number"
          min="1"
          max="60"
          step="1"
          data-testid="mcp-limit"
        />
      </label>
      <Button type="submit" size="sm" :disabled="saving">{{ t('settings.mcp.limit.save') }}</Button>
      <span class="text-text-muted text-xs">{{ t('settings.mcp.limit.range') }}</span>
    </form>
    <p v-if="limitError" class="text-danger text-sm" role="alert">{{ limitError }}</p>
  </SettingRow>

  <!-- Client configuration -->
  <SettingRow
    :title="t('settings.mcp.client.title')"
    :description="t('settings.mcp.client.description')"
  >
    <div class="flex flex-wrap items-center gap-3">
      <PwSelect
        v-model="client"
        :options="CLIENTS.map((id) => ({ value: id, label: t(`settings.mcp.client.${id}`) }))"
        :aria-label="t('settings.mcp.client.label')"
        class="w-56"
      />
      <Button
        size="sm"
        variant="outline"
        data-testid="mcp-copy"
        :disabled="!install?.exists"
        @click="copySnippet"
      >
        {{ copied ? t('settings.mcp.client.copied') : t('settings.mcp.client.copy') }}
      </Button>
      <Button
        size="sm"
        variant="outline"
        data-testid="mcp-check"
        :disabled="checking"
        @click="runCheck"
      >
        {{ checking ? t('settings.mcp.client.checking') : t('settings.mcp.client.check') }}
      </Button>
    </div>

    <pre
      class="pw-well text-text-muted overflow-x-auto font-mono text-xs"
      data-testid="mcp-snippet"
      >{{ snippet }}</pre>
    <p class="text-text-muted text-xs">
      {{ t('settings.mcp.client.file', { path: CLIENT_FILES[client] }) }}
    </p>

    <p
      v-if="check"
      class="text-sm"
      :class="check.ok ? 'text-success' : 'text-warning'"
      role="status"
      data-testid="mcp-check-result"
    >
      {{ checkMessage }}
    </p>

    <p class="pw-note flex items-start gap-2" data-tone="warning">
      <TriangleAlert class="text-warning mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{{ t('settings.mcp.client.security') }}</span>
    </p>
  </SettingRow>

  <!-- Enabling is the one change that gives an AI write access: ask first. -->
  <dialog
    ref="dialog"
    class="pw-dialog m-auto w-[30rem] max-w-[92vw]"
    data-testid="mcp-enable-dialog"
  >
    <h2 class="text-xl">{{ t('settings.mcp.confirm.title') }}</h2>
    <p class="text-text-muted mt-2 text-sm">{{ t('settings.mcp.confirm.body') }}</p>
    <div class="mt-5 flex justify-end gap-2">
      <Button variant="outline" size="sm" @click="dialog?.close()">
        {{ t('settings.mcp.confirm.cancel') }}
      </Button>
      <Button size="sm" data-testid="mcp-enable-confirm" @click="confirmEnable">
        {{ t('settings.mcp.confirm.enable') }}
      </Button>
    </div>
  </dialog>
</template>

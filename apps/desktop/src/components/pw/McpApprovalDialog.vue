<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// The confirmation for MCP actions: every waiting request with its complete arguments, the
// consequence in one line, a live countdown and Approve / Reject. The dialog itself is the
// confirmation (no typed phrase); the consequence line says what approving would do.
import { animate } from 'motion-v'
import { Hourglass, TriangleAlert, Wrench } from '@/components/pw/icons'
import { nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { springDialog } from '@/lib/motion'
import { useMcpStore } from '@/stores/mcp'
import type { McpPendingAction } from '@/types/generated/McpPendingAction'

const { t, te } = useI18n()
const mcp = useMcpStore()
const dialog = ref<HTMLDialogElement | null>(null)

/** Actions that change protection or the firewall: approving them is shown in the threat tone. */
const RISKY = new Set([
  'block_ip',
  'unblock_ip',
  'set_guardian_mode',
  'create_firewall_rule',
  'delete_firewall_rule',
])

function risky(tool: string): boolean {
  return RISKY.has(tool)
}

function consequence(tool: string): string {
  const key = `mcp.approval.consequence.${tool}`
  return te(key) ? t(key) : t('mcp.approval.consequence.generic')
}

/** The arguments exactly as the AI sent them (pretty-printed JSON). */
function argsText(action: McpPendingAction): string {
  if (typeof action.args === 'string') return action.args
  try {
    return JSON.stringify(action.args, null, 2)
  } catch {
    return String(action.args)
  }
}

watch(
  () => mcp.open,
  async (isOpen) => {
    await nextTick()
    if (isOpen) {
      if (!dialog.value?.open) dialog.value?.showModal()
      // Grows out of the page with a spring (unless animations are off).
      if (dialog.value && document.documentElement.dataset.motion !== 'reduced') {
        animate(dialog.value, { opacity: [0, 1], scale: [0.95, 1], y: [10, 0] }, springDialog)
      }
    } else {
      dialog.value?.close()
    }
  },
)
</script>

<template>
  <dialog
    ref="dialog"
    class="pw-dialog m-auto w-[34rem] max-w-[92vw]"
    data-testid="mcp-dialog"
    @close="mcp.closeDialog()"
  >
    <div v-if="mcp.pending.length > 0" class="flex max-h-[80vh] flex-col gap-4">
      <header class="flex items-start gap-3">
        <Wrench class="text-info mt-1 size-5 shrink-0" aria-hidden="true" />
        <div class="min-w-0">
          <h2 class="text-xl">{{ t('mcp.approval.dialogTitle') }}</h2>
          <p class="text-text-muted mt-1 text-sm">{{ t('mcp.approval.dialogExplain') }}</p>
        </div>
      </header>

      <div class="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
        <section
          v-for="action in mcp.pending"
          :key="action.id"
          class="border-hairline flex flex-col gap-2 border-t pt-4 first:border-t-0 first:pt-0"
          :data-testid="`mcp-action-${action.id}`"
        >
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <p class="font-mono text-sm">{{ action.tool }}</p>
              <p class="text-sm">{{ action.summary }}</p>
            </div>
            <span class="text-text-muted flex shrink-0 items-center gap-1 text-xs">
              <Hourglass class="size-3.5" aria-hidden="true" />
              {{ t('mcp.approval.expiresIn', { seconds: mcp.secondsLeft(action) }) }}
            </span>
          </div>
          <p class="text-text-muted flex items-start gap-1.5 text-xs">
            <TriangleAlert
              class="mt-0.5 size-3.5 shrink-0"
              :class="risky(action.tool) ? 'text-danger' : ''"
              aria-hidden="true"
            />
            {{ consequence(action.tool) }}
          </p>
          <pre
            class="pw-well max-h-48 overflow-auto font-mono text-xs break-words whitespace-pre-wrap"
            >{{ argsText(action) }}</pre>
          <div class="flex flex-wrap justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              :disabled="mcp.busy.includes(action.id)"
              @click="mcp.reject(action.id)"
            >
              {{ t('mcp.approval.reject') }}
            </Button>
            <Button
              type="button"
              :variant="risky(action.tool) ? 'destructive' : 'default'"
              size="sm"
              :disabled="mcp.busy.includes(action.id)"
              @click="mcp.approve(action.id)"
            >
              {{ t('mcp.approval.approve') }}
            </Button>
          </div>
        </section>
      </div>

      <div v-if="mcp.error" class="pw-note" data-tone="danger" role="alert">
        {{ t('mcp.approval.error', { message: mcp.error.message }) }}
      </div>
    </div>
  </dialog>
</template>

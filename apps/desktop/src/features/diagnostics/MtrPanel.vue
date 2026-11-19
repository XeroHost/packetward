<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Check, ClipboardCopy, Play, Square } from 'lucide-vue-next'
import { computed, onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import IpCell from '@/components/pw/IpCell.vue'
import { copyText } from '@/lib/clipboard'
import { useDiagStore } from '@/stores/diag'
import { formatLoss, formatMs, isIcmpRateLimited, lossLevel } from './diagFormat'
import FailureNote from './FailureNote.vue'
import { FIELD } from './fieldClass'

const { t } = useI18n()
const diag = useDiagStore()

const target = ref('')
const cycles = ref(20)
const resolveNames = ref(true)
const copied = ref(false)
const copyFailed = ref(false)
let copiedTimer: ReturnType<typeof setTimeout> | null = null

const canStart = computed(() => target.value.trim() !== '' && !diag.mtrRunning)
const hops = computed(() => diag.mtrSnapshot?.hops ?? [])

function start(): void {
  if (!canStart.value) return
  void diag.runMtr(
    target.value.trim(),
    Math.min(200, Math.max(1, Math.floor(cycles.value) || 1)),
    resolveNames.value,
  )
}

async function copyReport(): Promise<void> {
  const text = await diag.mtrReportText()
  if (text === null) return
  copyFailed.value = !(await copyText(text))
  copied.value = !copyFailed.value
  if (copiedTimer !== null) clearTimeout(copiedTimer)
  copiedTimer = setTimeout(() => {
    copied.value = false
    copyFailed.value = false
  }, 2500)
}

onBeforeUnmount(() => {
  if (copiedTimer !== null) clearTimeout(copiedTimer)
})

const LEVEL_CLASS = { ok: '', warn: 'text-warning', bad: 'text-danger' } as const
</script>

<template>
  <div class="flex flex-col gap-4">
    <form class="flex flex-wrap items-end gap-3" @submit.prevent="start">
      <label class="flex min-w-64 flex-1 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.target') }}</span>
        <input
          v-model="target"
          :class="[FIELD, 'font-mono']"
          type="text"
          spellcheck="false"
          autocomplete="off"
          :placeholder="t('diagnostics.targetPlaceholder')"
          :disabled="diag.mtrRunning"
        />
      </label>
      <label class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.mtr.cycles') }}</span>
        <input
          v-model.number="cycles"
          :class="FIELD"
          type="number"
          min="1"
          max="200"
          :disabled="diag.mtrRunning"
        />
      </label>
      <label class="flex h-9 items-center gap-2 text-sm">
        <input v-model="resolveNames" type="checkbox" :disabled="diag.mtrRunning" />
        {{ t('diagnostics.mtr.resolveNames') }}
      </label>
      <Button v-if="!diag.mtrRunning" type="submit" :disabled="!canStart">
        <Play aria-hidden="true" />{{ t('diagnostics.mtr.start') }}
      </Button>
      <Button v-else type="button" variant="outline" @click="diag.stopMtr()">
        <Square aria-hidden="true" />{{ t('diagnostics.stop') }}
      </Button>
      <Button type="button" variant="outline" :disabled="hops.length === 0" @click="copyReport">
        <Check v-if="copied" class="text-success" aria-hidden="true" />
        <ClipboardCopy v-else aria-hidden="true" />
        {{ copied ? t('diagnostics.mtr.reportCopied') : t('diagnostics.mtr.copyReport') }}
      </Button>
    </form>

    <p v-if="copyFailed" class="text-danger text-sm" role="alert">
      {{ t('diagnostics.mtr.copyFailed') }}
    </p>
    <FailureNote v-if="diag.mtrError" :failure="diag.mtrError" />

    <div v-if="diag.mtrTarget" class="flex flex-col gap-3">
      <p class="text-text-muted flex flex-wrap items-center gap-2 text-sm">
        <span class="text-text font-mono">{{ diag.mtrTarget }}</span>
        <template v-if="diag.mtrResolved && diag.mtrResolved !== diag.mtrTarget">
          <span>→</span><IpCell :addr="diag.mtrResolved" />
        </template>
        <span v-if="diag.mtrSnapshot" role="status">
          ·
          {{
            diag.mtrRunning
              ? t('diagnostics.mtr.progress', {
                  cycle: diag.mtrSnapshot.cycle,
                  total: diag.mtrSnapshot.total_cycles,
                })
              : diag.mtrCancelled
                ? t('diagnostics.mtr.stopped')
                : t('diagnostics.mtr.finished')
          }}
        </span>
      </p>

      <div v-if="hops.length > 0" class="border-border overflow-auto rounded-md border">
        <table class="w-full text-sm">
          <thead class="bg-surface-raised text-text-muted text-left">
            <tr>
              <th class="px-3 py-2 font-medium">{{ t('diagnostics.mtr.hop') }}</th>
              <th class="px-3 py-2 font-medium">{{ t('diagnostics.mtr.host') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.loss') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.sent') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.last') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.avg') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.best') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.worst') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.jitter') }}</th>
            </tr>
          </thead>
          <tbody class="divide-border divide-y font-mono">
            <tr v-for="(hop, index) in hops" :key="hop.ttl">
              <td class="text-text-muted px-3 py-1.5">{{ hop.ttl }}</td>
              <td class="px-3 py-1.5">
                <span v-if="hop.addr" class="flex flex-wrap items-center gap-x-2">
                  <span v-if="hop.name" class="font-sans">{{ hop.name }}</span>
                  <IpCell :addr="hop.addr" />
                  <span
                    v-if="hop.other_addrs.length > 0"
                    class="text-text-muted font-sans text-xs"
                    :title="hop.other_addrs.join(', ')"
                  >
                    {{ t('diagnostics.mtr.otherRouters', { count: hop.other_addrs.length }) }}
                  </span>
                </span>
                <span v-else class="text-text-muted">{{ t('diagnostics.mtr.noReply') }}</span>
              </td>
              <td
                class="px-3 py-1.5 text-right"
                :class="LEVEL_CLASS[lossLevel(hop.loss_percent)]"
                :title="
                  isIcmpRateLimited(hops, index) ? t('diagnostics.mtr.rateLimitedTip') : undefined
                "
              >
                {{ formatLoss(hop.loss_percent) }}
                <span v-if="isIcmpRateLimited(hops, index)" class="font-sans text-xs">*</span>
              </td>
              <td class="px-3 py-1.5 text-right">{{ hop.sent }}</td>
              <td class="px-3 py-1.5 text-right">{{ formatMs(hop.rtt?.last_ms) }}</td>
              <td class="px-3 py-1.5 text-right">{{ formatMs(hop.rtt?.avg_ms) }}</td>
              <td class="px-3 py-1.5 text-right">{{ formatMs(hop.rtt?.min_ms) }}</td>
              <td class="px-3 py-1.5 text-right">{{ formatMs(hop.rtt?.max_ms) }}</td>
              <td class="px-3 py-1.5 text-right">{{ formatMs(hop.rtt?.jitter_ms) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="hops.some((_, i) => isIcmpRateLimited(hops, i))" class="text-text-muted text-xs">
        * {{ t('diagnostics.mtr.rateLimitedNote') }}
      </p>
    </div>
    <p v-else class="text-text-muted text-sm">{{ t('diagnostics.mtr.hint') }}</p>
  </div>
</template>

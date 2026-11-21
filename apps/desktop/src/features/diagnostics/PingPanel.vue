<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
import { Play, Square } from '@/components/pw/icons'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import IpCell from '@/components/pw/IpCell.vue'
import { useDiagStore } from '@/stores/diag'
import { formatLoss, formatMs } from './diagFormat'
import { FIELD } from './fieldClass'
import FailureNote from './FailureNote.vue'

const { t } = useI18n()
const diag = useDiagStore()

const target = ref('')
const count = ref(10)

const canStart = computed(() => target.value.trim() !== '' && !diag.pingRunning)
const loss = computed(() =>
  diag.pingSent > 0 ? ((diag.pingSent - diag.pingReceived) / diag.pingSent) * 100 : 0,
)
// The newest reply first, so the latest result is always visible without scrolling.
const replies = computed(() => diag.pingReplies.slice().reverse())

function start(): void {
  if (!canStart.value) return
  void diag.runPing(target.value.trim(), Math.min(100, Math.max(1, Math.floor(count.value) || 1)))
}
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
          :disabled="diag.pingRunning"
        />
      </label>
      <label class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.ping.count') }}</span>
        <input
          v-model.number="count"
          :class="FIELD"
          type="number"
          min="1"
          max="100"
          :disabled="diag.pingRunning"
        />
      </label>
      <Button v-if="!diag.pingRunning" type="submit" :disabled="!canStart">
        <Play aria-hidden="true" />{{ t('diagnostics.ping.start') }}
      </Button>
      <Button v-else type="button" variant="outline" @click="diag.stopPing()">
        <Square aria-hidden="true" />{{ t('diagnostics.stop') }}
      </Button>
    </form>

    <FailureNote v-if="diag.pingError" :failure="diag.pingError" />

    <div v-if="diag.pingTarget" class="flex flex-col gap-3">
      <p class="text-text-muted flex flex-wrap items-center gap-2 text-sm">
        <span>{{ t('diagnostics.ping.pinging') }}</span>
        <span class="text-text font-mono">{{ diag.pingTarget }}</span>
        <template v-if="diag.pingResolved && diag.pingResolved !== diag.pingTarget">
          <span>→</span><IpCell :addr="diag.pingResolved" />
        </template>
      </p>

      <dl class="grid grid-cols-2 gap-3 text-sm sm:grid-cols-5">
        <div>
          <dt class="text-text-muted">{{ t('diagnostics.ping.sent') }}</dt>
          <dd class="font-mono">{{ diag.pingSent }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('diagnostics.ping.received') }}</dt>
          <dd class="font-mono">{{ diag.pingReceived }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('diagnostics.loss') }}</dt>
          <dd class="font-mono">{{ formatLoss(loss) }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('diagnostics.ping.avg') }}</dt>
          <dd class="font-mono">{{ formatMs(diag.pingSummary?.rtt?.avg_ms) }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('diagnostics.ping.jitter') }}</dt>
          <dd class="font-mono">{{ formatMs(diag.pingSummary?.rtt?.jitter_ms) }}</dd>
        </div>
      </dl>

      <p v-if="diag.pingSummary" class="text-text-muted text-sm" role="status">
        {{
          diag.pingSummary.cancelled
            ? t('diagnostics.ping.stopped')
            : t('diagnostics.ping.finished')
        }}
        <template v-if="diag.pingSummary.rtt">
          · {{ t('diagnostics.ping.range') }} {{ formatMs(diag.pingSummary.rtt.min_ms) }} –
          {{ formatMs(diag.pingSummary.rtt.max_ms) }}
        </template>
      </p>

      <ul
        class="bg-surface-2 max-h-72 divide-y overflow-auto rounded-[12px] font-mono text-sm"
        :aria-label="t('diagnostics.ping.replies')"
      >
        <li
          v-for="reply in replies"
          :key="reply.seq"
          class="flex items-center gap-4 px-3 py-1"
          :class="reply.outcome === 'success' ? '' : 'text-danger'"
        >
          <span class="text-text-muted w-10">#{{ reply.seq }}</span>
          <template v-if="reply.outcome === 'success'">
            <span class="w-24">{{ formatMs(reply.rtt_ms) }}</span>
            <span class="text-text-muted">{{ reply.from }}</span>
            <span class="text-text-muted">TTL {{ reply.ttl }}</span>
          </template>
          <span v-else>{{ t(`diagnostics.outcome.${reply.outcome}`) }}</span>
        </li>
      </ul>
    </div>
    <p v-else class="text-text-muted text-sm">{{ t('diagnostics.ping.hint') }}</p>
  </div>
</template>

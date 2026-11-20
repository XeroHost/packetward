<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// The inbox reads like a timeline: when and how bad on the left, what happened on the right. The
// severity is a coloured rail *and* a word, never colour alone. Crimson is kept for what is going
// on right now at high or critical severity.
import { Motion } from 'motion-v'
import { computed, onMounted, onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { BellOff, Trash2 } from '@/components/pw/icons'
import IpCell from '@/components/pw/IpCell.vue'
import SegmentedControl from '@/components/pw/SegmentedControl.vue'
import { Button } from '@/components/ui/button'
import { formatBitrate } from '@/lib/format'
import { LIST_STAGGER, springPage } from '@/lib/motion'
import { useAlertsStore } from '@/stores/alerts'
import { useLiveStore } from '@/stores/live'
import type { AlertSeverity } from '@/types/generated/AlertSeverity'
import type { AlertView } from '@/types/generated/AlertView'

const { t } = useI18n()
const alerts = useAlertsStore()
const live = useLiveStore()

const filter = ref<'all' | 'ongoing'>('all')
const shown = computed(() => (filter.value === 'ongoing' ? alerts.ongoing : alerts.items))
const options = computed(() => [
  { value: 'all' as const, label: t('alerts.all', { count: alerts.items.length }) },
  { value: 'ongoing' as const, label: t('alerts.ongoing', { count: alerts.ongoing.length }) },
])

/** Rail colour and label colour per severity. */
const RAIL: Record<AlertSeverity, string> = {
  low: 'bg-text-muted/40',
  medium: 'bg-warning',
  high: 'bg-danger',
  critical: 'bg-danger',
}
const WORD: Record<AlertSeverity, string> = {
  low: 'text-text-muted',
  medium: 'text-warning',
  high: 'text-brand-fg',
  critical: 'text-brand-fg',
}

function when(ms: number): string {
  return new Date(ms).toLocaleString()
}

function duration(alert: AlertView): string {
  const secs = Math.max(0, Math.round((alert.last_seen_unix_ms - alert.first_seen_unix_ms) / 1000))
  return secs < 60 ? `${secs} s` : `${Math.floor(secs / 60)} min ${secs % 60} s`
}

/** Metric keys carry their unit: `_permille` is shown as a percentage, `_bytes` as MB. */
function metric(key: string, value: number): string {
  if (key.endsWith('_permille')) return `${(value / 10).toFixed(1)}%`
  if (key === 'bytes' || key.endsWith('_bytes')) return `${(value / 1_000_000).toFixed(1)} MB`
  if (key.endsWith('_bps')) return formatBitrate(value)
  if (key.endsWith('_secs')) return `${value} s`
  return String(value)
}

function metricLabel(key: string): string {
  const k = `alerts.metrics.${key}`
  return t(k) === k ? key.replaceAll('_', ' ') : t(k)
}

onMounted(() => {
  void alerts.load().then(() => alerts.markSeen())
})
// Anything that arrives while the page is open has been seen.
onBeforeUnmount(() => alerts.markSeen())
</script>

<template>
  <section class="flex max-w-[60rem] flex-col gap-8">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <SegmentedControl v-model="filter" :options="options" :label="t('alerts.filter')" />
      <Button size="sm" variant="outline" @click="alerts.clearEnded()">
        <Trash2 aria-hidden="true" />{{ t('alerts.clearEnded') }}
      </Button>
    </div>

    <p v-if="alerts.failed" class="pw-note" data-tone="danger" role="alert">
      {{ t('alerts.failed') }}
    </p>

    <ul v-if="shown.length > 0" class="flex flex-col">
      <Motion
        v-for="(alert, index) in shown"
        :key="alert.id"
        as="li"
        :initial="{ opacity: 0, y: 8 }"
        :animate="{
          opacity: 1,
          y: 0,
          transition: { ...springPage, delay: Math.min(index, 12) * LIST_STAGGER },
        }"
        class="border-hairline grid grid-cols-[9.5rem_minmax(0,1fr)] gap-x-6 border-t py-5 first:border-t-0 first:pt-0"
      >
        <div class="flex gap-3">
          <span
            class="mt-0.5 w-[3px] shrink-0 self-stretch rounded-full"
            :class="RAIL[alert.severity]"
            aria-hidden="true"
          />
          <div class="flex flex-col gap-1">
            <span
              class="text-xs font-semibold tracking-wide uppercase"
              :class="WORD[alert.severity]"
            >
              {{ t(`alerts.severity.${alert.severity}`) }}
            </span>
            <span class="text-text-muted text-xs leading-snug">{{
              when(alert.first_seen_unix_ms)
            }}</span>
            <span v-if="alert.phase !== 'ended'" class="text-brand-fg mt-1 text-xs font-medium">
              {{ t('alerts.ongoingBadge') }}
            </span>
          </div>
        </div>

        <div class="flex min-w-0 flex-col gap-2">
          <div class="flex flex-wrap items-baseline gap-x-3">
            <h2 class="text-[1.0625rem] font-semibold">
              {{ t(`alerts.summary.${alert.summary_key}`) }}
            </h2>
            <span v-if="alert.protected" class="text-success text-xs">{{
              t('alerts.protected')
            }}</span>
          </div>
          <p class="text-text-muted max-w-prose text-[13px] leading-relaxed">
            {{ t(`alerts.explain.${alert.summary_key}`) }}
          </p>
          <div class="flex flex-wrap items-center gap-x-6 gap-y-1 pt-1 text-[13px]">
            <span class="flex items-center gap-2">
              <span class="text-text-muted">{{ t('alerts.source') }}</span>
              <IpCell
                v-if="alert.source"
                :addr="alert.source"
                :rdp="live.rdpPeers.has(alert.source)"
                :trusted="live.rdpTrusted.has(alert.source)"
              />
              <span v-else>{{ t('alerts.distributed') }}</span>
            </span>
            <span v-for="m in alert.metrics" :key="m.key" class="flex gap-1.5">
              <span class="text-text-muted">{{ metricLabel(m.key) }}</span>
              <span class="font-mono">{{ metric(m.key, m.value) }}</span>
            </span>
            <span class="text-text-muted">{{
              t('alerts.duration', { time: duration(alert) })
            }}</span>
          </div>
        </div>
      </Motion>
    </ul>
    <div v-else class="text-text-muted flex items-center gap-3 py-6">
      <BellOff class="size-6" aria-hidden="true" />
      <p>{{ filter === 'ongoing' ? t('alerts.noneOngoing') : t('alerts.none') }}</p>
    </div>
  </section>
</template>

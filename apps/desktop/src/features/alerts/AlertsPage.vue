<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { BellOff, Trash2 } from 'lucide-vue-next'
import { computed, onMounted, onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import IpCell from '@/components/pw/IpCell.vue'
import { formatBitrate } from '@/lib/format'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useAlertsStore } from '@/stores/alerts'
import { useLiveStore } from '@/stores/live'
import type { AlertSeverity } from '@/types/generated/AlertSeverity'
import type { AlertView } from '@/types/generated/AlertView'

const { t } = useI18n()
const alerts = useAlertsStore()
const live = useLiveStore()

const filter = ref<'all' | 'ongoing'>('all')
const shown = computed(() => (filter.value === 'ongoing' ? alerts.ongoing : alerts.items))

const TONE: Record<AlertSeverity, string> = {
  low: 'border-border text-text-muted',
  medium: 'border-warning/50 text-warning',
  high: 'border-danger/50 text-danger',
  critical: 'border-danger bg-danger/15 text-danger',
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
  <section class="flex flex-col gap-4">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div role="group" :aria-label="t('alerts.filter')" class="flex gap-1">
        <Button
          size="sm"
          :variant="filter === 'all' ? 'default' : 'outline'"
          @click="filter = 'all'"
        >
          {{ t('alerts.all', { count: alerts.items.length }) }}
        </Button>
        <Button
          size="sm"
          :variant="filter === 'ongoing' ? 'default' : 'outline'"
          @click="filter = 'ongoing'"
        >
          {{ t('alerts.ongoing', { count: alerts.ongoing.length }) }}
        </Button>
      </div>
      <Button size="sm" variant="outline" @click="alerts.clearEnded()">
        <Trash2 aria-hidden="true" />{{ t('alerts.clearEnded') }}
      </Button>
    </div>

    <p v-if="alerts.failed" class="text-danger text-sm" role="alert">{{ t('alerts.failed') }}</p>

    <ul v-if="shown.length > 0" class="flex flex-col gap-2">
      <li
        v-for="alert in shown"
        :key="alert.id"
        class="bg-surface border-border flex flex-col gap-2 rounded-lg border p-[var(--card-p)]"
        style="box-shadow: var(--shadow-card)"
      >
        <div class="flex flex-wrap items-center gap-2">
          <Badge variant="outline" :class="TONE[alert.severity]">
            {{ t(`alerts.severity.${alert.severity}`) }}
          </Badge>
          <span class="font-medium">{{ t(`alerts.summary.${alert.summary_key}`) }}</span>
          <Badge
            v-if="alert.phase !== 'ended'"
            variant="outline"
            class="border-brand-fg/50 text-brand-fg"
          >
            {{ t('alerts.ongoingBadge') }}
          </Badge>
          <Badge v-if="alert.protected" variant="outline" class="border-success/50 text-success">
            {{ t('alerts.protected') }}
          </Badge>
          <span class="text-text-muted ml-auto text-xs">{{ when(alert.first_seen_unix_ms) }}</span>
        </div>
        <p class="text-text-muted text-sm">{{ t(`alerts.explain.${alert.summary_key}`) }}</p>
        <div class="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
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
          <span class="text-text-muted">{{ t('alerts.duration', { time: duration(alert) }) }}</span>
        </div>
      </li>
    </ul>
    <div
      v-else
      class="bg-surface border-border text-text-muted flex items-center gap-3 rounded-lg border p-[var(--card-p)]"
    >
      <BellOff class="size-5" aria-hidden="true" />
      <p>{{ filter === 'ongoing' ? t('alerts.noneOngoing') : t('alerts.none') }}</p>
    </div>
  </section>
</template>

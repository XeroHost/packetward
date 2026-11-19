<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { use, type EChartsCoreOption } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { ArrowDown, ArrowUp, PackageX, TriangleAlert } from 'lucide-vue-next'
import { computed, onMounted, shallowRef, watch } from 'vue'
import VChart from 'vue-echarts'
import { useI18n } from 'vue-i18n'
import IpCell from '@/components/pw/IpCell.vue'
import StatTile from '@/components/pw/StatTile.vue'
import { buildChartOption, readChartColors } from '@/features/dashboard/chartOption'
import { formatBitrate, formatRate } from '@/lib/format'
import { useAppVisible } from '@/lib/visibility'
import { useAppearanceStore } from '@/stores/appearance'
import { useCaptureStore } from '@/stores/capture'
import { useLiveStore } from '@/stores/live'

use([LineChart, GridComponent, TooltipComponent, CanvasRenderer])

const { t } = useI18n()
const capture = useCaptureStore()
const live = useLiveStore()
const appearance = useAppearanceStore()
const visible = useAppVisible()

const sample = computed(() => capture.live)
const running = computed(() => capture.status?.state === 'running')
const blind = computed(() => capture.status?.blind === true || sample.value?.blind === true)
const rdpPeers = computed(() => live.rdpPeers)
const rdpTrusted = computed(() => live.rdpTrusted)

const option = shallowRef<EChartsCoreOption>({})
function refresh(): void {
  const h = capture.history
  option.value = buildChartOption(
    { t: h.t, inBps: h.inBps, outBps: h.outBps },
    { inbound: t('dashboard.chart.inbound'), outbound: t('dashboard.chart.outbound') },
    readChartColors(),
  )
}
// Redrawn once per sample and only while the window can be seen (nothing to draw in the tray).
watch(
  () => capture.tick,
  () => {
    if (visible.value) refresh()
  },
  { immediate: true },
)
watch(visible, (shown) => {
  if (shown) refresh()
})
watch(
  () => [appearance.resolvedTheme, t('dashboard.chart.inbound')],
  () => queueMicrotask(refresh),
)

onMounted(() => void capture.refresh())

const PROTO_ORDER = ['tcp', 'udp', 'icmp', 'other'] as const
const protocols = computed(() =>
  PROTO_ORDER.map((name) => ({
    name,
    rate: sample.value?.protocols.find((p) => p.proto === name) ?? { pps: 0, bps: 0 },
  })),
)

const card = 'bg-surface border-border flex flex-col gap-3 rounded-lg border p-[var(--card-p)]'
</script>

<template>
  <section class="flex flex-col gap-4">
    <p
      v-if="blind"
      class="border-warning/40 bg-warning/10 flex items-start gap-2 rounded-md border p-3 text-sm"
      role="alert"
    >
      <TriangleAlert class="text-warning mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{{ t('traffic.blind') }}</span>
    </p>

    <p
      v-if="!running"
      class="bg-surface border-border text-text-muted rounded-md border p-3 text-sm"
    >
      {{ capture.status?.error ?? capture.status?.selection.summary ?? t('traffic.notRunning') }}
      <RouterLink to="/capture" class="text-brand-fg underline">{{
        t('traffic.openCapture')
      }}</RouterLink>
    </p>

    <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <StatTile
        :label="t('traffic.tiles.inbound')"
        :value="sample ? formatBitrate(sample.inbound.bps) : '—'"
        :hint="sample ? t('traffic.pps', { rate: formatRate(sample.inbound.pps) }) : undefined"
        :icon="ArrowDown"
        tone="inbound"
      />
      <StatTile
        :label="t('traffic.tiles.outbound')"
        :value="sample ? formatBitrate(sample.outbound.bps) : '—'"
        :hint="sample ? t('traffic.pps', { rate: formatRate(sample.outbound.pps) }) : undefined"
        :icon="ArrowUp"
        tone="outbound"
      />
      <StatTile
        :label="t('traffic.tiles.dropped')"
        :value="String(sample?.dropped ?? capture.status?.counters.dropped ?? 0)"
        :hint="t('traffic.droppedHint')"
        :icon="PackageX"
        :tone="(sample?.dropped ?? 0) > 0 ? 'warning' : 'neutral'"
      />
      <StatTile
        :label="t('traffic.tiles.untracked')"
        :value="String(sample?.untracked_packets ?? 0)"
        :hint="t('traffic.untrackedHint')"
        tone="neutral"
      />
    </div>

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <h2 class="text-base">{{ t('traffic.chartTitle') }}</h2>
      <div class="relative h-64 w-full">
        <VChart
          class="h-full w-full"
          :option="option"
          autoresize
          role="img"
          :aria-label="t('traffic.chartTitle')"
        />
        <p
          v-if="!sample"
          class="text-text-muted absolute inset-0 flex items-center justify-center text-sm"
        >
          {{ t('dashboard.chart.empty') }}
        </p>
      </div>
    </div>

    <div class="grid gap-4 lg:grid-cols-2">
      <div :class="card" style="box-shadow: var(--shadow-card)">
        <h2 class="text-base">{{ t('traffic.protocols') }}</h2>
        <table class="w-full text-sm">
          <thead class="text-text-muted text-left">
            <tr>
              <th class="py-1 font-medium">{{ t('connections.columns.proto') }}</th>
              <th class="py-1 text-right font-medium">{{ t('traffic.rate') }}</th>
              <th class="py-1 text-right font-medium">{{ t('traffic.packets') }}</th>
            </tr>
          </thead>
          <tbody class="divide-border divide-y font-mono">
            <tr v-for="row in protocols" :key="row.name">
              <td class="py-1.5 uppercase">{{ row.name }}</td>
              <td class="py-1.5 text-right">{{ formatBitrate(row.rate.bps) }}</td>
              <td class="py-1.5 text-right">{{ formatRate(row.rate.pps) }}/s</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div :class="card" style="box-shadow: var(--shadow-card)">
        <h2 class="text-base">{{ t('traffic.talkers') }}</h2>
        <p class="text-text-muted text-xs">{{ t('traffic.talkersHint') }}</p>
        <table v-if="sample && sample.top_talkers.length > 0" class="w-full text-sm">
          <thead class="text-text-muted text-left">
            <tr>
              <th class="py-1 font-medium">{{ t('traffic.source') }}</th>
              <th class="py-1 text-right font-medium">{{ t('traffic.packets') }}</th>
              <th class="py-1 text-right font-medium">{{ t('traffic.bytes') }}</th>
              <th class="py-1 text-right font-medium">TCP / UDP / ICMP</th>
            </tr>
          </thead>
          <tbody class="divide-border divide-y font-mono">
            <tr v-for="talker in sample.top_talkers" :key="talker.addr">
              <td class="py-1.5">
                <IpCell
                  :addr="talker.addr"
                  :rdp="rdpPeers.has(talker.addr)"
                  :trusted="rdpTrusted.has(talker.addr)"
                />
              </td>
              <td class="py-1.5 text-right">{{ talker.packets }}</td>
              <td class="py-1.5 text-right">{{ talker.bytes }}</td>
              <td class="text-text-muted py-1.5 text-right">
                {{ talker.tcp_packets }} / {{ talker.udp_packets }} / {{ talker.icmp_packets }}
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="text-text-muted text-sm">{{ t('traffic.noTalkers') }}</p>
      </div>
    </div>
  </section>
</template>

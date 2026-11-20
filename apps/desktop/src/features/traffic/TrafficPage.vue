<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// Live capture, as a console: a readout line, one wide chart, the protocol mix as a single bar,
// and the loudest sources as rows with a share bar. Nothing here is a card.
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { use, type EChartsCoreOption } from 'echarts/core'
import { LegacyGridContainLabel } from 'echarts/features'
import { CanvasRenderer } from 'echarts/renderers'
import { computed, onMounted, shallowRef, watch } from 'vue'
import VChart from 'vue-echarts'
import { useI18n } from 'vue-i18n'
import CountingValue from '@/components/pw/CountingValue.vue'
import { TriangleAlert } from '@/components/pw/icons'
import IpCell from '@/components/pw/IpCell.vue'
import { buildChartOption, readChartColors } from '@/features/dashboard/chartOption'
import { formatBitrate, formatRate } from '@/lib/format'
import { useAppVisible } from '@/lib/visibility'
import { useAppearanceStore } from '@/stores/appearance'
import { useCaptureStore } from '@/stores/capture'
import { useLiveStore } from '@/stores/live'

use([LineChart, GridComponent, TooltipComponent, LegacyGridContainLabel, CanvasRenderer])

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
const PROTO_COLOR = {
  tcp: 'bg-chart-tcp',
  udp: 'bg-chart-udp',
  icmp: 'bg-chart-icmp',
  other: 'bg-chart-other',
} as const
const totalBps = computed(() =>
  Math.max(
    1,
    protocols.value.reduce((sum, p) => sum + p.rate.bps, 0),
  ),
)
const whole = (n: number): string => String(Math.round(n))
const mostPackets = computed(() =>
  Math.max(1, ...(sample.value?.top_talkers ?? []).map((x) => x.packets)),
)
const sectionTitle = 'text-[0.95rem] font-semibold'
</script>

<template>
  <section class="flex max-w-[72rem] flex-col gap-(--section-gap)">
    <p v-if="blind" class="pw-note" data-tone="warning" role="alert">
      <TriangleAlert class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{{ t('traffic.blind') }}</span>
    </p>

    <p v-if="!running" class="pw-note" data-tone="info">
      <span>
        {{ capture.status?.error ?? capture.status?.selection.summary ?? t('traffic.notRunning') }}
        <RouterLink to="/capture" class="text-brand-fg underline underline-offset-4">{{
          t('traffic.openCapture')
        }}</RouterLink>
      </span>
    </p>

    <!-- Readout: four numbers on one line, separated by hairlines -->
    <dl class="border-hairline grid grid-cols-2 gap-y-6 border-b pb-8 lg:grid-cols-4">
      <div class="pr-6">
        <dt class="text-text-muted flex items-center gap-2 text-xs">
          <span class="bg-chart-in inline-block size-2 rounded-full" aria-hidden="true" />
          {{ t('traffic.tiles.inbound') }}
        </dt>
        <dd
          class="font-heading mt-1 text-[2rem] leading-none font-semibold"
          data-testid="tile-value"
        >
          <CountingValue
            v-if="sample"
            :value="sample.inbound.bps"
            :format="formatBitrate"
            unit-class="text-text-muted text-base font-medium"
          />
          <template v-else>—</template>
        </dd>
        <dd v-if="sample" class="text-text-muted mt-1.5 text-xs">
          {{ t('traffic.pps', { rate: formatRate(sample.inbound.pps) }) }}
        </dd>
      </div>
      <div class="border-hairline border-l pr-6 pl-6">
        <dt class="text-text-muted flex items-center gap-2 text-xs">
          <span class="bg-chart-out inline-block size-2 rounded-full" aria-hidden="true" />
          {{ t('traffic.tiles.outbound') }}
        </dt>
        <dd
          class="font-heading mt-1 text-[2rem] leading-none font-semibold"
          data-testid="tile-value"
        >
          <CountingValue
            v-if="sample"
            :value="sample.outbound.bps"
            :format="formatBitrate"
            unit-class="text-text-muted text-base font-medium"
          />
          <template v-else>—</template>
        </dd>
        <dd v-if="sample" class="text-text-muted mt-1.5 text-xs">
          {{ t('traffic.pps', { rate: formatRate(sample.outbound.pps) }) }}
        </dd>
      </div>
      <div class="border-hairline border-l pr-6 pl-6 max-lg:!border-l-0 max-lg:!pl-0">
        <dt class="text-text-muted text-xs">{{ t('traffic.tiles.dropped') }}</dt>
        <dd
          class="font-heading mt-1 text-[2rem] leading-none font-semibold"
          :class="(sample?.dropped ?? 0) > 0 && 'text-warning'"
          data-testid="tile-value"
        >
          <CountingValue
            :value="sample?.dropped ?? capture.status?.counters.dropped ?? 0"
            :format="whole"
          />
        </dd>
        <dd class="text-text-muted mt-1.5 text-xs">{{ t('traffic.droppedHint') }}</dd>
      </div>
      <div class="border-hairline border-l pl-6">
        <dt class="text-text-muted text-xs">{{ t('traffic.tiles.untracked') }}</dt>
        <dd
          class="font-heading mt-1 text-[2rem] leading-none font-semibold"
          data-testid="tile-value"
        >
          <CountingValue :value="sample?.untracked_packets ?? 0" :format="whole" />
        </dd>
        <dd class="text-text-muted mt-1.5 text-xs">{{ t('traffic.untrackedHint') }}</dd>
      </div>
    </dl>

    <div>
      <h2 :class="sectionTitle">{{ t('traffic.chartTitle') }}</h2>
      <div class="relative mt-3 h-64 w-full">
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

    <!-- Protocol mix: one bar, a legend that carries the numbers -->
    <div>
      <h2 :class="sectionTitle">{{ t('traffic.protocols') }}</h2>
      <div
        class="bg-hairline mt-4 flex h-2 w-full overflow-hidden rounded-full"
        role="img"
        :aria-label="t('traffic.protocols')"
      >
        <div
          v-for="row in protocols"
          :key="row.name"
          class="h-full transition-[width] duration-500"
          :class="PROTO_COLOR[row.name]"
          :style="{ width: `${(row.rate.bps / totalBps) * 100}%` }"
        />
      </div>
      <table class="pw-rows mt-5 font-mono">
        <thead class="font-sans">
          <tr>
            <th>{{ t('connections.columns.proto') }}</th>
            <th class="!text-right">{{ t('traffic.rate') }}</th>
            <th class="!text-right">{{ t('traffic.packets') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in protocols" :key="row.name">
            <td>
              <span class="flex items-center gap-2 uppercase">
                <span
                  class="inline-block size-2 rounded-full"
                  :class="PROTO_COLOR[row.name]"
                  aria-hidden="true"
                />
                {{ row.name }}
              </span>
            </td>
            <td class="text-right">{{ formatBitrate(row.rate.bps) }}</td>
            <td class="text-right">{{ formatRate(row.rate.pps) }}/s</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div>
      <h2 :class="sectionTitle">{{ t('traffic.talkers') }}</h2>
      <p class="text-text-muted mt-0.5 text-xs">{{ t('traffic.talkersHint') }}</p>
      <table v-if="sample && sample.top_talkers.length > 0" class="pw-rows mt-4">
        <thead>
          <tr>
            <th>{{ t('traffic.source') }}</th>
            <th class="!text-right">{{ t('traffic.packets') }}</th>
            <th class="!text-right">{{ t('traffic.bytes') }}</th>
            <th class="!text-right">TCP / UDP / ICMP</th>
          </tr>
        </thead>
        <tbody class="font-mono">
          <tr v-for="talker in sample.top_talkers" :key="talker.addr">
            <td>
              <IpCell
                :addr="talker.addr"
                :rdp="rdpPeers.has(talker.addr)"
                :trusted="rdpTrusted.has(talker.addr)"
              />
              <div
                class="bg-hairline mt-1 h-0.5 w-40 overflow-hidden rounded-full"
                aria-hidden="true"
              >
                <div
                  class="bg-chart-in h-full rounded-full opacity-60"
                  :style="{ width: `${(talker.packets / mostPackets) * 100}%` }"
                />
              </div>
            </td>
            <td class="text-right">{{ talker.packets }}</td>
            <td class="text-right">{{ talker.bytes }}</td>
            <td class="text-text-muted text-right">
              {{ talker.tcp_packets }} / {{ talker.udp_packets }} / {{ talker.icmp_packets }}
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="text-text-muted mt-4 text-sm">{{ t('traffic.noTalkers') }}</p>
    </div>
  </section>
</template>

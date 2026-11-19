<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { use, type EChartsCoreOption } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { computed, shallowRef, watch } from 'vue'
import VChart from 'vue-echarts'
import { useI18n } from 'vue-i18n'
import { formatBitrate } from '@/lib/format'
import { useAppVisible } from '@/lib/visibility'
import { useAppearanceStore } from '@/stores/appearance'
import { useLiveStore } from '@/stores/live'
import { buildChartOption, readChartColors } from './chartOption'

// Tree-shaken: only what the traffic chart uses.
use([LineChart, GridComponent, TooltipComponent, CanvasRenderer])

const { t } = useI18n()
const live = useLiveStore()
const appearance = useAppearanceStore()
const visible = useAppVisible()

const option = shallowRef<EChartsCoreOption>({})

function refresh(): void {
  option.value = buildChartOption(
    live.history(),
    { inbound: t('dashboard.chart.inbound'), outbound: t('dashboard.chart.outbound') },
    readChartColors(),
  )
}

// Rebuilt once per sample, and only while the window can actually be seen: a hidden window
// (minimized to the tray) must not spend CPU drawing a chart nobody looks at.
watch(
  () => live.tick,
  () => {
    if (visible.value) refresh()
  },
  { immediate: true },
)
watch(visible, (isVisible) => {
  if (isVisible) refresh()
})
// A theme or language change re-reads the colours and labels (after the attributes are applied).
watch(
  () => [appearance.resolvedTheme, t('dashboard.chart.inbound')],
  () => queueMicrotask(refresh),
)

const summary = computed(() => {
  const totals = live.stats?.totals
  if (!totals) return t('dashboard.chart.empty')
  return t('dashboard.chart.summary', {
    inbound: formatBitrate(totals.in_bps),
    outbound: formatBitrate(totals.out_bps),
  })
})
</script>

<template>
  <div class="relative h-64 w-full">
    <VChart class="h-full w-full" :option="option" autoresize role="img" :aria-label="summary" />
    <p
      v-if="!live.stats"
      class="text-text-muted absolute inset-0 flex items-center justify-center text-sm"
    >
      {{ t('dashboard.chart.empty') }}
    </p>
  </div>
</template>

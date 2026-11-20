<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// Where the attackers are: a world map with the countries shaded by how many addresses are behind
// alerts and blocks, and the top countries beside it. Placement is local (the GeoIP database).
import { useIntervalFn } from '@vueuse/core'
import { MapChart } from 'echarts/charts'
import { GeoComponent, TooltipComponent } from 'echarts/components'
import { registerMap, use, type EChartsCoreOption } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { computed, onMounted, shallowRef, useTemplateRef, watch } from 'vue'
import VChart from 'vue-echarts'
import { useI18n } from 'vue-i18n'
import Flag from '@/components/pw/Flag.vue'
import HIcon from '@/components/pw/HIcon.vue'
import { Button } from '@/components/ui/button'
import { countryName } from '@/lib/countries'
import { Add01Icon, MinusSignIcon, Refresh01Icon } from '@/lib/icons'
import { useAppVisible } from '@/lib/visibility'
import { useAlertsStore } from '@/stores/alerts'
import { useAppearanceStore } from '@/stores/appearance'
import { useDefenseStore } from '@/stores/defense'
import { useGeoStore } from '@/stores/geo'
import { useIntelStore } from '@/stores/intel'
import { attackerAddresses, summarizeAttackers } from './attackers'
import { buildMapOption, DEFAULT_VIEW, readMapColors, type MapView } from './mapOption'
import { loadWorld } from './worldMap'

use([MapChart, GeoComponent, TooltipComponent, CanvasRenderer])

const { t, locale } = useI18n()
const alerts = useAlertsStore()
const defense = useDefenseStore()
const geo = useGeoStore()
const intel = useIntelStore()
const appearance = useAppearanceStore()
const visible = useAppVisible()

const worldReady = shallowRef(false)
const worldFailed = shallowRef(false)
const option = shallowRef<EChartsCoreOption>({})

onMounted(async () => {
  void alerts.load()
  void defense.loadBlocks()
  try {
    registerMap('world', (await loadWorld()) as never)
    worldReady.value = true
  } catch {
    worldFailed.value = true
  }
})
// Blocks are not pushed by the agent: look again while the page is open.
const { pause, resume } = useIntervalFn(() => void defense.loadBlocks(), 10_000, {
  immediate: false,
})
watch(
  visible,
  (shown) => {
    if (shown) resume()
    else pause()
  },
  { immediate: true },
)

const addresses = computed(() => attackerAddresses(alerts.items, defense.blocks))
// Asking is idempotent and batched; the answers land in the store and re-render this.
watch(addresses, (list) => geo.warm(list), { immediate: true })

const rows = computed(() =>
  summarizeAttackers(alerts.items, defense.blocks, (addr) => geo.place(addr)),
)
const top = computed(() => rows.value.slice(0, 8))
const most = computed(() => Math.max(1, ...rows.value.map((r) => r.addrs)))
const total = computed(() => rows.value.reduce((sum, r) => sum + r.addrs, 0))
const noDatabase = computed(() => geo.ready === false)
const control =
  'bg-surface-2 text-text-muted hover:bg-surface-3 hover:text-text flex size-8 items-center justify-center rounded-[10px] transition-colors'

/** The chart as vue-echarts exposes it (only what the camera controls need). */
interface MapHandle {
  dispatchAction(action: Record<string, unknown>): void
  getWidth(): number
  getHeight(): number
  getOption(): { series?: { zoom?: number; center?: [number, number] }[] } | undefined
  setOption(option: EChartsCoreOption, opts?: { notMerge?: boolean }): void
}
const chart = useTemplateRef<MapHandle>('chart')

/** Where the user left the camera, so new data does not snap the map back. */
let view: MapView = DEFAULT_VIEW

function build(camera: MapView): EChartsCoreOption {
  return buildMapOption(
    rows.value,
    readMapColors(),
    locale.value,
    {
      addresses: (n) => t('intel.map.addresses', { n }),
      alerts: (n) => (n > 0 ? t('intel.map.alerts', { n }) : ''),
      blocked: (n) => (n > 0 ? t('intel.map.blocked', { n }) : ''),
    },
    camera,
  )
}

function refresh(): void {
  option.value = build(view)
}

/** Remembers the zoom and centre after the wheel, a drag or a pinch. */
function onRoam(): void {
  const series = chart.value?.getOption()?.series?.[0]
  if (!series || series.zoom === undefined) return
  view = { zoom: series.zoom, ...(series.center ? { center: series.center } : {}) }
}

function zoomBy(ratio: number): void {
  const handle = chart.value
  if (!handle) return
  // ECharts zooms around a point: the middle of the map.
  handle.dispatchAction({
    type: 'geoRoam',
    componentType: 'series',
    seriesIndex: 0,
    zoom: ratio,
    originX: handle.getWidth() / 2,
    originY: handle.getHeight() / 2,
  })
}

function resetView(): void {
  view = DEFAULT_VIEW
  const fresh = build(view)
  option.value = fresh
  chart.value?.setOption(fresh, { notMerge: true })
}
watch(
  [rows, worldReady, locale, () => appearance.resolvedTheme],
  () => {
    if (worldReady.value && visible.value) queueMicrotask(refresh)
  },
  { immediate: true },
)
watch(visible, (shown) => {
  if (shown && worldReady.value) refresh()
})
</script>

<template>
  <div class="flex flex-col gap-5">
    <div>
      <h2 class="text-[1.0625rem] font-semibold">{{ t('intel.map.title') }}</h2>
      <p class="text-text-muted mt-1 max-w-prose text-[13px] leading-relaxed">
        {{ t('intel.map.hint') }}
      </p>
    </div>

    <p v-if="noDatabase" class="pw-note flex-wrap items-center" data-tone="info">
      <span>{{ t('intel.map.noDb') }}</span>
      <Button size="sm" :disabled="intel.geo?.updating" @click="intel.updateGeo()">
        {{ t('intel.geo.download') }}
      </Button>
    </p>

    <div class="grid gap-x-10 gap-y-6 lg:grid-cols-[minmax(0,1fr)_17rem]">
      <div class="relative h-[22rem] min-w-0">
        <VChart
          v-if="worldReady"
          ref="chart"
          class="h-full w-full"
          :option="option"
          autoresize
          role="img"
          :aria-label="t('intel.map.title')"
          @georoam="onRoam"
        />
        <div
          v-if="worldReady"
          class="absolute top-2 right-2 flex flex-col gap-1"
          role="group"
          :aria-label="t('intel.map.controls')"
        >
          <button
            type="button"
            :class="control"
            :aria-label="t('intel.map.zoomIn')"
            @click="zoomBy(1.5)"
          >
            <HIcon :icon="Add01Icon" :size="16" />
          </button>
          <button
            type="button"
            :class="control"
            :aria-label="t('intel.map.zoomOut')"
            @click="zoomBy(1 / 1.5)"
          >
            <HIcon :icon="MinusSignIcon" :size="16" />
          </button>
          <button
            type="button"
            :class="control"
            :aria-label="t('intel.map.reset')"
            @click="resetView"
          >
            <HIcon :icon="Refresh01Icon" :size="16" />
          </button>
        </div>
        <p
          v-if="worldReady"
          class="text-text-muted pointer-events-none absolute bottom-1 left-1 text-[11px] opacity-70"
        >
          {{ t('intel.map.gestures') }}
        </p>
        <p
          v-else
          class="text-text-muted absolute inset-0 flex items-center justify-center text-sm"
          role="status"
        >
          {{ worldFailed ? t('intel.map.failed') : t('intel.map.loading') }}
        </p>
      </div>

      <div class="flex min-w-0 flex-col gap-3">
        <h3 class="text-[0.9375rem] font-semibold">
          {{ t('intel.map.top') }}
          <span v-if="total > 0" class="text-text-muted ml-1 text-xs font-normal">{{
            t('intel.map.addresses', { n: total })
          }}</span>
        </h3>
        <p v-if="rows.length === 0" class="text-text-muted text-sm">
          {{ noDatabase ? t('intel.map.noDbShort') : t('intel.map.empty') }}
        </p>
        <ol v-else class="flex flex-col gap-2.5" data-testid="attacker-countries">
          <li v-for="row in top" :key="row.code" class="flex flex-col gap-1">
            <div class="flex items-center gap-2 text-[13px]">
              <Flag :code="row.code" :name="countryName(row.code, locale)" />
              <span class="min-w-0 flex-1 truncate">{{ countryName(row.code, locale) }}</span>
              <span class="font-mono text-xs tabular-nums">{{ row.addrs }}</span>
            </div>
            <div class="bg-hairline h-0.5 overflow-hidden rounded-full" aria-hidden="true">
              <div
                class="bg-danger h-full rounded-full opacity-80"
                :style="{ width: `${(row.addrs / most) * 100}%` }"
              />
            </div>
          </li>
        </ol>
      </div>
    </div>
  </div>
</template>

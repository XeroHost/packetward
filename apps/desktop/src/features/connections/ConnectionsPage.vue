<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import {
  createSortedRowModel,
  rowSortingFeature,
  sortFn_alphanumeric,
  sortFn_text,
  tableFeatures,
  useTable,
  type ColumnDef,
} from '@tanstack/vue-table'
import { useVirtualizer } from '@tanstack/vue-virtual'
import { refDebounced, useDocumentVisibility, useIntervalFn } from '@vueuse/core'
import { ArrowDown, ArrowUp, ArrowUpDown, TriangleAlert } from 'lucide-vue-next'
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import IpCell from '@/components/pw/IpCell.vue'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { copyText } from '@/lib/clipboard'
import { useAppearanceStore } from '@/stores/appearance'
import { useLiveStore, type ConnectionRow } from '@/stores/live'
import type { TcpState } from '@/types/generated/TcpState'
import { applyFilters, type ProtoFilter, type StateFilter } from './filters'

const { t } = useI18n()
const live = useLiveStore()
const appearance = useAppearanceStore()
const visibility = useDocumentVisibility()

const POLL_MS = 2000
const TCP_STATES: readonly TcpState[] = [
  'established',
  'listen',
  'syn_sent',
  'syn_received',
  'fin_wait1',
  'fin_wait2',
  'close_wait',
  'closing',
  'last_ack',
  'time_wait',
  'closed',
  'delete_tcb',
]

// ---- filters --------------------------------------------------------------------------------
const proto = ref<ProtoFilter>('all')
const state = ref<StateFilter>('all')
const search = ref('')
const debouncedSearch = refDebounced(search, 150)

const filtered = computed(() =>
  applyFilters(live.rows, {
    proto: proto.value,
    state: state.value,
    search: debouncedSearch.value,
  }),
)

function clearFilters(): void {
  proto.value = 'all'
  state.value = 'all'
  search.value = ''
}
const filtersActive = computed(
  () => proto.value !== 'all' || state.value !== 'all' || search.value.trim() !== '',
)

// ---- table (sorting) ------------------------------------------------------------------------
const features = tableFeatures({
  rowSortingFeature,
  sortedRowModel: createSortedRowModel(),
  sortFns: { alphanumeric: sortFn_alphanumeric, text: sortFn_text },
})

const COLUMN_IDS = ['proto', 'local', 'remote', 'state', 'process', 'pid'] as const
type ColumnId = (typeof COLUMN_IDS)[number]

const endpoint = (addr: string, port: number) => (addr ? `${addr}:${port}` : '')

const columns: ColumnDef<typeof features, ConnectionRow>[] = [
  { id: 'proto', accessorFn: (row) => row.proto, sortFn: 'text' },
  { id: 'local', accessorFn: (row) => endpoint(row.local_addr, row.local_port), sortFn: 'text' },
  { id: 'remote', accessorFn: (row) => endpoint(row.remote_addr, row.remote_port), sortFn: 'text' },
  { id: 'state', accessorFn: (row) => row.state ?? '', sortFn: 'text' },
  { id: 'process', accessorFn: (row) => row.process || `#${row.pid}`, sortFn: 'text' },
  { id: 'pid', accessorFn: (row) => row.pid, sortFn: 'alphanumeric' },
]

const table = useTable({
  features,
  columns,
  data: filtered,
  getRowId: (row: ConnectionRow) => String(row.id),
})

const rows = computed(() => table.getRowModel().rows)

function sortDirection(id: ColumnId): false | 'asc' | 'desc' {
  return table.getColumn(id)?.getIsSorted() ?? false
}

function toggleSort(id: ColumnId, event: Event): void {
  table.getColumn(id)?.getToggleSortingHandler()?.(event)
}

function ariaSort(id: ColumnId): 'ascending' | 'descending' | 'none' {
  const direction = sortDirection(id)
  return direction === 'asc' ? 'ascending' : direction === 'desc' ? 'descending' : 'none'
}

// ---- virtualization -------------------------------------------------------------------------
const scroller = ref<HTMLElement | null>(null)
const FALLBACK_ROW_HEIGHT = 36

/** The row height token (`--row-h`) in pixels: it follows density and the text-size setting. */
function measureRowHeight(): number {
  const probe = document.createElement('div')
  probe.style.cssText = 'position:absolute;visibility:hidden;height:var(--row-h);width:1px'
  document.body.appendChild(probe)
  const height = probe.offsetHeight
  probe.remove()
  return height > 0 ? height : FALLBACK_ROW_HEIGHT
}
const rowHeight = ref(FALLBACK_ROW_HEIGHT)

const virtualizer = useVirtualizer(
  computed(() => ({
    count: rows.value.length,
    getScrollElement: () => scroller.value,
    estimateSize: () => rowHeight.value,
    getItemKey: (index: number) => rows.value[index]?.id ?? index,
    overscan: 12,
  })),
)
const virtualRows = computed(() => virtualizer.value.getVirtualItems())
const totalSize = computed(() => virtualizer.value.getTotalSize())

watch(
  () => [appearance.prefs.density, appearance.prefs.textSize],
  async () => {
    await nextTick()
    rowHeight.value = measureRowHeight()
    virtualizer.value.measure()
  },
)

// ---- polling (only while the window is visible) ----------------------------------------------
const { pause, resume } = useIntervalFn(() => void live.loadConnections(), POLL_MS, {
  immediate: false,
})
onMounted(() => {
  rowHeight.value = measureRowHeight()
  void live.loadConnections()
  if (visibility.value === 'visible') resume()
})
watch(visibility, (current) => {
  if (current === 'visible') {
    void live.loadConnections()
    resume()
  } else {
    pause()
  }
})

// ---- keyboard ---------------------------------------------------------------------------------
const active = ref(0)
const copiedFlash = ref(false)

function move(to: number): void {
  const last = rows.value.length - 1
  if (last < 0) return
  active.value = Math.min(Math.max(to, 0), last)
  virtualizer.value.scrollToIndex(active.value, { align: 'auto' })
}

async function copyActive(): Promise<void> {
  const row = rows.value[active.value]?.original
  if (!row) return
  const addr = row.remote_addr || row.local_addr
  if (await copyText(addr)) {
    copiedFlash.value = true
    setTimeout(() => (copiedFlash.value = false), 1200)
  }
}

function onKeydown(event: KeyboardEvent): void {
  const page = Math.max(1, Math.floor((scroller.value?.clientHeight ?? 400) / rowHeight.value) - 1)
  switch (event.key) {
    case 'ArrowDown':
      move(active.value + 1)
      break
    case 'ArrowUp':
      move(active.value - 1)
      break
    case 'PageDown':
      move(active.value + page)
      break
    case 'PageUp':
      move(active.value - page)
      break
    case 'Home':
      move(0)
      break
    case 'End':
      move(rows.value.length - 1)
      break
    case 'c':
    case 'C':
      if (event.ctrlKey || event.metaKey || event.key === 'c') void copyActive()
      else return
      break
    default:
      return
  }
  event.preventDefault()
}

// Keep the active row inside the list when filtering shrinks it.
watch(
  () => rows.value.length,
  (length) => {
    if (active.value >= length) active.value = Math.max(0, length - 1)
  },
)

const sampled = computed(() =>
  live.sampledAt ? new Date(live.sampledAt).toLocaleTimeString() : null,
)
const GRID = 'grid grid-cols-[4rem_minmax(0,1.4fr)_minmax(0,1.4fr)_8rem_minmax(0,1fr)_5rem] gap-x-3'
</script>

<template>
  <div class="flex h-full min-h-0 flex-col gap-3">
    <!-- Filters -->
    <div class="flex flex-wrap items-end gap-3">
      <label class="flex flex-col gap-1 text-xs">
        <span class="text-text-muted">{{ t('connections.filters.protocol') }}</span>
        <Select v-model="proto">
          <SelectTrigger class="w-28" :aria-label="t('connections.filters.protocol')">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{{ t('connections.filters.all') }}</SelectItem>
            <SelectItem value="tcp">TCP</SelectItem>
            <SelectItem value="udp">UDP</SelectItem>
          </SelectContent>
        </Select>
      </label>
      <label class="flex flex-col gap-1 text-xs">
        <span class="text-text-muted">{{ t('connections.filters.state') }}</span>
        <Select v-model="state">
          <SelectTrigger class="w-40" :aria-label="t('connections.filters.state')">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{{ t('connections.filters.all') }}</SelectItem>
            <SelectItem v-for="s in TCP_STATES" :key="s" :value="s">
              {{ t(`connections.states.${s}`) }}
            </SelectItem>
          </SelectContent>
        </Select>
      </label>
      <label class="flex min-w-56 flex-1 flex-col gap-1 text-xs">
        <span class="text-text-muted">{{ t('connections.filters.search') }}</span>
        <input
          v-model="search"
          type="search"
          :placeholder="t('connections.filters.searchPlaceholder')"
          class="border-border bg-surface-2 text-text placeholder:text-text-muted focus-visible:ring-brand h-9 rounded-md border px-3 text-sm focus-visible:ring-2 focus-visible:outline-none"
          data-testid="connections-search"
        />
      </label>
      <Button v-if="filtersActive" variant="outline" size="sm" @click="clearFilters">
        {{ t('connections.filters.clear') }}
      </Button>
    </div>

    <!-- Status line -->
    <div class="text-text-muted flex flex-wrap items-center gap-x-4 gap-y-1 text-xs" role="status">
      <span data-testid="connections-summary">
        {{
          t('connections.summary', {
            shown: rows.length.toLocaleString(),
            total: live.total.toLocaleString(),
          })
        }}
      </span>
      <span v-if="sampled">{{ t('connections.updated', { time: sampled }) }}</span>
      <span v-if="copiedFlash" class="text-success">{{ t('common.copied') }}</span>
      <span v-if="live.truncated" class="text-warning flex items-center gap-1">
        <TriangleAlert class="size-3.5" aria-hidden="true" />
        {{ t('connections.truncated', { n: live.rows.length.toLocaleString() }) }}
      </span>
    </div>

    <p v-if="live.connectionsError === 'unsupported'" class="text-warning text-sm" role="alert">
      {{ t('connections.unsupported') }}
    </p>
    <p v-else-if="live.connectionsError === 'failed'" class="text-warning text-sm" role="alert">
      {{ t('connections.failed') }}
    </p>

    <!-- Table -->
    <div
      class="border-border bg-surface pw-table flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border"
      style="box-shadow: var(--shadow-card)"
    >
      <div
        :class="[
          GRID,
          'border-border bg-surface-2 text-text-muted border-b px-3 py-1.5 text-xs font-medium',
        ]"
        role="row"
      >
        <div
          v-for="id in COLUMN_IDS"
          :key="id"
          role="columnheader"
          :aria-sort="ariaSort(id)"
          class="min-w-0"
        >
          <button
            type="button"
            class="hover:text-text focus-visible:ring-brand flex max-w-full items-center gap-1 rounded focus-visible:ring-2 focus-visible:outline-none"
            @click="toggleSort(id, $event)"
          >
            <span class="truncate">{{ t(`connections.columns.${id}`) }}</span>
            <ArrowUp
              v-if="sortDirection(id) === 'asc'"
              class="size-3 shrink-0"
              aria-hidden="true"
            />
            <ArrowDown
              v-else-if="sortDirection(id) === 'desc'"
              class="size-3 shrink-0"
              aria-hidden="true"
            />
            <ArrowUpDown v-else class="size-3 shrink-0 opacity-40" aria-hidden="true" />
          </button>
        </div>
      </div>

      <div
        ref="scroller"
        class="focus-visible:ring-brand min-h-0 flex-1 overflow-auto focus-visible:ring-2 focus-visible:outline-none focus-visible:ring-inset"
        role="grid"
        tabindex="0"
        :aria-rowcount="rows.length"
        :aria-label="t('nav.connections')"
        data-testid="connections-grid"
        @keydown="onKeydown"
      >
        <p
          v-if="!rows.length"
          class="text-text-muted flex h-full items-center justify-center p-6 text-sm"
        >
          {{ live.rows.length ? t('connections.noMatch') : t('connections.empty') }}
        </p>
        <div v-else class="relative w-full" :style="{ height: `${totalSize}px` }">
          <div
            v-for="item in virtualRows"
            :key="String(item.key)"
            role="row"
            :aria-rowindex="item.index + 1"
            :aria-selected="item.index === active"
            :class="[
              GRID,
              'border-border absolute top-0 left-0 w-full items-center border-b px-3',
              item.index === active ? 'bg-surface-3' : 'hover:bg-surface-2',
            ]"
            :style="{ height: `${item.size}px`, transform: `translateY(${item.start}px)` }"
            @click="active = item.index"
          >
            <template v-if="rows[item.index]">
              <div role="gridcell" class="font-mono text-xs uppercase">
                {{ rows[item.index]!.original.proto }}
              </div>
              <div role="gridcell" class="min-w-0">
                <IpCell
                  :addr="rows[item.index]!.original.local_addr"
                  :port="rows[item.index]!.original.local_port"
                  :rdp="live.rdpPeers.has(rows[item.index]!.original.local_addr)"
                />
              </div>
              <div role="gridcell" class="min-w-0">
                <IpCell
                  :addr="rows[item.index]!.original.remote_addr"
                  :port="rows[item.index]!.original.remote_port"
                  :rdp="live.rdpPeers.has(rows[item.index]!.original.remote_addr)"
                />
              </div>
              <div role="gridcell" class="truncate text-xs">
                {{
                  rows[item.index]!.original.state
                    ? t(`connections.states.${rows[item.index]!.original.state}`)
                    : '—'
                }}
              </div>
              <div role="gridcell" class="min-w-0 truncate">
                {{
                  rows[item.index]!.original.process ||
                  t('connections.unknownProcess', { pid: rows[item.index]!.original.pid })
                }}
              </div>
              <div role="gridcell" class="text-text-muted font-mono text-xs tabular-nums">
                {{ rows[item.index]!.original.pid }}
              </div>
            </template>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

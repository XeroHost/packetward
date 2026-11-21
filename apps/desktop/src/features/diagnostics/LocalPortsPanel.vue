<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
import { useIntervalFn } from '@vueuse/core'
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import IpCell from '@/components/pw/IpCell.vue'
import { useAppVisible } from '@/lib/visibility'
import { useDiagStore } from '@/stores/diag'
import FailureNote from './FailureNote.vue'
import { FIELD } from './fieldClass'
import { portScope } from './diagFormat'

const { t } = useI18n()
const diag = useDiagStore()
const visible = useAppVisible()

const search = ref('')
const RDP_PORT = 3389

const rows = computed(() => {
  const needle = search.value.trim().toLowerCase()
  if (needle === '') return diag.localPorts
  return diag.localPorts.filter(
    (row) =>
      String(row.port).includes(needle) ||
      row.addr.includes(needle) ||
      (row.process ?? '').toLowerCase().includes(needle) ||
      String(row.pid) === needle,
  )
})

// The list changes slowly; refresh while the page is open and the window is shown.
const { pause, resume } = useIntervalFn(() => void diag.loadLocalPorts(), 5000, {
  immediate: false,
})
onMounted(() => {
  void diag.loadLocalPorts()
  if (visible.value) resume()
  else pause()
})
// Stop polling while the window is hidden in the tray.
watch(visible, (shown) => {
  if (shown) {
    void diag.loadLocalPorts()
    resume()
  } else pause()
})
</script>

<template>
  <div class="flex flex-col gap-4">
    <div class="flex flex-wrap items-end gap-3">
      <label class="flex min-w-64 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('connections.filters.search') }}</span>
        <input
          v-model="search"
          :class="FIELD"
          type="search"
          :placeholder="t('diagnostics.local.searchPlaceholder')"
        />
      </label>
      <p class="text-text-muted pb-2 text-sm">
        {{ t('diagnostics.local.count', { count: rows.length }) }}
      </p>
    </div>
    <p class="text-text-muted text-sm">{{ t('diagnostics.local.hint') }}</p>

    <FailureNote v-if="diag.localPortsError" :failure="diag.localPortsError" />

    <div v-if="rows.length > 0" class="bg-surface-2 max-h-[28rem] overflow-auto rounded-[12px]">
      <table class="w-full text-sm">
        <thead class="text-text-muted sticky top-0 text-left text-[11px] tracking-wide uppercase">
          <tr>
            <th class="px-3 py-2 font-medium">{{ t('connections.columns.proto') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('diagnostics.port.port') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('diagnostics.local.address') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('diagnostics.local.reachable') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('connections.columns.process') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('connections.columns.pid') }}</th>
          </tr>
        </thead>
        <tbody class="divide-hairline divide-y font-mono">
          <tr v-for="row in rows" :key="`${row.proto}-${row.addr}-${row.port}`">
            <td class="px-3 py-1.5 uppercase">{{ row.proto }}</td>
            <td class="px-3 py-1.5">
              {{ row.port }}
              <span v-if="row.port === RDP_PORT" class="text-brand-fg font-sans text-xs">RDP</span>
            </td>
            <td class="px-3 py-1.5"><IpCell :addr="row.addr" /></td>
            <td class="px-3 py-1.5 font-sans">
              {{ t(`diagnostics.local.scope.${portScope(row.addr)}`) }}
            </td>
            <td class="px-3 py-1.5">{{ row.process ?? '—' }}</td>
            <td class="text-text-muted px-3 py-1.5">{{ row.pid }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-else-if="diag.localPortsLoaded && !diag.localPortsError" class="text-text-muted text-sm">
      {{ t('diagnostics.local.empty') }}
    </p>
  </div>
</template>

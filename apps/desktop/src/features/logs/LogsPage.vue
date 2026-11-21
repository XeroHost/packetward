<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
// The audit log as a ledger: a search line, then rows with quiet column headers and hairlines.
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { TriangleAlert } from '@/components/pw/icons'
import { Button } from '@/components/ui/button'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { auditToCsv, auditToJson, useLogsStore } from '@/stores/logs'

const { t } = useI18n()
const logs = useLogsStore()
const search = ref('')
const copied = ref('')

onMounted(() => void logs.load())

async function copy(kind: 'csv' | 'json'): Promise<void> {
  const text = kind === 'csv' ? auditToCsv(logs.entries) : auditToJson(logs.entries)
  try {
    await navigator.clipboard.writeText(text)
    copied.value = kind
    setTimeout(() => (copied.value = ''), 2000)
  } catch {
    copied.value = ''
  }
}

function when(ms: number): string {
  return new Date(ms).toLocaleString()
}
</script>

<template>
  <section class="flex max-w-[72rem] flex-col gap-6">
    <p class="text-text-muted max-w-prose text-[13px] leading-relaxed">{{ t('logs.hint') }}</p>

    <form class="flex flex-wrap items-end gap-2" @submit.prevent="logs.load(search)">
      <label class="flex min-w-60 flex-1 flex-col gap-1.5 text-sm">
        <span class="text-text-muted text-xs">{{ t('logs.search') }}</span>
        <input v-model="search" :class="FIELD" spellcheck="false" />
      </label>
      <Button type="submit" size="sm" :disabled="logs.loading">{{ t('logs.apply') }}</Button>
      <Button
        size="sm"
        variant="outline"
        :disabled="logs.entries.length === 0"
        @click="copy('csv')"
      >
        {{ copied === 'csv' ? t('logs.copied') : t('logs.copyCsv') }}
      </Button>
      <Button
        size="sm"
        variant="outline"
        :disabled="logs.entries.length === 0"
        @click="copy('json')"
      >
        {{ copied === 'json' ? t('logs.copied') : t('logs.copyJson') }}
      </Button>
    </form>

    <p v-if="logs.error" class="pw-note" data-tone="danger" role="alert">
      <TriangleAlert class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{{ logs.error }}</span>
    </p>
    <p v-if="logs.truncated" class="text-text-muted text-xs">{{ t('logs.truncated') }}</p>
    <p v-if="!logs.loading && !logs.error && logs.entries.length === 0" class="text-sm">
      {{ t('logs.empty') }}
    </p>
    <div v-else class="overflow-x-auto">
      <table class="pw-rows">
        <thead>
          <tr>
            <th>{{ t('logs.time') }}</th>
            <th>{{ t('logs.actor') }}</th>
            <th>{{ t('logs.action') }}</th>
            <th>{{ t('logs.target') }}</th>
            <th>{{ t('logs.detail') }}</th>
            <th>{{ t('logs.result') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(e, i) in logs.entries" :key="i" class="align-top">
            <td class="text-text-muted text-xs whitespace-nowrap">{{ when(e.unix_ms) }}</td>
            <td>{{ e.actor }}</td>
            <td class="font-mono">{{ e.action }}</td>
            <td class="font-mono break-all">{{ e.target }}</td>
            <td class="text-text-muted break-words">{{ e.detail }}</td>
            <td :class="e.result === 'ok' ? 'text-text-muted' : 'text-warning'">{{ e.result }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { ScrollText, TriangleAlert } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
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

const card = 'bg-surface border-border flex flex-col gap-3 rounded-lg border p-[var(--card-p)]'
</script>

<template>
  <section class="flex flex-col gap-4">
    <div :class="card" style="box-shadow: var(--shadow-card)">
      <div class="flex items-center gap-3">
        <ScrollText class="text-brand-fg size-5" aria-hidden="true" />
        <h2 class="text-base">{{ t('logs.title') }}</h2>
      </div>
      <p class="text-text-muted text-sm">{{ t('logs.hint') }}</p>
      <form class="flex flex-wrap items-end gap-2" @submit.prevent="logs.load(search)">
        <label class="flex min-w-60 flex-1 flex-col gap-1 text-sm">
          <span class="text-text-muted">{{ t('logs.search') }}</span>
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
      <p
        v-if="logs.error"
        class="border-danger/40 bg-danger/10 flex items-start gap-2 rounded-md border p-3 text-sm"
        role="alert"
      >
        <TriangleAlert class="text-danger mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <span>{{ logs.error }}</span>
      </p>
      <p v-if="logs.truncated" class="text-text-muted text-xs">{{ t('logs.truncated') }}</p>
      <p v-if="!logs.loading && !logs.error && logs.entries.length === 0" class="text-sm">
        {{ t('logs.empty') }}
      </p>
      <div v-else class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="text-text-muted text-left text-xs">
            <tr>
              <th class="py-1 pr-3">{{ t('logs.time') }}</th>
              <th class="py-1 pr-3">{{ t('logs.actor') }}</th>
              <th class="py-1 pr-3">{{ t('logs.action') }}</th>
              <th class="py-1 pr-3">{{ t('logs.target') }}</th>
              <th class="py-1 pr-3">{{ t('logs.detail') }}</th>
              <th class="py-1">{{ t('logs.result') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(e, i) in logs.entries" :key="i" class="border-border border-t align-top">
              <td class="py-1 pr-3 whitespace-nowrap">{{ when(e.unix_ms) }}</td>
              <td class="py-1 pr-3">{{ e.actor }}</td>
              <td class="py-1 pr-3 font-mono">{{ e.action }}</td>
              <td class="py-1 pr-3 font-mono break-all">{{ e.target }}</td>
              <td class="py-1 pr-3 break-words">{{ e.detail }}</td>
              <td class="py-1" :class="e.result === 'ok' ? '' : 'text-warning'">{{ e.result }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>
</template>

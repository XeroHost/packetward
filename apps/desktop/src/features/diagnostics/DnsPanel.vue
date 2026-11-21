<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
import { Search } from '@/components/pw/icons'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { useDiagStore } from '@/stores/diag'
import FailureNote from './FailureNote.vue'
import { FIELD } from './fieldClass'
import PwSelect from '@/components/pw/PwSelect.vue'

const { t } = useI18n()
const diag = useDiagStore()

const RECORD_TYPES = [
  'A',
  'AAAA',
  'MX',
  'TXT',
  'NS',
  'CNAME',
  'PTR',
  'SOA',
  'CAA',
  'SRV',
  'ALL',
] as const
const RESOLVERS = ['system', 'cloudflare', 'google', 'custom'] as const

const name = ref('')
const recordType = ref<(typeof RECORD_TYPES)[number]>('A')
const resolver = ref<(typeof RESOLVERS)[number]>('system')
const custom = ref('')

const canRun = computed(
  () =>
    name.value.trim() !== '' &&
    !diag.dnsBusy &&
    (resolver.value !== 'custom' || custom.value.trim() !== ''),
)

function run(): void {
  if (!canRun.value) return
  void diag.runDns({
    name: name.value.trim(),
    record_type: recordType.value,
    resolver: resolver.value,
    custom_servers: custom.value
      .split(/[\s,;]+/)
      .map((server) => server.trim())
      .filter((server) => server !== ''),
  })
}

const typeOptions = RECORD_TYPES.map((value) => ({ value, label: value }))

const resolverOptions = computed(() =>
  RESOLVERS.map((value) => ({ value, label: t(`diagnostics.dns.resolvers.${value}`) })),
)
</script>

<template>
  <div class="flex flex-col gap-4">
    <form class="flex flex-wrap items-end gap-3" @submit.prevent="run">
      <label class="flex min-w-64 flex-1 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.dns.name') }}</span>
        <input
          v-model="name"
          :class="[FIELD, 'font-mono']"
          type="text"
          spellcheck="false"
          autocomplete="off"
          placeholder="example.com"
        />
      </label>
      <label class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.dns.type') }}</span>
        <PwSelect v-model="recordType" :options="typeOptions" />
      </label>
      <label class="flex w-44 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.dns.resolver') }}</span>
        <PwSelect v-model="resolver" :options="resolverOptions" />
      </label>
      <label v-if="resolver === 'custom'" class="flex min-w-48 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.dns.customServers') }}</span>
        <input
          v-model="custom"
          :class="[FIELD, 'font-mono']"
          type="text"
          spellcheck="false"
          placeholder="1.1.1.1, 9.9.9.9"
        />
      </label>
      <Button type="submit" :disabled="!canRun">
        <Search aria-hidden="true" />{{ t('diagnostics.dns.lookup') }}
      </Button>
    </form>

    <FailureNote v-if="diag.dnsError" :failure="diag.dnsError" />

    <div v-if="diag.dnsResult" class="flex flex-col gap-3">
      <p class="text-text-muted text-sm" role="status">
        {{
          t('diagnostics.dns.summary', {
            count: diag.dnsResult.records.length,
            ms: diag.dnsResult.elapsed_ms,
          })
        }}
      </p>
      <div
        v-if="diag.dnsResult.records.length > 0"
        class="bg-surface-2 overflow-auto rounded-[12px]"
      >
        <table class="w-full text-sm">
          <thead class="text-text-muted text-left text-[11px] tracking-wide uppercase">
            <tr>
              <th class="px-3 py-2 font-medium">{{ t('diagnostics.dns.name') }}</th>
              <th class="px-3 py-2 font-medium">{{ t('diagnostics.dns.type') }}</th>
              <th class="px-3 py-2 text-right font-medium">TTL</th>
              <th class="px-3 py-2 font-medium">{{ t('diagnostics.dns.value') }}</th>
            </tr>
          </thead>
          <tbody class="divide-hairline divide-y font-mono">
            <tr v-for="(record, index) in diag.dnsResult.records" :key="index">
              <td class="px-3 py-1.5">{{ record.name }}</td>
              <td class="px-3 py-1.5">{{ record.record_type }}</td>
              <td class="px-3 py-1.5 text-right">{{ record.ttl }}</td>
              <td class="px-3 py-1.5 break-all">{{ record.value }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="text-text-muted text-sm">{{ t('diagnostics.dns.none') }}</p>
      <ul v-if="diag.dnsResult.errors.length > 0" class="text-warning text-sm">
        <li v-for="error in diag.dnsResult.errors" :key="error.record_type">
          {{ error.record_type }}: {{ error.message }}
        </li>
      </ul>
    </div>
    <p v-else class="text-text-muted text-sm">{{ t('diagnostics.dns.hint') }}</p>
  </div>
</template>

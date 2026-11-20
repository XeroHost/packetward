<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Plug } from '@/components/pw/icons'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { useDiagStore } from '@/stores/diag'
import FailureNote from './FailureNote.vue'
import { FIELD } from './fieldClass'
import PwSelect from '@/components/pw/PwSelect.vue'

const { t } = useI18n()
const diag = useDiagStore()

const host = ref('')
const port = ref<number | null>(null)
const protocol = ref<'tcp' | 'udp'>('tcp')

const validPort = computed(
  () =>
    port.value !== null && Number.isInteger(port.value) && port.value >= 1 && port.value <= 65535,
)
const canRun = computed(() => host.value.trim() !== '' && validPort.value && !diag.portBusy)

function run(): void {
  if (!canRun.value || port.value === null) return
  void diag.runPortCheck({
    host: host.value.trim(),
    port: port.value,
    protocol: protocol.value,
    timeout_ms: 5000,
  })
}

const protocolOptions = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
] as const
</script>

<template>
  <div class="flex flex-col gap-4">
    <form class="flex flex-wrap items-end gap-3" @submit.prevent="run">
      <label class="flex min-w-64 flex-1 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.target') }}</span>
        <input
          v-model="host"
          :class="[FIELD, 'font-mono']"
          type="text"
          spellcheck="false"
          autocomplete="off"
          :placeholder="t('diagnostics.targetPlaceholder')"
        />
      </label>
      <label class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.port.port') }}</span>
        <input v-model.number="port" :class="FIELD" type="number" min="1" max="65535" />
      </label>
      <label class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.port.protocol') }}</span>
        <PwSelect v-model="protocol" :options="protocolOptions" />
      </label>
      <Button type="submit" :disabled="!canRun">
        <Plug aria-hidden="true" />{{ t('diagnostics.port.check') }}
      </Button>
    </form>

    <FailureNote v-if="diag.portError" :failure="diag.portError" />

    <div
      v-if="diag.portResult"
      class="bg-surface-2 flex flex-col gap-1 rounded-[12px] p-4"
      role="status"
    >
      <p class="text-base font-medium">
        <span class="font-mono">{{ diag.portResult.host }}:{{ diag.portResult.port }}</span>
        / {{ diag.portResult.protocol.toUpperCase() }} —
        {{ t(`diagnostics.port.states.${diag.portResult.state}`) }}
      </p>
      <p class="text-text-muted text-sm">
        {{ t(`diagnostics.port.explain.${diag.portResult.state}`) }}
      </p>
      <p v-if="diag.portResult.error" class="text-danger text-sm">{{ diag.portResult.error }}</p>
      <p class="text-text-muted text-xs">{{ diag.portResult.elapsed_ms }} ms</p>
    </div>
    <p v-else class="text-text-muted text-sm">{{ t('diagnostics.port.hint') }}</p>
  </div>
</template>

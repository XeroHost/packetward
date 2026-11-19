<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { TriangleAlert } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import type { DiagFailure } from '@/stores/diag'

defineProps<{ failure: DiagFailure }>()
const { t } = useI18n()
</script>

<template>
  <p
    class="border-danger/40 bg-danger/10 text-text flex items-start gap-2 rounded-md border p-3 text-sm"
    role="alert"
  >
    <TriangleAlert class="text-danger mt-0.5 size-4 shrink-0" aria-hidden="true" />
    <span>
      <template v-if="failure.kind === 'not_connected'">{{
        t('diagnostics.errors.notConnected')
      }}</template>
      <template v-else-if="failure.kind === 'unsupported'">{{
        t('diagnostics.errors.unsupported')
      }}</template>
      <template v-else-if="failure.kind === 'busy'">{{ t('diagnostics.errors.busy') }}</template>
      <template v-else>{{ failure.message }}</template>
    </span>
  </p>
</template>

<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
import { TriangleAlert } from '@/components/pw/icons'
import { useI18n } from 'vue-i18n'
import type { DiagFailure } from '@/stores/diag'

defineProps<{ failure: DiagFailure }>()
const { t } = useI18n()
</script>

<template>
  <p class="pw-note text-text flex items-start gap-2" data-tone="danger" role="alert">
    <TriangleAlert class="text-danger mt-0.5 size-4 shrink-0" aria-hidden="true" />
    <span>
      <template v-if="failure.kind === 'not_connected'">{{
        t('diagnostics.errors.notConnected')
      }}</template>
      <template v-else-if="failure.kind === 'unsupported'">{{
        t('diagnostics.errors.unsupported')
      }}</template>
      <template v-else-if="failure.kind === 'busy'">{{ t('diagnostics.errors.busy') }}</template>
      <template v-else-if="failure.kind === 'mode_unavailable'">
        {{ failure.message }}
        <span class="text-text-muted mt-1 block" data-test="npcap-hint">{{
          t('diagnostics.errors.modeUnavailableHint')
        }}</span>
      </template>
      <template v-else>{{ failure.message }}</template>
    </span>
  </p>
</template>

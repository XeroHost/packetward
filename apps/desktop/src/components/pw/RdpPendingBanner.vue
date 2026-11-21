<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
import { Timer } from '@/components/pw/icons'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { useRdpStore } from '@/stores/rdp'

const { t } = useI18n()
const rdp = useRdpStore()
</script>

<template>
  <div
    v-if="rdp.pending"
    class="pw-note pw-appear mx-9 mt-5 flex-wrap items-center"
    data-tone="warning"
    role="alert"
  >
    <Timer class="text-warning size-4 shrink-0" aria-hidden="true" />
    <span class="min-w-0 flex-1">
      <strong>{{ rdp.pending.description }}.</strong>
      {{ t('rdp.pending.explain', { seconds: rdp.secondsLeft }) }}
    </span>
    <Button size="sm" :disabled="rdp.busy" @click="rdp.confirm()">{{
      t('rdp.pending.keep')
    }}</Button>
    <Button size="sm" variant="outline" :disabled="rdp.busy" @click="rdp.cancel()">
      {{ t('rdp.pending.revert') }}
    </Button>
  </div>
</template>

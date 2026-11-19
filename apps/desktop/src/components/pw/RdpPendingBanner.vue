<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Timer } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { useRdpStore } from '@/stores/rdp'

const { t } = useI18n()
const rdp = useRdpStore()
</script>

<template>
  <div
    v-if="rdp.pending"
    class="border-warning/50 bg-warning/10 flex flex-wrap items-center gap-3 border-b px-5 py-2 text-sm"
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

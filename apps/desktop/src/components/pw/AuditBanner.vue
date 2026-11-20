<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { TriangleAlert } from '@/components/pw/icons'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useLiveStore } from '@/stores/live'

const { t } = useI18n()
const live = useLiveStore()

/** What is wrong with logon auditing / the event feed, if anything (most serious first). */
const problems = computed(() => {
  const trust = live.stats?.rdp_trust
  if (!trust) return []
  const list: string[] = []
  if (trust.feed === 'unavailable') list.push('feedUnavailable')
  if (trust.audit.success !== 'enabled') {
    list.push(trust.audit.success === 'disabled' ? 'successOff' : 'successUnknown')
  }
  if (trust.audit.failure !== 'enabled') {
    list.push(trust.audit.failure === 'disabled' ? 'failureOff' : 'failureUnknown')
  }
  return list
})
</script>

<template>
  <div
    v-if="problems.length"
    class="pw-note pw-appear mx-9 mt-5"
    data-tone="warning"
    role="alert"
    data-testid="audit-banner"
  >
    <TriangleAlert class="text-warning mt-0.5 size-4 shrink-0" aria-hidden="true" />
    <div class="flex flex-col gap-0.5">
      <p v-for="problem in problems" :key="problem">{{ t(`audit.${problem}`) }}</p>
      <p class="text-text-muted text-xs">{{ t('audit.howToFix') }}</p>
      <code class="text-text-muted font-mono text-xs select-all">{{ t('audit.command') }}</code>
    </div>
  </div>
</template>

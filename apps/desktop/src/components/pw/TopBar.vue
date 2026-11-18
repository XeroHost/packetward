<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import {
  CircleAlert,
  CircleCheck,
  CircleHelp,
  CircleX,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
} from 'lucide-vue-next'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import StatusPill, { type PillTone } from '@/components/pw/StatusPill.vue'
import { useAgentStore } from '@/stores/agent'

const { t } = useI18n()
const route = useRoute()
const agent = useAgentStore()

const title = computed(() => t(String(route.meta.titleKey ?? 'app.name')))

const agentPill = computed(() => {
  const map = {
    unknown: { icon: CircleHelp, tone: 'neutral' as PillTone },
    connected: { icon: CircleCheck, tone: 'success' as PillTone },
    disconnected: { icon: CircleX, tone: 'danger' as PillTone },
  }
  return { ...map[agent.status], value: t(`topbar.agent.${agent.status}`) }
})

const guardianPill = computed(() => {
  const mode = agent.guardianMode
  if (mode === null) {
    return { icon: CircleAlert, tone: 'neutral' as PillTone, value: t('topbar.guardian.unknown') }
  }
  const map = {
    off: { icon: ShieldOff, tone: 'neutral' as PillTone },
    monitor: { icon: ShieldAlert, tone: 'warning' as PillTone },
    active: { icon: ShieldCheck, tone: 'danger' as PillTone },
  }
  return { ...map[mode], value: t(`topbar.guardian.${mode}`) }
})
</script>

<template>
  <header
    class="border-border bg-surface flex h-12 shrink-0 items-center justify-between border-b px-5"
  >
    <h1 class="text-xl">{{ title }}</h1>
    <div class="flex items-center gap-2">
      <StatusPill
        :label="t('topbar.agent.label')"
        :value="agentPill.value"
        :tone="agentPill.tone"
        :icon="agentPill.icon"
      />
      <StatusPill
        :label="t('topbar.guardian.label')"
        :value="guardianPill.value"
        :tone="guardianPill.tone"
        :icon="guardianPill.icon"
      />
    </div>
  </header>
</template>

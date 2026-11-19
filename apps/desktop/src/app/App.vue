<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { LoaderCircle } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { RouterView } from 'vue-router'
import AppShell from '@/components/pw/AppShell.vue'
import { TooltipProvider } from '@/components/ui/tooltip'
import AgentUnavailable from '@/features/agent/AgentUnavailable.vue'
import { useAgentStore } from '@/stores/agent'

const { t } = useI18n()
const agent = useAgentStore()
</script>

<template>
  <TooltipProvider :delay-duration="300">
    <!-- The UI requires the agent: without it there is no half-working app, only this screen. -->
    <main
      v-if="agent.connecting"
      class="bg-bg text-text-muted flex h-screen items-center justify-center gap-2"
      role="status"
    >
      <LoaderCircle class="size-4 animate-spin" aria-hidden="true" />
      {{ t('agent.connecting') }}
    </main>
    <AgentUnavailable v-else-if="!agent.connected" />
    <AppShell v-else>
      <RouterView />
    </AppShell>
  </TooltipProvider>
</template>

<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
import { MotionConfig } from 'motion-v'
import { useI18n } from 'vue-i18n'
import AppShell from '@/components/pw/AppShell.vue'
import HIcon from '@/components/pw/HIcon.vue'
import TitleBar from '@/components/pw/TitleBar.vue'
import { TooltipProvider } from '@/components/ui/tooltip'
import AgentUnavailable from '@/features/agent/AgentUnavailable.vue'
import { Loading03Icon } from '@/lib/icons'
import { useAgentStore } from '@/stores/agent'

const { t } = useI18n()
const agent = useAgentStore()
</script>

<template>
  <!--
    Motion always runs: reduced-motion="never" ignores the operating system. Windows Server ships with
    visual effects off, which browsers report as "prefers-reduced-motion"; the only switch that turns
    animations off is Settings > Appearance > Reduce animations (data-motion="reduced").
  -->
  <MotionConfig reduced-motion="never">
    <TooltipProvider :delay-duration="300">
      <!-- The UI requires the agent: without it there is no half-working app, only this screen. -->
      <AppShell v-if="agent.connected" />
      <div v-else class="pw-window text-text flex h-screen flex-col">
        <!-- No native frame: even these screens need a way to move and close the window. -->
        <TitleBar />
        <main
          v-if="agent.connecting"
          class="text-text-muted flex min-h-0 flex-1 items-center justify-center gap-2"
          role="status"
        >
          <HIcon :icon="Loading03Icon" :size="16" class="animate-spin" />
          {{ t('agent.connecting') }}
        </main>
        <AgentUnavailable v-else class="min-h-0 flex-1" />
      </div>
    </TooltipProvider>
  </MotionConfig>
</template>

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// The window's own title bar: brand on the left (over the sidebar), a drag area, the state of the
// agent and the Guardian, and the Windows window controls on the right.
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import BrandLogo from '@/components/pw/BrandLogo.vue'
import StatusPill, { type PillTone } from '@/components/pw/StatusPill.vue'
import WindowControls from '@/components/pw/WindowControls.vue'
import {
  Alert02Icon,
  AlertCircleIcon,
  CheckmarkCircle02Icon,
  InformationCircleIcon,
  ShieldAlertIcon,
  ShieldBanIcon,
  ShieldCheckIcon,
  type IconData,
} from '@/lib/icons'
import { useAgentStore } from '@/stores/agent'

const { t } = useI18n()
const agent = useAgentStore()

const AGENT_PILLS = {
  unknown: { icon: InformationCircleIcon, tone: 'neutral' },
  connected: { icon: CheckmarkCircle02Icon, tone: 'success' },
  unresponsive: { icon: Alert02Icon, tone: 'warning' },
  disconnected: { icon: AlertCircleIcon, tone: 'danger' },
} as const satisfies Record<string, { icon: IconData; tone: PillTone }>

const GUARDIAN_PILLS = {
  off: { icon: ShieldBanIcon, tone: 'neutral' },
  monitor: { icon: ShieldAlertIcon, tone: 'warning' },
  active: { icon: ShieldCheckIcon, tone: 'success' },
} as const satisfies Record<string, { icon: IconData; tone: PillTone }>

const agentPill = computed(() => ({
  ...AGENT_PILLS[agent.pill],
  value: t(`topbar.agent.${agent.pill}`),
}))

const guardianPill = computed(() => {
  const mode = agent.guardianMode
  if (mode === null) {
    return {
      icon: InformationCircleIcon as IconData,
      tone: 'neutral' as PillTone,
      value: t('topbar.guardian.unknown'),
      pulse: false,
    }
  }
  return {
    ...GUARDIAN_PILLS[mode],
    value: t(`topbar.guardian.${mode}`),
    pulse: mode === 'active',
  }
})
</script>

<template>
  <header
    class="flex h-[var(--titlebar-h)] shrink-0 items-stretch select-none"
    data-tauri-drag-region
  >
    <div
      class="pointer-events-none flex w-[var(--sidebar-w)] shrink-0 items-center px-5"
      data-tauri-drag-region
    >
      <BrandLogo height-class="h-6" />
    </div>
    <div class="flex-1" data-tauri-drag-region />
    <div class="flex items-center gap-5 pr-4">
      <StatusPill
        hide-label
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
        :pulse="guardianPill.pulse"
      />
    </div>
    <WindowControls />
  </header>
</template>

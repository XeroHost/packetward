<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import {
  ExternalLink,
  KeyRound,
  LoaderCircle,
  LogOut,
  PlugZap,
  ServerOff,
  TriangleAlert,
  Wrench,
} from '@/components/pw/icons'
import { computed, type Component } from 'vue'
import { useI18n } from 'vue-i18n'
import { openExternal, XEROHOST_URL } from '@/api/links'
import { Button } from '@/components/ui/button'
import { useAgentStore } from '@/stores/agent'

const { t } = useI18n()
const agent = useAgentStore()

interface View {
  /** Key under `agent.unavailable.*` holding `title` and `body`. */
  key: string
  icon: Component
  /** Primary elevated action, if one can fix this. */
  action: 'start' | 'repair' | null
  spinning?: boolean
  detail?: string
}

const view = computed<View>(() => {
  const c = agent.connection
  switch (c.state) {
    case 'not_installed':
      return { key: 'notInstalled', icon: ServerOff, action: 'repair' }
    case 'stopped':
      return { key: 'stopped', icon: PlugZap, action: 'start' }
    case 'starting':
      return { key: 'starting', icon: LoaderCircle, action: null, spinning: true }
    case 'access_denied':
      switch (c.reason) {
        case 'group_missing':
          return { key: 'groupMissing', icon: KeyRound, action: 'repair' }
        case 'not_member':
          return { key: 'notMember', icon: KeyRound, action: 'repair' }
        case 'sign_out_required':
          // Repair restarts the agent, which then lists the members' own SIDs in the pipe ACL: that
          // matches the token this session already has, so no sign-out is needed.
          return { key: 'signOutRequired', icon: LogOut, action: 'repair' }
        default:
          return { key: 'unexplained', icon: KeyRound, action: 'repair' }
      }
    case 'agent_outdated':
      return { key: 'agentOutdated', icon: TriangleAlert, action: null, detail: c.agent_version }
    case 'ui_outdated':
      return { key: 'uiOutdated', icon: TriangleAlert, action: null, detail: c.agent_version }
    case 'error':
      return { key: 'error', icon: TriangleAlert, action: 'repair', detail: c.message }
    default:
      return { key: 'starting', icon: LoaderCircle, action: null, spinning: true }
  }
})

const notice = computed(() => {
  const n = agent.elevationNotice
  if (!n) return null
  return n.kind === 'cancelled'
    ? t('agent.unavailable.cancelled')
    : t('agent.unavailable.failed', { reason: n.message ?? '' })
})
</script>

<template>
  <main class="text-text overflow-y-auto px-10 py-12">
    <section class="pw-appear mx-auto flex w-full max-w-2xl flex-col gap-6" role="alert">
      <div class="flex items-start gap-5">
        <span
          class="pw-well text-brand-fg flex size-14 shrink-0 items-center justify-center !rounded-2xl !p-0"
        >
          <component
            :is="view.icon"
            class="size-7"
            :class="{ 'animate-spin': view.spinning }"
            aria-hidden="true"
          />
        </span>
        <div class="flex min-w-0 flex-col gap-2">
          <h1 class="text-[1.75rem] leading-tight font-semibold tracking-tight">
            {{ t(`agent.unavailable.${view.key}.title`) }}
          </h1>
          <p class="text-text-muted max-w-prose leading-relaxed">
            {{ t(`agent.unavailable.${view.key}.body`) }}
          </p>
          <p v-if="view.detail" class="text-text-muted font-mono text-xs break-all">
            {{ view.detail }}
          </p>
        </div>
      </div>

      <p v-if="notice" class="pw-note" data-tone="warning" role="status">{{ notice }}</p>

      <div class="flex flex-wrap items-center gap-2">
        <Button
          v-if="view.action"
          :disabled="agent.elevating"
          @click="agent.runElevated(view.action)"
        >
          <LoaderCircle v-if="agent.elevating" class="animate-spin" aria-hidden="true" />
          <Wrench v-else aria-hidden="true" />
          {{
            view.action === 'start'
              ? t('agent.unavailable.actionStart')
              : t('agent.unavailable.actionRepair')
          }}
        </Button>
        <Button
          v-if="view.action === 'start'"
          variant="outline"
          :disabled="agent.elevating"
          @click="agent.runElevated('repair')"
        >
          {{ t('agent.unavailable.actionRepair') }}
        </Button>
        <Button variant="outline" @click="openExternal(XEROHOST_URL)">
          <ExternalLink aria-hidden="true" />
          {{ t('app.contactSupport') }}
        </Button>
      </div>
      <p v-if="view.action" class="text-text-muted text-xs">
        {{ t('agent.unavailable.uacHint') }}
      </p>
    </section>
  </main>
</template>

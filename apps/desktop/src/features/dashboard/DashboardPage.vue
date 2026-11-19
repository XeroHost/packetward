<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Activity } from 'lucide-vue-next'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatUptime } from '@/lib/format'
import { useAgentStore } from '@/stores/agent'

const { t } = useI18n()
const agent = useAgentStore()

const info = computed(() => {
  const c = agent.connection
  return c.state === 'connected' ? c : null
})
const since = computed(() => agent.secondsSinceBeat)
</script>

<template>
  <section
    class="bg-surface border-border flex max-w-xl flex-col gap-4 rounded-lg border p-[var(--card-p)]"
    style="box-shadow: var(--shadow-card)"
  >
    <header class="flex items-center gap-2">
      <Activity class="text-text-muted size-4" aria-hidden="true" />
      <h2 class="text-base">{{ t('dashboard.agent.title') }}</h2>
    </header>
    <p class="text-text-muted">{{ t('dashboard.agent.description') }}</p>

    <dl v-if="info" class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5">
      <dt class="text-text-muted">{{ t('dashboard.agent.version') }}</dt>
      <dd class="font-mono">{{ info.agent_version }}</dd>
      <dt class="text-text-muted">{{ t('dashboard.agent.protocol') }}</dt>
      <dd class="font-mono">{{ info.protocol_major }}.{{ info.protocol_minor }}</dd>
      <dt class="text-text-muted">{{ t('dashboard.agent.heartbeat') }}</dt>
      <dd class="font-mono" data-testid="heartbeat-seq">
        {{ agent.heartbeat ? `#${agent.heartbeat.seq}` : t('dashboard.agent.waiting') }}
      </dd>
      <dt class="text-text-muted">{{ t('dashboard.agent.uptime') }}</dt>
      <dd class="font-mono" data-testid="heartbeat-uptime">
        {{ agent.heartbeat ? formatUptime(agent.heartbeat.uptime_secs) : '—' }}
      </dd>
      <dt class="text-text-muted">{{ t('dashboard.agent.lastBeat') }}</dt>
      <dd class="font-mono" :class="{ 'text-warning': agent.stale }">
        {{ since === null ? '—' : t('dashboard.agent.secondsAgo', { n: since }) }}
      </dd>
    </dl>
  </section>
</template>

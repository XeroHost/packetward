<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Activity, ArrowDown, ArrowUp, Cable, Check, Monitor } from 'lucide-vue-next'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import IpCell from '@/components/pw/IpCell.vue'
import StatTile from '@/components/pw/StatTile.vue'
import { Badge } from '@/components/ui/badge'
import { formatBitrate, formatRate, formatUptime } from '@/lib/format'
import { useAgentStore } from '@/stores/agent'
import { useLiveStore } from '@/stores/live'
import TrafficChart from './TrafficChart.vue'

const { t } = useI18n()
const agent = useAgentStore()
const live = useLiveStore()

const info = computed(() => {
  const c = agent.connection
  return c.state === 'connected' ? c : null
})
const since = computed(() => agent.secondsSinceBeat)
/** An agent from before M2 connects fine but publishes no traffic data. */
const agentTooOld = computed(() => info.value !== null && info.value.protocol_minor < 1)

const totals = computed(() => live.stats?.totals ?? null)
const counts = computed(() => live.stats?.connections ?? null)
const peers = computed(() => live.stats?.rdp_peers ?? [])
const sessions = computed(() => live.stats?.rdp_sessions ?? [])
const trust = computed(() => live.stats?.rdp_trust ?? null)

const linkHint = computed(() =>
  totals.value && totals.value.link_speed_bps > 0
    ? t('dashboard.tiles.link', { speed: formatBitrate(totals.value.link_speed_bps) })
    : undefined,
)

const cardClass = 'bg-surface border-border flex flex-col gap-3 rounded-lg border p-[var(--card-p)]'
</script>

<template>
  <div class="flex max-w-6xl flex-col gap-4">
    <p v-if="agentTooOld" class="text-warning text-sm" role="status">
      {{ t('dashboard.oldAgent') }}
    </p>

    <!-- Headline numbers -->
    <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <StatTile
        :label="t('dashboard.tiles.inbound')"
        :value="totals ? formatBitrate(totals.in_bps) : '—'"
        :hint="totals ? `${formatRate(totals.in_pps)} ${t('dashboard.tiles.pps')}` : undefined"
        :icon="ArrowDown"
        tone="inbound"
      />
      <StatTile
        :label="t('dashboard.tiles.outbound')"
        :value="totals ? formatBitrate(totals.out_bps) : '—'"
        :hint="totals ? `${formatRate(totals.out_pps)} ${t('dashboard.tiles.pps')}` : undefined"
        :icon="ArrowUp"
        tone="outbound"
      />
      <StatTile
        :label="t('dashboard.tiles.connections')"
        :value="counts ? String(counts.established) : '—'"
        :hint="
          counts
            ? t('dashboard.tiles.connectionsHint', {
                total: counts.total,
                waiting: counts.time_wait,
                half: counts.syn_received,
              })
            : undefined
        "
        :icon="Cable"
      />
      <StatTile
        :label="t('dashboard.tiles.rdp')"
        :value="live.stats ? String(sessions.length) : '—'"
        :hint="
          live.stats
            ? t('dashboard.tiles.rdpHint', { n: peers.length, port: live.stats.rdp_port })
            : undefined
        "
        :icon="Monitor"
      />
    </div>

    <!-- Traffic chart -->
    <section :class="cardClass" style="box-shadow: var(--shadow-card)">
      <header class="flex items-center justify-between gap-2">
        <h2 class="text-base">{{ t('dashboard.chart.title') }}</h2>
        <span v-if="linkHint" class="text-text-muted ml-auto mr-4 text-xs">{{ linkHint }}</span>
        <span class="text-text-muted flex items-center gap-3 text-xs">
          <span class="flex items-center gap-1.5">
            <span class="bg-chart-in inline-block size-2 rounded-full" aria-hidden="true" />
            {{ t('dashboard.chart.inbound') }}
          </span>
          <span class="flex items-center gap-1.5">
            <span class="bg-chart-out inline-block size-2 rounded-full" aria-hidden="true" />
            {{ t('dashboard.chart.outbound') }}
          </span>
        </span>
      </header>
      <TrafficChart />
    </section>

    <div class="grid gap-4 lg:grid-cols-2">
      <!-- Top remote addresses -->
      <section :class="cardClass" style="box-shadow: var(--shadow-card)">
        <header>
          <h2 class="text-base">{{ t('dashboard.topRemote.title') }}</h2>
          <p class="text-text-muted text-xs">{{ t('dashboard.topRemote.description') }}</p>
        </header>
        <p v-if="!live.stats?.top_remote.length" class="text-text-muted text-sm">
          {{ t('dashboard.topRemote.empty') }}
        </p>
        <ol v-else class="flex flex-col" data-testid="top-remote">
          <li
            v-for="talker in live.stats.top_remote"
            :key="talker.addr"
            class="border-border flex min-h-[var(--row-h)] items-center justify-between gap-3 border-b last:border-b-0"
          >
            <IpCell :addr="talker.addr" :rdp="live.rdpPeers.has(talker.addr)" />
            <span class="text-text-muted shrink-0 font-mono text-xs tabular-nums">
              {{ t('dashboard.topRemote.connections', { n: talker.connections }) }}
            </span>
          </li>
        </ol>
      </section>

      <!-- Adapters -->
      <section :class="cardClass" style="box-shadow: var(--shadow-card)">
        <header>
          <h2 class="text-base">{{ t('dashboard.adapters.title') }}</h2>
          <p class="text-text-muted text-xs">{{ t('dashboard.adapters.description') }}</p>
        </header>
        <p v-if="!live.stats?.interfaces.length" class="text-text-muted text-sm">
          {{ t('dashboard.adapters.empty') }}
        </p>
        <ul v-else class="flex flex-col" data-testid="adapters">
          <li
            v-for="nic in live.stats.interfaces"
            :key="nic.index"
            class="border-border flex min-h-[var(--row-h)] items-center justify-between gap-3 border-b py-1 last:border-b-0"
          >
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="truncate font-medium" :title="nic.description">{{ nic.name }}</span>
                <Badge variant="outline" class="h-4 px-1.5 text-[10px] leading-none">
                  {{ t(`dashboard.adapters.kind.${nic.kind}`) }}
                </Badge>
              </div>
              <div class="text-text-muted flex items-center gap-1 text-xs">
                <template v-if="nic.counts_toward_total">
                  <Check class="text-success size-3" aria-hidden="true" />
                  {{ t('dashboard.adapters.counted') }}
                </template>
                <template v-else>{{ t('dashboard.adapters.notCounted') }}</template>
              </div>
            </div>
            <div class="shrink-0 text-right font-mono text-xs tabular-nums">
              <div class="text-chart-in">↓ {{ formatBitrate(nic.in_bps) }}</div>
              <div class="text-chart-out">↑ {{ formatBitrate(nic.out_bps) }}</div>
            </div>
          </li>
        </ul>
      </section>
    </div>

    <!-- RDP -->
    <section :class="cardClass" style="box-shadow: var(--shadow-card)">
      <header>
        <h2 class="text-base">{{ t('dashboard.rdp.title') }}</h2>
        <p class="text-text-muted text-xs">{{ t('dashboard.rdp.description') }}</p>
      </header>
      <p v-if="live.stats && !sessions.length && !peers.length" class="text-text-muted text-sm">
        {{ t('dashboard.rdp.none') }}
      </p>
      <div v-else-if="live.stats" class="flex flex-col gap-3">
        <div v-if="peers.length" class="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span class="text-text-muted text-xs">{{ t('dashboard.rdp.peers') }}</span>
          <IpCell
            v-for="peer in peers"
            :key="peer"
            :addr="peer"
            rdp
            :trusted="live.rdpTrusted.has(peer)"
          />
        </div>
        <ul v-if="sessions.length" class="flex flex-col" data-testid="rdp-sessions">
          <li
            v-for="session in sessions"
            :key="session.session_id"
            class="border-border flex min-h-[var(--row-h)] flex-wrap items-center gap-x-4 gap-y-1 border-b py-1 last:border-b-0"
          >
            <span class="font-mono">{{ session.user || '—' }}</span>
            <Badge variant="outline" class="h-4 px-1.5 text-[10px] leading-none">
              {{ t(`dashboard.rdp.state.${session.state}`) }}
            </Badge>
            <span v-if="session.client_name" class="text-text-muted text-xs">
              {{ session.client_name }}
            </span>
            <span
              v-if="session.reported_addr"
              class="text-text-muted flex items-center gap-1 text-xs"
            >
              {{ t('dashboard.rdp.reported') }}
              <IpCell :addr="session.reported_addr" />
            </span>
          </li>
        </ul>
        <p class="text-text-muted text-xs">{{ t('dashboard.rdp.note') }}</p>
      </div>
      <div
        v-if="trust"
        class="border-border flex flex-col gap-2 border-t pt-3"
        data-testid="rdp-trust"
      >
        <div>
          <h3 class="text-sm font-medium">
            {{ t('dashboard.rdp.trustedTitle', { days: trust.window_days }) }}
          </h3>
          <p class="text-text-muted text-xs">{{ t('dashboard.rdp.trustedDescription') }}</p>
        </div>
        <p v-if="trust.feed === 'loading'" class="text-text-muted text-sm">
          {{ t('dashboard.rdp.trustedLoading') }}
        </p>
        <p v-else-if="trust.feed === 'unavailable'" class="text-warning text-sm">
          {{ t('dashboard.rdp.trustedUnavailable') }}
        </p>
        <p v-else-if="!trust.addresses.length" class="text-text-muted text-sm">
          {{ t('dashboard.rdp.trustedEmpty') }}
        </p>
        <ul v-else class="flex flex-wrap gap-x-5 gap-y-1">
          <li v-for="entry in trust.addresses" :key="entry.addr" class="flex items-center gap-2">
            <IpCell :addr="entry.addr" />
            <span class="text-text-muted text-xs">{{
              new Date(entry.last_logon_unix_ms).toLocaleDateString()
            }}</span>
          </li>
        </ul>
      </div>
    </section>

    <!-- Agent connection (kept from M1: proof of life) -->
    <section :class="cardClass" style="box-shadow: var(--shadow-card)">
      <header class="flex items-center gap-2">
        <Activity class="text-text-muted size-4" aria-hidden="true" />
        <h2 class="text-base">{{ t('dashboard.agent.title') }}</h2>
      </header>
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
  </div>
</template>

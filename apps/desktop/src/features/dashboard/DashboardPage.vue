<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
// The dashboard answers one question: "am I being attacked, from where, how much?". Traffic is the
// hero (the biggest thing on the page), protection sits beside it as a quiet column, and the
// lists below are plain rows, not a grid of identical cards.
import { Motion } from 'motion-v'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterLink } from 'vue-router'
import CountingValue from '@/components/pw/CountingValue.vue'
import HIcon from '@/components/pw/HIcon.vue'
import IpCell from '@/components/pw/IpCell.vue'
import { Badge } from '@/components/ui/badge'
import { formatBitrate, formatRate, formatUptime } from '@/lib/format'
import { CheckmarkCircle02Icon, ShieldAlertIcon, ShieldBanIcon, ShieldCheckIcon } from '@/lib/icons'
import { LIST_STAGGER, springPage } from '@/lib/motion'
import { useAgentStore } from '@/stores/agent'
import { useAlertsStore } from '@/stores/alerts'
import { useLiveStore } from '@/stores/live'
import TrafficChart from './TrafficChart.vue'

const { t } = useI18n()
const agent = useAgentStore()
const live = useLiveStore()
const alerts = useAlertsStore()

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

const guardian = computed(() => {
  const map = {
    off: { icon: ShieldBanIcon, tone: 'text-text-muted' },
    monitor: { icon: ShieldAlertIcon, tone: 'text-warning' },
    active: { icon: ShieldCheckIcon, tone: 'text-success' },
  } as const
  const mode = agent.guardianMode
  return mode === null ? null : { mode, ...map[mode] }
})
const incidents = computed(() => alerts.ongoing.length)

const topRemote = computed(() => live.stats?.top_remote ?? [])
const mostConnections = computed(() => Math.max(1, ...topRemote.value.map((r) => r.connections)))

const whole = (n: number): string => String(Math.round(n))
const sectionTitle = 'text-[0.95rem] font-semibold'
</script>

<template>
  <div class="flex max-w-[72rem] flex-col gap-(--section-gap)">
    <p v-if="agentTooOld" class="text-warning text-sm" role="status">
      {{ t('dashboard.oldAgent') }}
    </p>

    <!-- Traffic (hero) and protection -->
    <section class="grid gap-x-10 gap-y-8 lg:grid-cols-[minmax(0,1fr)_17rem]">
      <div class="min-w-0">
        <div class="flex flex-wrap items-end gap-x-12 gap-y-4">
          <div>
            <div class="text-text-muted flex items-center gap-2 text-xs">
              <span class="bg-chart-in inline-block size-2 rounded-full" aria-hidden="true" />
              {{ t('dashboard.tiles.inbound') }}
            </div>
            <div
              class="font-heading mt-1 text-[3.5rem] leading-none font-semibold tracking-tight tabular-nums"
              data-testid="tile-value"
            >
              <CountingValue
                v-if="totals"
                :value="totals.in_bps"
                :format="formatBitrate"
                unit-class="text-text-muted text-2xl font-medium"
              />
              <template v-else>—</template>
            </div>
            <div v-if="totals" class="text-text-muted mt-2 text-xs">
              {{ formatRate(totals.in_pps) }} {{ t('dashboard.tiles.pps') }}
            </div>
          </div>
          <div>
            <div class="text-text-muted flex items-center gap-2 text-xs">
              <span class="bg-chart-out inline-block size-2 rounded-full" aria-hidden="true" />
              {{ t('dashboard.tiles.outbound') }}
            </div>
            <div
              class="font-heading mt-1 text-[1.75rem] leading-none font-semibold tabular-nums"
              data-testid="tile-value"
            >
              <CountingValue
                v-if="totals"
                :value="totals.out_bps"
                :format="formatBitrate"
                unit-class="text-text-muted text-base font-medium"
              />
              <template v-else>—</template>
            </div>
            <div v-if="totals" class="text-text-muted mt-2 text-xs">
              {{ formatRate(totals.out_pps) }} {{ t('dashboard.tiles.pps') }}
            </div>
          </div>
          <span v-if="linkHint" class="text-text-muted mb-1 ml-auto text-xs">{{ linkHint }}</span>
        </div>
        <TrafficChart class="mt-5" />
      </div>

      <aside class="border-hairline flex flex-col gap-8 lg:border-l lg:pl-8">
        <div>
          <h2 :class="sectionTitle">{{ t('dashboard.protection.title') }}</h2>
          <div v-if="guardian" class="mt-3 flex items-center gap-2.5" :class="guardian.tone">
            <HIcon :icon="guardian.icon" :size="22" />
            <span class="font-heading text-xl font-semibold">{{
              t(`topbar.guardian.${guardian.mode}`)
            }}</span>
          </div>
          <p v-if="guardian" class="text-text-muted mt-2 text-[13px] leading-relaxed">
            {{ t(`dashboard.protection.${guardian.mode}`) }}
          </p>
          <p class="mt-4 flex items-center gap-2 text-[13px]">
            <HIcon
              :icon="incidents > 0 ? ShieldAlertIcon : CheckmarkCircle02Icon"
              :size="16"
              :class="incidents > 0 ? 'text-warning' : 'text-success'"
            />
            {{
              incidents > 0
                ? t('dashboard.protection.incidents', { n: incidents })
                : t('dashboard.protection.incidentsNone')
            }}
          </p>
          <RouterLink
            to="/guardian"
            class="text-brand-fg mt-3 inline-block text-[13px] font-medium underline-offset-4 hover:underline"
          >
            {{ t('dashboard.protection.open') }}
          </RouterLink>
        </div>

        <div>
          <h2 :class="sectionTitle">{{ t('dashboard.now.title') }}</h2>
          <dl class="mt-3 grid grid-cols-[1fr_auto] items-baseline gap-x-4 gap-y-2.5 text-[13px]">
            <dt class="text-text-muted">{{ t('dashboard.tiles.connections') }}</dt>
            <dd class="font-heading text-xl font-semibold" data-testid="tile-value">
              <CountingValue v-if="counts" :value="counts.established" :format="whole" />
              <template v-else>—</template>
            </dd>
            <dd v-if="counts" class="text-text-muted col-span-2 -mt-1.5 text-xs">
              {{
                t('dashboard.tiles.connectionsHint', {
                  total: counts.total,
                  waiting: counts.time_wait,
                  half: counts.syn_received,
                })
              }}
            </dd>
            <dt class="text-text-muted">{{ t('dashboard.tiles.rdp') }}</dt>
            <dd class="font-heading text-xl font-semibold" data-testid="tile-value">
              <CountingValue v-if="live.stats" :value="sessions.length" :format="whole" />
              <template v-else>—</template>
            </dd>
            <dd v-if="live.stats" class="text-text-muted col-span-2 -mt-1.5 text-xs">
              {{ t('dashboard.tiles.rdpHint', { n: peers.length, port: live.stats.rdp_port }) }}
            </dd>
          </dl>
        </div>
      </aside>
    </section>

    <!-- Who is connecting, and through which adapter -->
    <section class="grid gap-x-12 gap-y-10 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
      <div>
        <h2 :class="sectionTitle">{{ t('dashboard.topRemote.title') }}</h2>
        <p class="text-text-muted mt-0.5 text-xs">{{ t('dashboard.topRemote.description') }}</p>
        <p v-if="!topRemote.length" class="text-text-muted mt-4 text-sm">
          {{ t('dashboard.topRemote.empty') }}
        </p>
        <ol v-else class="mt-3 flex flex-col" data-testid="top-remote">
          <Motion
            v-for="(talker, index) in topRemote"
            :key="talker.addr"
            as="li"
            :initial="{ opacity: 0, y: 6 }"
            :animate="{
              opacity: 1,
              y: 0,
              transition: { ...springPage, delay: index * LIST_STAGGER },
            }"
            class="border-hairline border-b last:border-b-0"
          >
            <div class="flex min-h-[var(--row-h)] items-center justify-between gap-3">
              <IpCell :addr="talker.addr" :rdp="live.rdpPeers.has(talker.addr)" />
              <span class="text-text-muted shrink-0 font-mono text-xs tabular-nums">
                {{ t('dashboard.topRemote.connections', { n: talker.connections }) }}
              </span>
            </div>
            <div class="bg-hairline mb-1.5 h-0.5 overflow-hidden rounded-full" aria-hidden="true">
              <div
                class="bg-chart-in h-full rounded-full opacity-60 transition-[width] duration-500"
                :style="{ width: `${(talker.connections / mostConnections) * 100}%` }"
              />
            </div>
          </Motion>
        </ol>
      </div>

      <div>
        <h2 :class="sectionTitle">{{ t('dashboard.adapters.title') }}</h2>
        <p class="text-text-muted mt-0.5 text-xs">{{ t('dashboard.adapters.description') }}</p>
        <p v-if="!live.stats?.interfaces.length" class="text-text-muted mt-4 text-sm">
          {{ t('dashboard.adapters.empty') }}
        </p>
        <ul v-else class="mt-3 flex flex-col" data-testid="adapters">
          <li
            v-for="nic in live.stats.interfaces"
            :key="nic.index"
            class="border-hairline flex min-h-[var(--row-h)] items-center justify-between gap-3 border-b py-1.5 last:border-b-0"
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
                  <HIcon :icon="CheckmarkCircle02Icon" :size="12" class="text-success" />
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
      </div>
    </section>

    <!-- Remote Desktop -->
    <section class="border-hairline border-t pt-8">
      <h2 :class="sectionTitle">{{ t('dashboard.rdp.title') }}</h2>
      <p class="text-text-muted mt-0.5 text-xs">{{ t('dashboard.rdp.description') }}</p>
      <p
        v-if="live.stats && !sessions.length && !peers.length"
        class="text-text-muted mt-4 text-sm"
      >
        {{ t('dashboard.rdp.none') }}
      </p>
      <div v-else-if="live.stats" class="mt-4 flex flex-col gap-4">
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
            class="border-hairline flex min-h-[var(--row-h)] flex-wrap items-center gap-x-4 gap-y-1 border-b py-1 last:border-b-0"
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
      <div v-if="trust" class="mt-6 flex flex-col gap-2" data-testid="rdp-trust">
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

    <!-- Agent connection: proof of life, deliberately small -->
    <footer
      v-if="info"
      class="text-text-muted -mt-4 flex flex-wrap items-center gap-x-6 gap-y-1 text-xs"
    >
      <span class="font-medium">{{ t('dashboard.agent.title') }}</span>
      <span
        >{{ t('dashboard.agent.version') }}
        <span class="font-mono">{{ info.agent_version }}</span></span
      >
      <span
        >{{ t('dashboard.agent.protocol') }}
        <span class="font-mono">{{ info.protocol_major }}.{{ info.protocol_minor }}</span></span
      >
      <span>
        {{ t('dashboard.agent.heartbeat') }}
        <span class="font-mono" data-testid="heartbeat-seq">{{
          agent.heartbeat ? `#${agent.heartbeat.seq}` : t('dashboard.agent.waiting')
        }}</span>
      </span>
      <span>
        {{ t('dashboard.agent.uptime') }}
        <span class="font-mono" data-testid="heartbeat-uptime">{{
          agent.heartbeat ? formatUptime(agent.heartbeat.uptime_secs) : '—'
        }}</span>
      </span>
      <span :class="{ 'text-warning': agent.stale }">
        {{ t('dashboard.agent.lastBeat') }}
        <span class="font-mono">{{
          since === null ? '—' : t('dashboard.agent.secondsAgo', { n: since })
        }}</span>
      </span>
    </footer>
  </div>
</template>

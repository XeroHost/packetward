<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// Speed test: what to measure against (provider, streams) and the start buttons in one card, the steps
// and the live rate while it runs (the number is the page), and the latest result as a hero with the
// older ones as plain rows.
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Check, Square, TriangleAlert } from '@/components/pw/icons'
import IpCell from '@/components/pw/IpCell.vue'
import PwSelect from '@/components/pw/PwSelect.vue'
import { Button } from '@/components/ui/button'
import { FIELD } from '@/features/diagnostics/fieldClass'
import {
  BIN_LIMIT_GB,
  MAX_STREAMS,
  PROVIDERS,
  useSpeedStore,
  type SpeedProvider,
} from '@/stores/speed'
import type { SpeedKind } from '@/types/generated/SpeedKind'
import type { SpeedResultView } from '@/types/generated/SpeedResultView'

const { t } = useI18n()
const speed = useSpeedStore()

const streams = ref(4)
const confirm50 = ref(false)

const providerModel = computed({
  get: () => speed.provider,
  set: (value: SpeedProvider) => speed.setProvider(value),
})
const providerOptions = computed(() =>
  PROVIDERS.map((value) => ({ value, label: t(`speed.providers.${value}`) })),
)
/** Your own servers are only used when the provider is automatic or "my servers". */
const showServers = computed(() => speed.provider === 'auto' || speed.provider === 'custom')
const binLimit = computed(() => BIN_LIMIT_GB[speed.provider])
/** Connections the provider tolerates (public mirrors rate-limit more than a few). */
const streamCap = computed(() => MAX_STREAMS[speed.provider] ?? 16)

const serversText = computed({
  get: () => speed.servers,
  set: (value: string) => speed.setServers(value),
})

function run(kind: SpeedKind): void {
  void speed.start({
    kind,
    streams: Math.min(streamCap.value, Math.max(1, Math.floor(streams.value) || 4)),
    confirmLarge: kind === 'bin50' ? confirm50.value : undefined,
  })
}

/** A sparkline of Mbps samples as an SVG polyline. */
function spark(values: readonly number[], width = 320, height = 56): string {
  if (values.length < 2) return ''
  const max = Math.max(...values, 1)
  return values
    .map(
      (v, i) =>
        `${((i / (values.length - 1)) * width).toFixed(1)},${(height - (v / max) * (height - 4) - 2).toFixed(1)}`,
    )
    .join(' ')
}

/** A rate as a big number and a small unit, so the unit never wraps under the figure. */
function rate(value: number | undefined): { n: string; unit: string } {
  if (value === undefined) return { n: '—', unit: '' }
  return value >= 1000
    ? { n: (value / 1000).toFixed(2), unit: 'Gbps' }
    : { n: value.toFixed(1), unit: 'Mbps' }
}

function ms(value: number | undefined): string {
  return value === undefined ? '—' : `${value.toFixed(1)} ms`
}

function gib(bytes: number): string {
  return `${(bytes / 1024 ** 3).toFixed(2)} GiB`
}

function when(result: SpeedResultView): string {
  return new Date(result.started_unix_ms).toLocaleString()
}

const latest = computed(() => speed.results[0] ?? null)
const older = computed(() => speed.results.slice(1))
const sectionTitle = 'text-[1.0625rem] font-semibold'

// The steps of a quick test, in order; a bin test only downloads.
const STEPS = ['picking_server', 'latency', 'download', 'upload'] as const
const steps = computed(() => {
  const at =
    speed.phase === 'server_info'
      ? 1
      : speed.phase === 'bin_download'
        ? 2
        : STEPS.indexOf(speed.phase as (typeof STEPS)[number])
  const list = speed.kind === 'quick' ? STEPS : (['picking_server', 'download'] as const)
  return list.map((id) => {
    const index = STEPS.indexOf(id)
    return {
      id,
      state: at < 0 ? 'todo' : index < at ? 'done' : index === at ? 'now' : 'todo',
    }
  })
})

const failureText = computed(() => {
  const failure = speed.failure
  if (!failure) return ''
  if (failure.code === 'rate_limited') {
    const wait = failure.retryAfterSecs ?? 0
    // A public provider can ask for an hour: say minutes, and say so plainly when it does not tell.
    if (wait <= 0) return t('speed.errors.rate_limited_unknown')
    if (wait >= 120) {
      return t('speed.errors.rate_limited_minutes', { minutes: Math.ceil(wait / 60) })
    }
  }
  return t(`speed.errors.${failure.code}`, { retry: failure.retryAfterSecs ?? 0 })
})
</script>

<template>
  <section class="flex max-w-[64rem] flex-col gap-(--section-gap)">
    <div class="flex flex-col gap-5">
      <div>
        <h2 :class="sectionTitle">{{ t('speed.title') }}</h2>
        <p class="text-text-muted mt-1 max-w-prose text-[13px] leading-relaxed">
          {{ t('speed.hint') }}
        </p>
      </div>

      <div class="bg-surface-2/60 flex flex-col gap-5 rounded-[16px] p-5">
        <div class="flex flex-wrap items-start gap-4">
          <label class="flex w-full max-w-sm min-w-60 flex-1 flex-col gap-1.5 text-sm">
            <span class="text-text-muted text-xs">{{ t('speed.provider') }}</span>
            <PwSelect
              v-model="providerModel"
              :options="providerOptions"
              :disabled="speed.running"
            />
          </label>
          <label class="flex w-28 flex-col gap-1.5 text-sm">
            <span class="text-text-muted text-xs">{{ t('speed.streams') }}</span>
            <input
              v-model.number="streams"
              :class="FIELD"
              type="number"
              min="1"
              :max="streamCap"
              :disabled="speed.running"
            />
          </label>
        </div>
        <p
          class="text-text-muted -mt-2 max-w-prose text-xs leading-relaxed"
          data-testid="provider-hint"
        >
          {{ t(`speed.providerHints.${speed.provider}`) }}
          <template v-if="streamCap < 16">
            {{ t('speed.streamCap', { n: streamCap }) }}
          </template>
        </p>

        <div v-if="showServers" class="flex flex-col gap-1.5">
          <label class="flex max-w-3xl flex-col gap-1.5 text-sm">
            <span class="text-text-muted text-xs">{{ t('speed.servers') }}</span>
            <textarea
              v-model="serversText"
              :class="[FIELD, 'h-16 py-2 font-mono']"
              spellcheck="false"
              :disabled="speed.running"
              placeholder="https://speed.example.com:443"
            />
          </label>
          <p class="text-text-muted text-xs">{{ t('speed.serversHint') }}</p>
        </div>

        <div class="flex flex-wrap items-center gap-2">
          <Button v-if="!speed.running" @click="run('quick')">{{ t('speed.kinds.quick') }}</Button>
          <template v-if="!speed.running">
            <span class="bg-hairline mx-1 hidden h-5 w-px sm:block" aria-hidden="true" />
            <Button
              variant="outline"
              :disabled="binLimit < 1"
              :title="binLimit < 1 ? t('speed.binUnavailable') : undefined"
              data-testid="run-bin1"
              @click="run('bin1')"
              >{{ t('speed.kinds.bin1') }}</Button
            >
            <Button
              variant="outline"
              :disabled="binLimit < 10"
              :title="binLimit < 10 ? t('speed.binUnavailable') : undefined"
              data-testid="run-bin10"
              @click="run('bin10')"
              >{{ t('speed.kinds.bin10') }}</Button
            >
            <Button
              v-if="binLimit >= 50"
              variant="outline"
              :disabled="!confirm50"
              data-testid="run-bin50"
              @click="run('bin50')"
              >{{ t('speed.kinds.bin50') }}</Button
            >
          </template>
          <Button v-else variant="destructive" @click="speed.cancel()">
            <Square aria-hidden="true" />{{ t('speed.cancel') }}
          </Button>
        </div>
        <label v-if="binLimit >= 50" class="flex max-w-prose items-start gap-2 text-[13px]">
          <input v-model="confirm50" type="checkbox" class="mt-1" :disabled="speed.running" />
          <span class="text-text-muted">{{ t('speed.confirm50') }}</span>
        </label>
      </div>

      <p v-if="speed.rejected.length > 0" class="pw-note" data-tone="warning">
        {{ t('speed.rejected') }} {{ speed.rejected.join('; ') }}
      </p>
      <p v-if="speed.failure" class="pw-note" data-tone="danger" role="alert" data-testid="failure">
        <TriangleAlert class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <span>
          {{ failureText }}
          <span class="text-text-muted block">{{ speed.failure.message }}</span>
        </span>
      </p>
    </div>

    <!-- Live: the steps, then the rate is the page -->
    <div v-if="speed.running" class="pw-appear flex flex-col gap-6" role="status">
      <ol class="flex flex-wrap items-center gap-x-1 gap-y-2 text-[13px]" data-testid="steps">
        <li v-for="(step, index) in steps" :key="step.id" class="flex items-center gap-1">
          <span
            class="flex items-center gap-1.5 rounded-full px-3 py-1"
            :class="
              step.state === 'now'
                ? 'bg-brand/15 text-brand-fg font-medium'
                : step.state === 'done'
                  ? 'text-text-muted'
                  : 'text-text-muted/60'
            "
            :aria-current="step.state === 'now' ? 'step' : undefined"
          >
            <Check v-if="step.state === 'done'" class="text-success size-3.5" aria-hidden="true" />
            <span
              v-else-if="step.state === 'now'"
              class="bg-brand-fg size-1.5 animate-pulse rounded-full"
              aria-hidden="true"
            />
            {{ t(`speed.steps.${step.id}`) }}
          </span>
          <span v-if="index < steps.length - 1" class="text-text-muted/40" aria-hidden="true"
            >›</span
          >
        </li>
      </ol>

      <template v-if="speed.bin">
        <p class="font-heading text-[3.5rem] leading-none font-semibold tabular-nums">
          {{ rate(speed.bin.mbps).n }}
          <span class="text-text-muted text-xl font-medium">{{ rate(speed.bin.mbps).unit }}</span>
        </p>
        <progress class="w-full max-w-xl" :value="speed.bin.done" :max="speed.bin.total" />
        <p class="text-text-muted font-mono text-xs">
          {{ gib(speed.bin.done) }} / {{ gib(speed.bin.total) }} — {{ t('speed.avg') }}
          {{ rate(speed.bin.avg).n }} {{ rate(speed.bin.avg).unit }}
        </p>
      </template>
      <div v-if="speed.down.length > 1 || speed.up.length > 1" class="grid gap-8 sm:grid-cols-2">
        <div v-if="speed.down.length > 1">
          <p class="text-text-muted text-xs">{{ t('speed.download') }}</p>
          <p class="font-heading mt-1 text-[2.5rem] leading-none font-semibold tabular-nums">
            {{ rate(speed.down.at(-1)).n }}
            <span class="text-text-muted text-lg font-medium">{{
              rate(speed.down.at(-1)).unit
            }}</span>
          </p>
          <svg
            viewBox="0 0 320 56"
            class="mt-3 h-14 w-full"
            role="img"
            :aria-label="t('speed.download')"
          >
            <polyline
              :points="spark(speed.down)"
              fill="none"
              stroke="var(--chart-in)"
              stroke-width="2"
            />
          </svg>
        </div>
        <div v-if="speed.up.length > 1">
          <p class="text-text-muted text-xs">{{ t('speed.upload') }}</p>
          <p class="font-heading mt-1 text-[2.5rem] leading-none font-semibold tabular-nums">
            {{ rate(speed.up.at(-1)).n }}
            <span class="text-text-muted text-lg font-medium">{{
              rate(speed.up.at(-1)).unit
            }}</span>
          </p>
          <svg
            viewBox="0 0 320 56"
            class="mt-3 h-14 w-full"
            role="img"
            :aria-label="t('speed.upload')"
          >
            <polyline
              :points="spark(speed.up)"
              fill="none"
              stroke="var(--chart-out)"
              stroke-width="2"
            />
          </svg>
        </div>
      </div>
    </div>

    <!-- Latest result: a hero -->
    <div v-if="latest" class="pw-appear border-hairline flex flex-col gap-6 border-t pt-10">
      <div class="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 class="text-[1.25rem] font-semibold">{{ latest.server.name }}</h2>
        <span v-if="latest.server.location" class="text-text-muted text-sm">{{
          latest.server.location
        }}</span>
        <span class="text-text-muted ml-auto text-xs"
          >{{ t(`speed.kinds.${latest.kind}`) }} · {{ when(latest) }}</span
        >
      </div>
      <dl class="grid grid-cols-2 gap-x-10 gap-y-6 lg:grid-cols-4">
        <div v-if="latest.download">
          <dt class="text-text-muted text-xs">{{ t('speed.download') }}</dt>
          <dd class="font-heading mt-1 leading-none font-semibold tabular-nums">
            <span class="text-[2.75rem]">{{ rate(latest.download.avg_mbps).n }}</span>
            <span class="text-text-muted ml-1.5 text-base font-medium">{{
              rate(latest.download.avg_mbps).unit
            }}</span>
          </dd>
          <dd class="text-text-muted mt-2 text-xs">
            {{ t('speed.peak') }} {{ rate(latest.download.peak_mbps).n }}
            {{ rate(latest.download.peak_mbps).unit }} · {{ latest.download.streams }}
            {{ t('speed.streamsShort') }}
          </dd>
        </div>
        <div v-if="latest.upload">
          <dt class="text-text-muted text-xs">{{ t('speed.upload') }}</dt>
          <dd class="font-heading mt-1 leading-none font-semibold tabular-nums">
            <span class="text-[2.75rem]">{{ rate(latest.upload.avg_mbps).n }}</span>
            <span class="text-text-muted ml-1.5 text-base font-medium">{{
              rate(latest.upload.avg_mbps).unit
            }}</span>
          </dd>
          <dd class="text-text-muted mt-2 text-xs">
            {{ t('speed.peak') }} {{ rate(latest.upload.peak_mbps).n }}
            {{ rate(latest.upload.peak_mbps).unit }}
          </dd>
          <dd
            v-if="latest.upload_server"
            class="text-text-muted mt-1 text-xs"
            data-testid="upload-server"
          >
            {{ t('speed.uploadOn', { server: latest.upload_server.name }) }}
          </dd>
        </div>
        <div v-else-if="latest.download && latest.kind === 'quick'">
          <dt class="text-text-muted text-xs">{{ t('speed.upload') }}</dt>
          <dd class="text-text-muted mt-2 text-sm" data-testid="download-only">
            {{ t('speed.downloadOnly') }}
          </dd>
        </div>
        <div v-if="latest.latency">
          <dt class="text-text-muted text-xs">{{ t('speed.latency') }}</dt>
          <dd class="font-heading mt-1 leading-none font-semibold tabular-nums">
            <span class="text-[2.75rem]">{{ latest.latency.avg_ms?.toFixed(1) ?? '—' }}</span>
            <span class="text-text-muted ml-1.5 text-base font-medium">ms</span>
          </dd>
          <dd class="text-text-muted mt-2 text-xs">
            {{ t('speed.jitter') }} {{ ms(latest.latency.jitter_ms) }} · {{ t('diagnostics.loss') }}
            {{ latest.latency.loss_percent.toFixed(0) }}%
          </dd>
        </div>
        <div v-if="latest.source_ip">
          <dt class="text-text-muted text-xs">{{ t('speed.sourceIp') }}</dt>
          <dd class="mt-2"><IpCell :addr="latest.source_ip" /></dd>
        </div>
      </dl>
      <svg
        v-if="latest.download && latest.download.buckets_mbps.length > 1"
        viewBox="0 0 320 56"
        class="h-14 w-full max-w-xl"
        role="img"
        :aria-label="t('speed.download')"
      >
        <polyline
          :points="spark(latest.download.buckets_mbps)"
          fill="none"
          stroke="var(--chart-in)"
          stroke-width="2"
        />
      </svg>
      <div v-if="latest.candidates.length > 1" class="flex flex-col gap-2">
        <p class="text-text-muted text-xs">{{ t('speed.candidates') }}</p>
        <ul class="flex flex-wrap gap-2">
          <li
            v-for="c in latest.candidates"
            :key="c.id"
            class="rounded-full px-3 py-1 text-xs"
            :class="
              c.id === latest.server.id
                ? 'bg-brand/15 text-brand-fg font-medium'
                : c.latency_ms === undefined
                  ? 'bg-surface-2 text-text-muted/70 line-through'
                  : 'bg-surface-2 text-text-muted'
            "
          >
            {{ c.name }} ·
            {{ c.latency_ms === undefined ? t('speed.noAnswer') : ms(c.latency_ms) }}
          </li>
        </ul>
      </div>
    </div>

    <!-- Earlier results: plain rows -->
    <ul v-if="older.length > 0" class="divide-hairline divide-y text-sm">
      <li
        v-for="(result, index) in older"
        :key="result.started_unix_ms + '-' + index"
        class="flex flex-wrap items-baseline gap-x-6 gap-y-1 py-3"
      >
        <span class="font-medium">{{ result.server.name }}</span>
        <span class="text-text-muted text-xs">{{ when(result) }}</span>
        <span class="text-text-muted text-xs">{{ t(`speed.kinds.${result.kind}`) }}</span>
        <span v-if="result.download" class="ml-auto font-mono"
          >↓ {{ rate(result.download.avg_mbps).n }} {{ rate(result.download.avg_mbps).unit }}</span
        >
        <span v-if="result.upload" class="font-mono"
          >↑ {{ rate(result.upload.avg_mbps).n }} {{ rate(result.upload.avg_mbps).unit }}</span
        >
        <span v-if="result.latency" class="text-text-muted font-mono">{{
          ms(result.latency.avg_ms)
        }}</span>
      </li>
    </ul>
    <p v-if="speed.results.length === 0 && !speed.running" class="text-text-muted text-sm">
      {{ t('speed.empty') }}
    </p>
  </section>
</template>

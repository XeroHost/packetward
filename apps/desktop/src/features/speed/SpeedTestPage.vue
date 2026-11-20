<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// Speed test: a start bar, the live rate while it runs (the number is the page), and the latest
// result as a hero with the older ones as plain rows.
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Square, TriangleAlert } from '@/components/pw/icons'
import IpCell from '@/components/pw/IpCell.vue'
import { Button } from '@/components/ui/button'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { useSpeedStore } from '@/stores/speed'
import type { SpeedKind } from '@/types/generated/SpeedKind'
import type { SpeedResultView } from '@/types/generated/SpeedResultView'

const { t } = useI18n()
const speed = useSpeedStore()

const streams = ref(4)
const confirm50 = ref(false)

const serversText = computed({
  get: () => speed.servers,
  set: (value: string) => speed.setServers(value),
})

function run(kind: SpeedKind): void {
  void speed.start({
    kind,
    streams: Math.min(16, Math.max(1, Math.floor(streams.value) || 4)),
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

function mbps(value: number | undefined): string {
  if (value === undefined) return '—'
  return value >= 1000 ? `${(value / 1000).toFixed(2)} Gbps` : `${value.toFixed(1)} Mbps`
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
</script>

<template>
  <section class="flex max-w-[64rem] flex-col gap-12">
    <div class="flex flex-col gap-5">
      <div>
        <h2 :class="sectionTitle">{{ t('speed.title') }}</h2>
        <p class="text-text-muted mt-1 max-w-prose text-[13px] leading-relaxed">
          {{ t('speed.hint') }}
        </p>
      </div>

      <div class="flex flex-wrap items-end gap-3">
        <label class="flex min-w-72 flex-1 flex-col gap-1.5 text-sm">
          <span class="text-text-muted text-xs">{{ t('speed.servers') }}</span>
          <textarea
            v-model="serversText"
            :class="[FIELD, 'h-16 py-2 font-mono']"
            spellcheck="false"
            :disabled="speed.running"
            placeholder="https://speed.example.com:443"
          />
        </label>
        <label class="flex w-24 flex-col gap-1.5 text-sm">
          <span class="text-text-muted text-xs">{{ t('speed.streams') }}</span>
          <input
            v-model.number="streams"
            :class="FIELD"
            type="number"
            min="1"
            max="16"
            :disabled="speed.running"
          />
        </label>
      </div>
      <p class="text-text-muted -mt-2 text-xs">{{ t('speed.serversHint') }}</p>

      <div class="flex flex-wrap items-center gap-2">
        <Button v-if="!speed.running" @click="run('quick')">{{ t('speed.kinds.quick') }}</Button>
        <Button v-if="!speed.running" variant="outline" @click="run('bin1')">{{
          t('speed.kinds.bin1')
        }}</Button>
        <Button v-if="!speed.running" variant="outline" @click="run('bin10')">{{
          t('speed.kinds.bin10')
        }}</Button>
        <Button
          v-if="!speed.running"
          variant="outline"
          :disabled="!confirm50"
          @click="run('bin50')"
        >
          {{ t('speed.kinds.bin50') }}
        </Button>
        <Button v-else variant="destructive" @click="speed.cancel()">
          <Square aria-hidden="true" />{{ t('speed.cancel') }}
        </Button>
      </div>
      <label class="flex max-w-prose items-start gap-2 text-[13px]">
        <input v-model="confirm50" type="checkbox" class="mt-1" :disabled="speed.running" />
        <span class="text-text-muted">{{ t('speed.confirm50') }}</span>
      </label>
      <p v-if="speed.rejected.length > 0" class="pw-note" data-tone="warning">
        {{ t('speed.rejected') }} {{ speed.rejected.join('; ') }}
      </p>
      <p v-if="speed.failure" class="pw-note" data-tone="danger" role="alert">
        <TriangleAlert class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <span>
          {{
            t(`speed.errors.${speed.failure.code}`, { retry: speed.failure.retryAfterSecs ?? 0 })
          }}
          <span class="text-text-muted block">{{ speed.failure.message }}</span>
        </span>
      </p>
    </div>

    <!-- Live: the rate is the page -->
    <div v-if="speed.running" class="pw-appear flex flex-col gap-5" role="status">
      <p class="text-text-muted text-sm">
        {{ speed.running && speed.phase ? t(`speed.phases.${speed.phase}`) : t('speed.running') }}
      </p>
      <template v-if="speed.bin">
        <p class="font-heading text-[3.5rem] leading-none font-semibold tabular-nums">
          {{ mbps(speed.bin.mbps) }}
        </p>
        <progress class="w-full max-w-xl" :value="speed.bin.done" :max="speed.bin.total" />
        <p class="text-text-muted font-mono text-xs">
          {{ gib(speed.bin.done) }} / {{ gib(speed.bin.total) }} — {{ t('speed.avg') }}
          {{ mbps(speed.bin.avg) }}
        </p>
      </template>
      <div v-if="speed.down.length > 1 || speed.up.length > 1" class="grid gap-8 sm:grid-cols-2">
        <div v-if="speed.down.length > 1">
          <p class="text-text-muted text-xs">{{ t('speed.download') }}</p>
          <p class="font-heading mt-1 text-[2.5rem] leading-none font-semibold tabular-nums">
            {{ mbps(speed.down.at(-1)) }}
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
            {{ mbps(speed.up.at(-1)) }}
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
          <dd class="font-heading mt-1 text-[2.75rem] leading-none font-semibold tabular-nums">
            {{ mbps(latest.download.avg_mbps) }}
          </dd>
          <dd class="text-text-muted mt-2 text-xs">
            {{ t('speed.peak') }} {{ mbps(latest.download.peak_mbps) }} ·
            {{ latest.download.streams }} {{ t('speed.streamsShort') }}
          </dd>
        </div>
        <div v-if="latest.upload">
          <dt class="text-text-muted text-xs">{{ t('speed.upload') }}</dt>
          <dd class="font-heading mt-1 text-[2.75rem] leading-none font-semibold tabular-nums">
            {{ mbps(latest.upload.avg_mbps) }}
          </dd>
          <dd class="text-text-muted mt-2 text-xs">
            {{ t('speed.peak') }} {{ mbps(latest.upload.peak_mbps) }}
          </dd>
        </div>
        <div v-if="latest.latency">
          <dt class="text-text-muted text-xs">{{ t('speed.latency') }}</dt>
          <dd class="font-heading mt-1 text-[2.75rem] leading-none font-semibold tabular-nums">
            {{ ms(latest.latency.avg_ms) }}
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
      <p v-if="latest.candidates.length > 1" class="text-text-muted text-xs">
        {{ t('speed.candidates') }}
        {{
          latest.candidates
            .map((c) => `${c.name} ${c.latency_ms === undefined ? '✗' : ms(c.latency_ms)}`)
            .join(' · ')
        }}
      </p>
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
          >↓ {{ mbps(result.download.avg_mbps) }}</span
        >
        <span v-if="result.upload" class="font-mono">↑ {{ mbps(result.upload.avg_mbps) }}</span>
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

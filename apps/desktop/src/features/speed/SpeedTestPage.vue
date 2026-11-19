<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Gauge, Square, TriangleAlert } from 'lucide-vue-next'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
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

const card = 'bg-surface border-border flex flex-col gap-3 rounded-lg border p-[var(--card-p)]'
</script>

<template>
  <section class="flex flex-col gap-4">
    <div :class="card" style="box-shadow: var(--shadow-card)">
      <div class="flex items-center gap-3">
        <Gauge class="text-brand-fg size-5" aria-hidden="true" />
        <h2 class="text-base">{{ t('speed.title') }}</h2>
      </div>
      <p class="text-text-muted text-sm">{{ t('speed.hint') }}</p>
      <label class="flex flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('speed.servers') }}</span>
        <textarea
          v-model="serversText"
          :class="[FIELD, 'h-20 py-2 font-mono']"
          spellcheck="false"
          :disabled="speed.running"
          placeholder="https://speed.example.com:443"
        />
        <span class="text-text-muted text-xs">{{ t('speed.serversHint') }}</span>
      </label>
      <div class="flex flex-wrap items-end gap-3">
        <label class="flex w-28 flex-col gap-1 text-sm">
          <span class="text-text-muted">{{ t('speed.streams') }}</span>
          <input
            v-model.number="streams"
            :class="FIELD"
            type="number"
            min="1"
            max="16"
            :disabled="speed.running"
          />
        </label>
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
      <label class="flex items-start gap-2 text-sm">
        <input v-model="confirm50" type="checkbox" class="mt-1" :disabled="speed.running" />
        <span>{{ t('speed.confirm50') }}</span>
      </label>
      <p v-if="speed.rejected.length > 0" class="text-warning text-sm">
        {{ t('speed.rejected') }} {{ speed.rejected.join('; ') }}
      </p>
      <p
        v-if="speed.failure"
        class="border-danger/40 bg-danger/10 flex items-start gap-2 rounded-md border p-3 text-sm"
        role="alert"
      >
        <TriangleAlert class="text-danger mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <span>
          {{
            t(`speed.errors.${speed.failure.code}`, { retry: speed.failure.retryAfterSecs ?? 0 })
          }}
          <span class="text-text-muted block">{{ speed.failure.message }}</span>
        </span>
      </p>
    </div>

    <div v-if="speed.running" :class="card" style="box-shadow: var(--shadow-card)" role="status">
      <h2 class="text-base">{{ t('speed.running') }}</h2>
      <p class="text-text-muted text-sm">
        {{ speed.phase ? t(`speed.phases.${speed.phase}`) : '…' }}
      </p>
      <template v-if="speed.bin">
        <progress class="w-full" :value="speed.bin.done" :max="speed.bin.total" />
        <p class="font-mono text-sm">
          {{ gib(speed.bin.done) }} / {{ gib(speed.bin.total) }} — {{ mbps(speed.bin.mbps) }} ({{
            t('speed.avg')
          }}
          {{ mbps(speed.bin.avg) }})
        </p>
      </template>
      <div v-if="speed.down.length > 1 || speed.up.length > 1" class="grid gap-3 sm:grid-cols-2">
        <div v-if="speed.down.length > 1">
          <p class="text-text-muted text-xs">
            {{ t('speed.download') }} · {{ mbps(speed.down.at(-1)) }}
          </p>
          <svg
            viewBox="0 0 320 56"
            class="h-14 w-full"
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
          <p class="text-text-muted text-xs">
            {{ t('speed.upload') }} · {{ mbps(speed.up.at(-1)) }}
          </p>
          <svg viewBox="0 0 320 56" class="h-14 w-full" role="img" :aria-label="t('speed.upload')">
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

    <div
      v-for="(result, index) in speed.results"
      :key="result.started_unix_ms + '-' + index"
      :class="card"
      style="box-shadow: var(--shadow-card)"
    >
      <div class="flex flex-wrap items-center gap-2">
        <h2 class="text-base">{{ result.server.name }}</h2>
        <span v-if="result.server.location" class="text-text-muted text-sm">{{
          result.server.location
        }}</span>
        <span class="text-text-muted ml-auto text-xs"
          >{{ t(`speed.kinds.${result.kind}`) }} · {{ when(result) }}</span
        >
      </div>
      <dl class="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <div v-if="result.download">
          <dt class="text-text-muted">{{ t('speed.download') }}</dt>
          <dd class="font-mono text-lg">{{ mbps(result.download.avg_mbps) }}</dd>
          <dd class="text-text-muted text-xs">
            {{ t('speed.peak') }} {{ mbps(result.download.peak_mbps) }} ·
            {{ result.download.streams }} {{ t('speed.streamsShort') }}
          </dd>
        </div>
        <div v-if="result.upload">
          <dt class="text-text-muted">{{ t('speed.upload') }}</dt>
          <dd class="font-mono text-lg">{{ mbps(result.upload.avg_mbps) }}</dd>
          <dd class="text-text-muted text-xs">
            {{ t('speed.peak') }} {{ mbps(result.upload.peak_mbps) }}
          </dd>
        </div>
        <div v-if="result.latency">
          <dt class="text-text-muted">{{ t('speed.latency') }}</dt>
          <dd class="font-mono text-lg">{{ ms(result.latency.avg_ms) }}</dd>
          <dd class="text-text-muted text-xs">
            {{ t('speed.jitter') }} {{ ms(result.latency.jitter_ms) }} · {{ t('diagnostics.loss') }}
            {{ result.latency.loss_percent.toFixed(0) }}%
          </dd>
        </div>
        <div v-if="result.source_ip">
          <dt class="text-text-muted">{{ t('speed.sourceIp') }}</dt>
          <dd><IpCell :addr="result.source_ip" /></dd>
        </div>
      </dl>
      <div v-if="result.download && result.download.buckets_mbps.length > 1">
        <svg viewBox="0 0 320 56" class="h-14 w-full" role="img" :aria-label="t('speed.download')">
          <polyline
            :points="spark(result.download.buckets_mbps)"
            fill="none"
            stroke="var(--chart-in)"
            stroke-width="2"
          />
        </svg>
      </div>
      <p v-if="result.candidates.length > 1" class="text-text-muted text-xs">
        {{ t('speed.candidates') }}
        {{
          result.candidates
            .map((c) => `${c.name} ${c.latency_ms === undefined ? '✗' : ms(c.latency_ms)}`)
            .join(' · ')
        }}
      </p>
    </div>
    <p v-if="speed.results.length === 0 && !speed.running" class="text-text-muted text-sm">
      {{ t('speed.empty') }}
    </p>
  </section>
</template>

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { useIntervalFn } from '@vueuse/core'
import { ExternalLink, Play, Square } from 'lucide-vue-next'
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { openExternal } from '@/api/links'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useAppVisible } from '@/lib/visibility'
import { useCaptureStore } from '@/stores/capture'
import FailureNote from '@/features/diagnostics/FailureNote.vue'
import RecordPanel from './RecordPanel.vue'
import SupportBundlePanel from './SupportBundlePanel.vue'

const { t } = useI18n()
const capture = useCaptureStore()
const visible = useAppVisible()

const status = computed(() => capture.status)
const running = computed(() => status.value?.state === 'running')
const backends = computed(() =>
  status.value ? [status.value.selection.npcap, status.value.selection.raw_socket] : [],
)

// Counters and the recording progress move; poll while the page is open and the window is shown.
const { pause, resume } = useIntervalFn(() => void capture.refresh(), 2000, { immediate: false })
onMounted(() => {
  void capture.refresh()
  if (visible.value) resume()
  else pause()
})

const card = 'bg-surface border-border flex flex-col gap-3 rounded-lg border p-[var(--card-p)]'
</script>

<template>
  <section class="flex flex-col gap-4">
    <FailureNote v-if="capture.error" :failure="capture.error" />

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <h2 class="text-base">{{ t('capture.backend.title') }}</h2>
        <Button
          v-if="!running"
          :disabled="capture.busy || status?.selection.selected === undefined"
          @click="capture.start()"
        >
          <Play aria-hidden="true" />{{ t('capture.live.start') }}
        </Button>
        <Button v-else variant="outline" :disabled="capture.busy" @click="capture.stop()">
          <Square aria-hidden="true" />{{ t('capture.live.stop') }}
        </Button>
      </div>
      <p v-if="status" class="text-sm">{{ status.selection.summary }}</p>
      <ul class="flex flex-col gap-2">
        <li
          v-for="backend in backends"
          :key="backend.kind"
          class="border-border flex flex-wrap items-center gap-2 rounded-md border p-3 text-sm"
        >
          <span class="font-medium">{{ t(`capture.backend.kinds.${backend.kind}`) }}</span>
          <Badge
            variant="outline"
            :class="backend.available ? 'border-success/50 text-success' : 'text-text-muted'"
          >
            {{ backend.available ? t('capture.backend.available') : t('capture.backend.missing') }}
          </Badge>
          <Badge v-if="status?.selection.selected === backend.kind" variant="outline">
            {{ t('capture.backend.inUse') }}
          </Badge>
          <span v-if="backend.available" class="text-text-muted">
            {{ backend.bpf ? t('capture.backend.bpf') : t('capture.backend.noBpf') }} ·
            {{
              backend.sees_outbound
                ? t('capture.backend.seesOut')
                : t('capture.backend.inboundOnly')
            }}
          </span>
          <span v-else-if="backend.reason" class="text-text-muted">{{ backend.reason }}</span>
        </li>
      </ul>
      <ul v-if="status && status.selection.missing.length > 0" class="flex flex-col gap-1 text-sm">
        <li v-for="item in status.selection.missing" :key="item.kind" class="text-text-muted">
          {{ item.message }}
          <button
            v-if="item.install_url"
            type="button"
            class="text-brand-fg inline-flex items-center gap-1 underline"
            @click="openExternal(item.install_url)"
          >
            {{ item.install_url }}<ExternalLink class="size-3" aria-hidden="true" />
          </button>
        </li>
      </ul>
      <p class="text-text-muted text-xs">{{ t('capture.backend.licenseNote') }}</p>

      <dl v-if="status" class="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <div>
          <dt class="text-text-muted">{{ t('capture.live.state') }}</dt>
          <dd>{{ t(`capture.live.states.${status.state}`) }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('capture.live.adapter') }}</dt>
          <dd class="font-mono break-all">{{ status.interface ?? '—' }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('capture.live.seen') }}</dt>
          <dd class="font-mono">{{ status.counters.received }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('capture.live.dropped') }}</dt>
          <dd class="font-mono" :class="status.counters.dropped > 0 ? 'text-warning' : ''">
            {{ status.counters.dropped }}
          </dd>
        </div>
      </dl>
      <p v-if="status?.error" class="text-danger text-sm" role="alert">{{ status.error }}</p>
      <p v-if="status?.blind" class="text-warning text-sm" role="alert">
        {{ t('traffic.blind') }}
      </p>
    </div>

    <RecordPanel />
    <SupportBundlePanel />
  </section>
</template>

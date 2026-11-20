<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// Capture: the state of the live capture is the headline (with its one action), the two backends
// sit side by side as quiet wells, and recording and the support bundle follow as sections.
import { useIntervalFn } from '@vueuse/core'
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { openExternal } from '@/api/links'
import { ExternalLink, Play, Square } from '@/components/pw/icons'
import { Button } from '@/components/ui/button'
import FailureNote from '@/features/diagnostics/FailureNote.vue'
import { useAppVisible } from '@/lib/visibility'
import { useCaptureStore } from '@/stores/capture'
import { useLogsStore } from '@/stores/logs'
import RecordPanel from './RecordPanel.vue'
import SupportBundlePanel from './SupportBundlePanel.vue'

const { t } = useI18n()
const capture = useCaptureStore()
const visible = useAppVisible()
const logs = useLogsStore()

const status = computed(() => capture.status)
const running = computed(() => status.value?.state === 'running')
const backends = computed(() =>
  status.value ? [status.value.selection.npcap, status.value.selection.raw_socket] : [],
)

// Counters and the recording progress move; poll while the page is open and the window is shown.
const { pause, resume } = useIntervalFn(() => void capture.refresh(), 2000, { immediate: false })
onMounted(() => {
  void logs.loadSettings()
  void capture.refresh()
  if (visible.value) resume()
  else pause()
})
</script>

<template>
  <section class="flex max-w-[64rem] flex-col gap-(--section-gap)">
    <FailureNote v-if="capture.error" :failure="capture.error" />

    <div class="flex flex-col gap-7">
      <div class="flex flex-wrap items-start justify-between gap-6">
        <div class="min-w-0">
          <h2 class="text-[1.0625rem] font-semibold">{{ t('capture.backend.title') }}</h2>
          <p v-if="status" class="text-text-muted mt-1 max-w-prose text-[13px] leading-relaxed">
            {{ status.selection.summary }}
          </p>
          <p
            v-if="logs.settings && !logs.settings.capture_on_start"
            class="text-text-muted mt-1 max-w-prose text-xs"
            data-testid="capture-start-note"
          >
            {{ t('capture.live.notOnStart') }}
          </p>
        </div>
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

      <dl
        v-if="status"
        class="border-hairline grid grid-cols-2 gap-y-5 border-y py-6 sm:grid-cols-4"
      >
        <div class="pr-5">
          <dt class="text-text-muted text-xs">{{ t('capture.live.state') }}</dt>
          <dd class="font-heading mt-1 text-xl font-semibold" :class="running && 'text-success'">
            {{ t(`capture.live.states.${status.state}`) }}
          </dd>
        </div>
        <div class="border-hairline border-l px-5">
          <dt class="text-text-muted text-xs">{{ t('capture.live.adapter') }}</dt>
          <dd class="mt-1.5 font-mono text-[13px] break-all">{{ status.interface ?? '—' }}</dd>
        </div>
        <div class="border-hairline border-l px-5 max-sm:!border-l-0 max-sm:!pl-0">
          <dt class="text-text-muted text-xs">{{ t('capture.live.seen') }}</dt>
          <dd class="font-heading mt-1 text-xl font-semibold">{{ status.counters.received }}</dd>
        </div>
        <div class="border-hairline border-l pl-5">
          <dt class="text-text-muted text-xs">{{ t('capture.live.dropped') }}</dt>
          <dd
            class="font-heading mt-1 text-xl font-semibold"
            :class="status.counters.dropped > 0 && 'text-warning'"
          >
            {{ status.counters.dropped }}
          </dd>
        </div>
      </dl>

      <p v-if="status?.error" class="pw-note" data-tone="danger" role="alert">{{ status.error }}</p>
      <p v-if="status?.blind" class="pw-note" data-tone="warning" role="alert">
        {{ t('traffic.blind') }}
      </p>

      <ul class="grid gap-3 md:grid-cols-2">
        <li v-for="backend in backends" :key="backend.kind" class="pw-well flex flex-col gap-1.5">
          <div class="flex items-center justify-between gap-2">
            <span class="font-medium">{{ t(`capture.backend.kinds.${backend.kind}`) }}</span>
            <span
              class="text-xs font-medium"
              :class="backend.available ? 'text-success' : 'text-text-muted'"
            >
              {{
                status?.selection.selected === backend.kind
                  ? t('capture.backend.inUse')
                  : backend.available
                    ? t('capture.backend.available')
                    : t('capture.backend.missing')
              }}
            </span>
          </div>
          <p v-if="backend.available" class="text-text-muted text-[13px]">
            {{ backend.bpf ? t('capture.backend.bpf') : t('capture.backend.noBpf') }} ·
            {{
              backend.sees_outbound
                ? t('capture.backend.seesOut')
                : t('capture.backend.inboundOnly')
            }}
          </p>
          <p v-else-if="backend.reason" class="text-text-muted text-[13px]">{{ backend.reason }}</p>
        </li>
      </ul>

      <ul v-if="status && status.selection.missing.length > 0" class="flex flex-col gap-1 text-sm">
        <li v-for="item in status.selection.missing" :key="item.kind" class="text-text-muted">
          {{ item.message }}
          <button
            v-if="item.install_url"
            type="button"
            class="text-brand-fg inline-flex items-center gap-1 underline underline-offset-4"
            @click="openExternal(item.install_url)"
          >
            {{ item.install_url }}<ExternalLink class="size-3" aria-hidden="true" />
          </button>
        </li>
      </ul>
      <p class="text-text-muted text-xs">{{ t('capture.backend.licenseNote') }}</p>
    </div>

    <RecordPanel />
    <SupportBundlePanel />
  </section>
</template>

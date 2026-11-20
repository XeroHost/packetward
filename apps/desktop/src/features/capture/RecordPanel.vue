<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Circle, Square, Trash2 } from '@/components/pw/icons'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { copyText } from '@/lib/clipboard'
import { useCaptureStore } from '@/stores/capture'
import type { PayloadView } from '@/types/generated/PayloadView'
import type { RecordModeView } from '@/types/generated/RecordModeView'
import FailureNote from '@/features/diagnostics/FailureNote.vue'
import { FIELD } from '@/features/diagnostics/fieldClass'

const { t } = useI18n()
const capture = useCaptureStore()

const name = ref('capture')
const mode = ref<RecordModeView>('timed')
const duration = ref(60)
const filter = ref('')
const payload = ref<PayloadView>('headers')
const confirmFull = ref(false)
/** The file waiting for the user to confirm its deletion. */
const pendingDelete = ref<string | null>(null)

const recording = computed(() => capture.status?.recording ?? null)
const running = computed(() => recording.value?.running === true)
const canStart = computed(
  () =>
    !running.value &&
    !capture.busy &&
    name.value.trim() !== '' &&
    (payload.value === 'headers' || confirmFull.value),
)

function start(): void {
  if (!canStart.value) return
  void capture.record({
    name: name.value.trim(),
    mode: mode.value,
    duration_secs:
      mode.value === 'timed' ? Math.max(1, Math.floor(duration.value) || 60) : undefined,
    filter: filter.value.trim() === '' ? undefined : filter.value.trim(),
    payload: payload.value,
    confirm_full_payload: payload.value === 'full' && confirmFull.value,
  })
}

function megabytes(bytes: number): string {
  return `${(bytes / 1_000_000).toFixed(bytes < 100_000 ? 3 : 1)} MB`
}

async function confirmDelete(file: string): Promise<void> {
  pendingDelete.value = null
  await capture.removeFile(file)
}

onMounted(() => void capture.loadFiles())

const card = 'flex flex-col gap-4'
</script>

<template>
  <div :class="card">
    <h2 class="text-[1.0625rem] font-semibold">{{ t('capture.record.title') }}</h2>
    <p class="text-text-muted text-sm">{{ t('capture.record.hint') }}</p>

    <form class="flex flex-wrap items-end gap-3" @submit.prevent="start">
      <label class="flex w-44 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('capture.record.name') }}</span>
        <input v-model="name" :class="FIELD" type="text" :disabled="running" />
      </label>
      <label class="flex w-40 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('capture.record.mode') }}</span>
        <select v-model="mode" :class="FIELD" :disabled="running">
          <option value="timed">{{ t('capture.record.modes.timed') }}</option>
          <option value="ring">{{ t('capture.record.modes.ring') }}</option>
        </select>
      </label>
      <label v-if="mode === 'timed'" class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('capture.record.seconds') }}</span>
        <input
          v-model.number="duration"
          :class="FIELD"
          type="number"
          min="1"
          max="3600"
          :disabled="running"
        />
      </label>
      <label class="flex min-w-56 flex-1 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('capture.record.filter') }}</span>
        <input
          v-model="filter"
          :class="[FIELD, 'font-mono']"
          type="text"
          spellcheck="false"
          placeholder="tcp and port 3389"
          :disabled="running"
        />
      </label>
      <label class="flex w-48 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('capture.record.payload') }}</span>
        <select v-model="payload" :class="FIELD" :disabled="running">
          <option value="headers">{{ t('capture.record.payloads.headers') }}</option>
          <option value="full">{{ t('capture.record.payloads.full') }}</option>
        </select>
      </label>
      <Button v-if="!running" type="submit" :disabled="!canStart">
        <Circle aria-hidden="true" />{{ t('capture.record.start') }}
      </Button>
      <Button v-else type="button" variant="outline" @click="capture.stopRecord()">
        <Square aria-hidden="true" />{{ t('capture.record.stop') }}
      </Button>
    </form>

    <label v-if="payload === 'full'" class="pw-note flex items-start gap-2" data-tone="warning">
      <input v-model="confirmFull" type="checkbox" class="mt-1" :disabled="running" />
      <span>{{ t('capture.record.fullWarning') }}</span>
    </label>
    <p v-if="mode === 'ring'" class="text-text-muted text-xs">{{ t('capture.record.ringNote') }}</p>

    <p v-if="recording" class="text-sm" role="status">
      <template v-if="recording.running">
        {{
          t('capture.record.running', {
            packets: recording.packets_written,
            size: megabytes(recording.bytes_written),
          })
        }}
      </template>
      <template v-else-if="recording.result">
        {{
          t('capture.record.finished', {
            packets: recording.result.packets,
            reason: t(`capture.record.reasons.${recording.result.reason}`),
          })
        }}
        <span v-if="recording.result.error" class="text-danger">{{ recording.result.error }}</span>
      </template>
    </p>

    <h3 class="text-sm font-medium">{{ t('capture.files.title') }}</h3>
    <FailureNote v-if="capture.filesError" :failure="capture.filesError" />
    <p class="text-text-muted text-xs">
      {{ t('capture.files.where') }}
      <button
        type="button"
        class="text-text font-mono underline"
        :title="t('common.copy')"
        @click="copyText(capture.filesDir)"
      >
        {{ capture.filesDir }}
      </button>
      — {{ t('capture.files.retention') }}
    </p>
    <ul v-if="capture.files.length > 0" class="divide-hairline divide-y text-sm">
      <li
        v-for="file in capture.files"
        :key="file.name"
        class="flex flex-wrap items-center gap-3 px-3 py-2"
      >
        <span class="min-w-0 flex-1 truncate font-mono">{{ file.name }}</span>
        <span class="text-text-muted font-mono">{{ megabytes(file.bytes) }}</span>
        <span class="text-text-muted">{{ new Date(file.modified_unix_ms).toLocaleString() }}</span>
        <template v-if="pendingDelete === file.name">
          <span class="text-warning">{{ t('capture.files.confirm') }}</span>
          <Button size="xs" variant="destructive" @click="confirmDelete(file.name)">
            {{ t('capture.files.delete') }}
          </Button>
          <Button size="xs" variant="outline" @click="pendingDelete = null">
            {{ t('capture.files.cancel') }}
          </Button>
        </template>
        <Button
          v-else
          size="icon-xs"
          variant="ghost"
          :disabled="running"
          :aria-label="t('capture.files.deleteFile', { name: file.name })"
          @click="pendingDelete = file.name"
        >
          <Trash2 aria-hidden="true" />
        </Button>
      </li>
    </ul>
    <p v-else class="text-text-muted text-sm">{{ t('capture.files.empty') }}</p>
  </div>
</template>

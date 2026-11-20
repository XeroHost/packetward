<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { FileArchive, Save } from '@/components/pw/icons'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { copyText } from '@/lib/clipboard'
import { useCaptureStore } from '@/stores/capture'
import type { SupportBundleRequest } from '@/types/generated/SupportBundleRequest'
import FailureNote from '@/features/diagnostics/FailureNote.vue'
import { FIELD } from '@/features/diagnostics/fieldClass'

const { t } = useI18n()
const capture = useCaptureStore()

const anonymize = ref(false)
const includeLogs = ref(true)
const captureSecs = ref(30)

const request = computed<SupportBundleRequest>(() => ({
  anonymize_local_ips: anonymize.value,
  include_logs: includeLogs.value,
  capture_secs: anonymize.value
    ? 0
    : Math.min(120, Math.max(0, Math.floor(captureSecs.value) || 0)),
}))

// Any change of the options invalidates what was previewed.
watch(request, () => {
  capture.bundlePreview = null
  capture.bundleSaved = null
})

function size(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`
}

const card = 'flex flex-col gap-4'
</script>

<template>
  <div :class="card">
    <h2 class="text-[1.0625rem] font-semibold">{{ t('capture.bundle.title') }}</h2>
    <p class="text-text-muted text-sm">{{ t('capture.bundle.hint') }}</p>

    <div class="flex flex-wrap items-end gap-4">
      <label class="flex items-center gap-2 text-sm">
        <input v-model="anonymize" type="checkbox" />
        {{ t('capture.bundle.anonymize') }}
      </label>
      <label class="flex items-center gap-2 text-sm">
        <input v-model="includeLogs" type="checkbox" />
        {{ t('capture.bundle.logs') }}
      </label>
      <label class="flex w-40 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('capture.bundle.captureSecs') }}</span>
        <input
          v-model.number="captureSecs"
          :class="FIELD"
          type="number"
          min="0"
          max="120"
          :disabled="anonymize"
        />
      </label>
      <Button variant="outline" @click="capture.previewBundle(request)">
        <FileArchive aria-hidden="true" />{{ t('capture.bundle.preview') }}
      </Button>
    </div>
    <p v-if="anonymize" class="text-text-muted text-xs">{{ t('capture.bundle.anonymizeNote') }}</p>

    <FailureNote v-if="capture.bundleError" :failure="capture.bundleError" />

    <div v-if="capture.bundlePreview" class="flex flex-col gap-2">
      <p v-if="anonymize" class="text-sm">
        {{ t('capture.bundle.hidden', { count: capture.bundlePreview.local_addrs_hidden }) }}
      </p>
      <ul class="flex flex-col gap-2">
        <li
          v-for="item in capture.bundlePreview.items"
          :key="item.name"
          class="bg-surface-2 rounded-[12px] text-sm"
        >
          <details>
            <summary class="flex cursor-pointer flex-wrap items-center gap-2 px-3 py-2">
              <span class="font-mono">{{ item.name }}</span>
              <span class="text-text-muted">{{ item.description }}</span>
              <span v-if="item.bytes > 0" class="text-text-muted ml-auto font-mono">{{
                size(item.bytes)
              }}</span>
            </summary>
            <pre
              v-if="item.sample"
              class="bg-surface-2 max-h-64 overflow-auto px-3 py-2 font-mono text-xs whitespace-pre-wrap"
              >{{ item.sample }}</pre>
            <p v-else class="text-text-muted px-3 py-2 text-xs">{{ t('capture.bundle.binary') }}</p>
          </details>
        </li>
      </ul>
      <div class="flex flex-wrap items-center gap-3">
        <Button :disabled="capture.bundleBusy" @click="capture.saveBundle(request)">
          <Save aria-hidden="true" />{{
            capture.bundleBusy ? t('capture.bundle.saving') : t('capture.bundle.save')
          }}
        </Button>
        <span class="text-text-muted text-xs">{{ t('capture.bundle.neverUploaded') }}</span>
      </div>
    </div>

    <p v-if="capture.bundleSaved" class="text-sm" role="status">
      {{ t('capture.bundle.saved') }}
      <button
        type="button"
        class="font-mono underline break-all"
        :title="t('common.copy')"
        @click="copyText(capture.bundleSaved.path)"
      >
        {{ capture.bundleSaved.path }}
      </button>
      <br />
      <span class="text-text-muted">{{ t('capture.bundle.attach') }}</span>
    </p>
  </div>
</template>

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// Minimize / maximize / close, drawn like the Windows ones (the window has no native frame).
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  closeWindow,
  isWindowMaximized,
  minimizeWindow,
  onWindowResized,
  toggleMaximizeWindow,
} from '@/api/window'

const { t } = useI18n()
const maximized = ref(false)
let unlisten: (() => void) | null = null

async function refresh(): Promise<void> {
  maximized.value = await isWindowMaximized()
}

onMounted(async () => {
  await refresh()
  unlisten = await onWindowResized(() => void refresh())
})
onBeforeUnmount(() => unlisten?.())

const button =
  'text-text-muted hover:bg-hairline hover:text-text flex h-full w-[46px] items-center justify-center transition-colors'
</script>

<template>
  <div class="flex h-full items-stretch">
    <button
      type="button"
      :class="button"
      :aria-label="t('window.minimize')"
      @click="minimizeWindow"
    >
      <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden="true">
        <path d="M0 5h10" stroke="currentColor" stroke-width="1" />
      </svg>
    </button>
    <button
      type="button"
      :class="button"
      :aria-label="maximized ? t('window.restore') : t('window.maximize')"
      @click="toggleMaximizeWindow"
    >
      <svg
        v-if="!maximized"
        width="10"
        height="10"
        viewBox="0 0 10 10"
        fill="none"
        aria-hidden="true"
      >
        <rect x="0.5" y="0.5" width="9" height="9" stroke="currentColor" stroke-width="1" />
      </svg>
      <svg v-else width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden="true">
        <path d="M2.5 2.5V0.5h7v7h-2" stroke="currentColor" stroke-width="1" />
        <rect x="0.5" y="2.5" width="7" height="7" stroke="currentColor" stroke-width="1" />
      </svg>
    </button>
    <button
      type="button"
      :class="[button, 'hover:!bg-danger hover:!text-on-brand']"
      :aria-label="t('window.close')"
      @click="closeWindow"
    >
      <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden="true">
        <path d="M0.5 0.5l9 9M9.5 0.5l-9 9" stroke="currentColor" stroke-width="1" />
      </svg>
    </button>
  </div>
</template>

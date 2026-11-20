<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import SettingRow from '@/components/pw/SettingRow.vue'
import { TriangleAlert } from '@/components/pw/icons'
import { onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { useLogsStore } from '@/stores/logs'

const { t } = useI18n()
const logs = useLogsStore()
const proxy = ref('')
const saved = ref(false)

onMounted(async () => {
  await logs.loadSettings()
})
watch(
  () => logs.settings?.proxy,
  (value) => {
    proxy.value = value ?? ''
  },
  { immediate: true },
)

async function save(): Promise<void> {
  saved.value = await logs.saveProxy(proxy.value)
}
</script>

<template>
  <SettingRow :title="t('settings.network.title')" :description="t('settings.network.description')">
    <form class="flex flex-wrap items-end gap-2" @submit.prevent="save">
      <label class="flex min-w-72 flex-1 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('settings.network.proxy') }}</span>
        <input
          v-model="proxy"
          :class="[FIELD, 'font-mono']"
          spellcheck="false"
          autocomplete="off"
          placeholder="http://proxy.example.com:3128"
        />
      </label>
      <Button type="submit" size="sm">{{ t('settings.network.save') }}</Button>
    </form>
    <p class="text-text-muted text-xs">{{ t('settings.network.hint') }}</p>
    <p v-if="saved && !logs.settingsError" class="text-sm" role="status">
      {{ t('settings.network.saved') }}
    </p>
    <p
      v-if="logs.settings?.restart_required"
      class="pw-note flex items-start gap-2"
      data-tone="warning"
      role="status"
    >
      <TriangleAlert class="text-warning mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{{ t('settings.network.restart') }}</span>
    </p>
    <p v-if="logs.settingsError" class="text-danger text-sm" role="alert">
      {{ logs.settingsError }}
    </p>
  </SettingRow>
</template>

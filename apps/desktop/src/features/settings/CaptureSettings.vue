<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
// Whether the live capture starts together with the agent. It writes nothing to disk and its memory is
// bounded, so it is on by default; turning it off is for machines where even that is unwanted.
import { onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import SettingRow from '@/components/pw/SettingRow.vue'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useLogsStore } from '@/stores/logs'

const { t } = useI18n()
const logs = useLogsStore()

onMounted(() => void logs.loadSettings())
</script>

<template>
  <SettingRow :title="t('settings.capture.title')" :description="t('settings.capture.description')">
    <div class="flex items-center gap-3">
      <Switch
        id="sw-capture-start"
        :model-value="logs.settings?.capture_on_start ?? true"
        :disabled="logs.settings === null"
        data-testid="capture-on-start"
        @update:model-value="(on: boolean) => logs.saveCaptureOnStart(on)"
      />
      <Label for="sw-capture-start">{{ t('settings.capture.label') }}</Label>
    </div>
    <p class="text-text-muted text-xs">{{ t('settings.capture.hint') }}</p>
    <p
      v-if="logs.settings && !logs.settings.capture_on_start"
      class="pw-note"
      data-tone="warning"
      role="status"
      data-testid="capture-off-note"
    >
      {{ t('settings.capture.offNote') }}
    </p>
    <p v-if="logs.settingsError" class="text-danger text-sm" role="alert">
      {{ logs.settingsError }}
    </p>
  </SettingRow>
</template>

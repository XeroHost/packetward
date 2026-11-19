<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import type { UpdateChannel } from '@/api/uiPrefs'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import { useSettingsStore } from '@/stores/settings'
import { useUpdateStore } from '@/stores/update'

const { t } = useI18n()
const settings = useSettingsStore()
const update = useUpdateStore()

onMounted(() => {
  void update.load()
})

async function onUpdateChannel(v: unknown): Promise<void> {
  if (typeof v !== 'string' || !v) return
  await settings.setUpdateChannel(v as UpdateChannel)
  // A result found on the other channel does not apply any more.
  update.reset()
}
</script>

<template>
  <!-- Updates -->
  <section
    class="bg-surface border-border flex flex-col gap-5 rounded-lg border p-[var(--card-p)]"
    style="box-shadow: var(--shadow-card)"
    aria-labelledby="updates-title"
  >
    <header>
      <h2 id="updates-title" class="text-base">{{ t('settings.updates.title') }}</h2>
      <p class="text-text-muted">{{ t('settings.updates.description') }}</p>
    </header>

    <div class="grid grid-cols-[12rem_1fr] items-center gap-x-4 gap-y-4">
      <Label>{{ t('settings.updates.currentVersion') }}</Label>
      <span class="font-mono" data-testid="update-current">{{
        update.info?.currentVersion ?? '…'
      }}</span>

      <Label id="lbl-channel">{{ t('settings.updates.channel') }}</Label>
      <div class="flex flex-col gap-1.5">
        <ToggleGroup
          type="single"
          variant="outline"
          aria-labelledby="lbl-channel"
          :model-value="settings.updates.channel"
          :disabled="!update.configured"
          @update:model-value="onUpdateChannel"
        >
          <ToggleGroupItem value="stable">{{ t('settings.updates.stable') }}</ToggleGroupItem>
          <ToggleGroupItem value="beta">{{ t('settings.updates.beta') }}</ToggleGroupItem>
        </ToggleGroup>
        <span class="text-text-muted text-xs">{{
          t(`settings.updates.${settings.updates.channel}Hint`)
        }}</span>
      </div>

      <Label for="sw-update-start">{{ t('settings.updates.checkOnStart') }}</Label>
      <div class="flex items-center gap-3">
        <Switch
          id="sw-update-start"
          :model-value="settings.updates.checkOnStart"
          :disabled="!update.configured"
          @update:model-value="(on: boolean) => settings.setCheckOnStart(on)"
        />
        <span class="text-text-muted text-xs">{{ t('settings.updates.checkOnStartHint') }}</span>
      </div>
    </div>

    <p
      v-if="update.status === 'notConfigured'"
      class="text-text-muted text-sm"
      role="status"
      data-testid="update-not-configured"
    >
      {{ t('settings.updates.notConfigured') }}
    </p>

    <div class="flex flex-wrap items-center gap-3">
      <Button
        variant="outline"
        size="sm"
        :disabled="!update.configured || update.busy"
        @click="update.check()"
      >
        {{
          update.status === 'checking'
            ? t('settings.updates.checking')
            : t('settings.updates.check')
        }}
      </Button>
      <Button
        v-if="update.status === 'available' || update.status === 'installing'"
        size="sm"
        :disabled="update.status === 'installing'"
        @click="update.install()"
      >
        {{
          update.status === 'installing'
            ? update.progress === null
              ? t('settings.updates.installing')
              : t('settings.updates.downloading', { percent: Math.round(update.progress * 100) })
            : t('settings.updates.install', { version: update.available?.version ?? '' })
        }}
      </Button>
      <span
        v-if="update.status === 'upToDate'"
        class="text-text-muted text-sm"
        role="status"
        data-testid="update-uptodate"
        >{{ t('settings.updates.upToDate') }}</span
      >
    </div>

    <div
      v-if="update.status === 'available' && update.available?.notes"
      class="bg-surface-2 text-text-muted max-h-40 overflow-auto rounded-md p-3 text-xs whitespace-pre-wrap"
    >
      {{ update.available.notes }}
    </div>
    <p v-if="update.status === 'error'" class="text-warning text-sm" role="alert">
      {{ t('settings.updates.error', { reason: update.error ?? '' }) }}
    </p>
    <p class="text-text-muted text-xs">{{ t('settings.updates.privacy') }}</p>
  </section>
</template>

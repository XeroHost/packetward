<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import SettingRow from '@/components/pw/SettingRow.vue'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { getAutostart, setAutostart } from '@/api/shell'
import type { Density, LanguageSetting, MonoFont, TextSize, ThemeSetting } from '@/api/uiPrefs'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import NetworkSettings from '@/features/settings/NetworkSettings.vue'
import { useAppearanceStore } from '@/stores/appearance'
import { useSettingsStore } from '@/stores/settings'
import UpdatesSettings from './UpdatesSettings.vue'

const { t } = useI18n()
const appearance = useAppearanceStore()
const settings = useSettingsStore()

const TEXT_SIZES: readonly TextSize[] = [90, 100, 110, 125]
const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const

const themeValue = computed(() => appearance.prefs.theme)

/** Toggle groups can emit nothing when the active item is clicked again; ignore that. */
function onTheme(v: unknown): void {
  if (typeof v !== 'string' || !v) return
  appearance.setTheme(v as ThemeSetting)
  void settings.persist()
}
function onDensity(v: unknown): void {
  if (typeof v !== 'string' || !v) return
  appearance.setDensity(v as Density)
  void settings.persist()
}
function onTextSize(v: unknown): void {
  if (typeof v !== 'string' || !v) return
  appearance.setTextSize(Number(v) as TextSize)
  void settings.persist()
}
function onMono(v: unknown): void {
  if (typeof v !== 'string' || !v) return
  appearance.setMonoFont(v as MonoFont)
  void settings.persist()
}
function onReduceMotion(v: boolean): void {
  appearance.setReduceMotion(v)
  void settings.persist()
}
const autostart = ref(false)
const autostartBusy = ref(false)
const autostartError = ref<string | null>(null)

onMounted(async () => {
  try {
    autostart.value = await getAutostart()
  } catch (err) {
    autostartError.value = String(err)
  }
})

async function onAutostart(enabled: boolean): Promise<void> {
  autostartBusy.value = true
  autostartError.value = null
  try {
    await setAutostart(enabled)
    autostart.value = enabled
  } catch (err) {
    // Keep the switch showing what is really registered.
    autostartError.value = String(err)
  } finally {
    autostartBusy.value = false
  }
}

function onLanguage(v: unknown): void {
  if (typeof v !== 'string' || !v) return
  void settings.setLanguage(v as LanguageSetting)
}
</script>

<template>
  <div class="flex max-w-[60rem] flex-col">
    <!-- Appearance -->
    <SettingRow
      :title="t('settings.appearance.title')"
      :description="t('settings.appearance.description')"
    >
      <div class="grid grid-cols-[12rem_1fr] items-center gap-x-4 gap-y-4">
        <Label id="lbl-theme">{{ t('settings.appearance.theme') }}</Label>
        <ToggleGroup
          type="single"
          variant="outline"
          aria-labelledby="lbl-theme"
          :model-value="themeValue"
          @update:model-value="onTheme"
        >
          <ToggleGroupItem value="dark">{{ t('settings.appearance.themeDark') }}</ToggleGroupItem>
          <ToggleGroupItem value="light">{{ t('settings.appearance.themeLight') }}</ToggleGroupItem>
          <ToggleGroupItem value="system">{{
            t('settings.appearance.themeSystem')
          }}</ToggleGroupItem>
        </ToggleGroup>

        <Label for="sel-mono">{{ t('settings.appearance.monoFont') }}</Label>
        <div class="flex items-center gap-4">
          <Select :model-value="appearance.prefs.monoFont" @update:model-value="onMono">
            <SelectTrigger id="sel-mono" class="w-56">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="jetbrains">{{
                t('settings.appearance.monoJetbrains')
              }}</SelectItem>
              <SelectItem value="geist">{{ t('settings.appearance.monoGeist') }}</SelectItem>
              <SelectItem value="system">{{ t('settings.appearance.monoSystem') }}</SelectItem>
            </SelectContent>
          </Select>
          <code class="bg-surface-2 rounded-md px-2 py-1 font-mono text-xs">{{
            t('settings.appearance.monoPreview')
          }}</code>
        </div>

        <Label id="lbl-density">{{ t('settings.appearance.density') }}</Label>
        <ToggleGroup
          type="single"
          variant="outline"
          aria-labelledby="lbl-density"
          :model-value="appearance.prefs.density"
          @update:model-value="onDensity"
        >
          <ToggleGroupItem value="comfortable">{{
            t('settings.appearance.densityComfortable')
          }}</ToggleGroupItem>
          <ToggleGroupItem value="compact">{{
            t('settings.appearance.densityCompact')
          }}</ToggleGroupItem>
        </ToggleGroup>

        <Label id="lbl-size">{{ t('settings.appearance.textSize') }}</Label>
        <ToggleGroup
          type="single"
          variant="outline"
          aria-labelledby="lbl-size"
          :model-value="String(appearance.prefs.textSize)"
          @update:model-value="onTextSize"
        >
          <ToggleGroupItem v-for="size in TEXT_SIZES" :key="size" :value="String(size)">
            {{ size }}%
          </ToggleGroupItem>
        </ToggleGroup>

        <Label for="sw-motion">{{ t('settings.appearance.reduceMotion') }}</Label>
        <div class="flex items-center gap-3">
          <Switch
            id="sw-motion"
            :model-value="appearance.prefs.reduceMotion"
            @update:model-value="onReduceMotion"
          />
          <span class="text-text-muted text-xs">{{
            t('settings.appearance.reduceMotionHint')
          }}</span>
        </div>
      </div>
    </SettingRow>

    <!-- Notifications -->
    <SettingRow
      :title="t('settings.notifications.title')"
      :description="t('settings.notifications.description')"
    >
      <div class="grid grid-cols-[12rem_1fr] items-center gap-x-4 gap-y-3">
        <template v-for="severity in SEVERITIES" :key="severity">
          <Label :for="`sw-notify-${severity}`">{{ t(`alerts.severity.${severity}`) }}</Label>
          <Switch
            :id="`sw-notify-${severity}`"
            :model-value="settings.notifications[severity]"
            @update:model-value="(on: boolean) => settings.setNotification(severity, on)"
          />
        </template>
      </div>
      <p class="text-text-muted text-xs">{{ t('settings.notifications.hint') }}</p>
    </SettingRow>

    <!-- Startup -->
    <SettingRow
      :title="t('settings.startup.title')"
      :description="t('settings.startup.description')"
    >
      <div class="grid grid-cols-[12rem_1fr] items-center gap-x-4">
        <Label for="sw-autostart">{{ t('settings.startup.autostart') }}</Label>
        <div class="flex items-center gap-3">
          <Switch
            id="sw-autostart"
            :model-value="autostart"
            :disabled="autostartBusy"
            @update:model-value="onAutostart"
          />
          <span class="text-text-muted text-xs">{{ t('settings.startup.autostartHint') }}</span>
        </div>
      </div>
      <p v-if="autostartError" class="text-warning text-sm" role="alert">
        {{ t('settings.startup.error', { reason: autostartError }) }}
      </p>
    </SettingRow>

    <UpdatesSettings />

    <!-- Language -->
    <SettingRow
      :title="t('settings.language.title')"
      :description="t('settings.language.description')"
    >
      <div class="grid grid-cols-[12rem_1fr] items-center gap-x-4">
        <Label for="sel-lang">{{ t('settings.language.label') }}</Label>
        <Select :model-value="settings.language" @update:model-value="onLanguage">
          <SelectTrigger id="sel-lang" class="w-56">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="auto">{{ t('settings.language.auto') }}</SelectItem>
            <SelectItem value="en">{{ t('settings.language.en') }}</SelectItem>
            <SelectItem value="es">{{ t('settings.language.es') }}</SelectItem>
            <SelectItem value="pt-BR">{{ t('settings.language.ptBR') }}</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </SettingRow>

    <NetworkSettings />
  </div>
</template>

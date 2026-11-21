// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { setTrayLocale } from '@/api/shell'
import {
  DEFAULT_NOTIFICATIONS,
  DEFAULT_UPDATES,
  loadUiPrefs,
  saveUiPrefs,
  systemLocale,
  type LanguageSetting,
  type NotificationPrefs,
  type UpdateChannel,
  type UpdatePrefs,
} from '@/api/uiPrefs'
import { setI18nLocale } from '@/app/i18n'
import { resolveLocale, type Locale } from '@/app/locale'
import { useAppearanceStore } from './appearance'

/** Owns UI preferences: language, plus persistence of everything in `ui.json`. */
export const useSettingsStore = defineStore('settings', () => {
  const language = ref<LanguageSetting>('auto')
  const activeLocale = ref<Locale>('en')
  const systemTag = ref<string | null>(null)
  const notifications = ref<NotificationPrefs>({ ...DEFAULT_NOTIFICATIONS })
  const updates = ref<UpdatePrefs>({ ...DEFAULT_UPDATES })
  const ready = ref(false)
  const appearance = useAppearanceStore()

  function applyLanguage(): void {
    activeLocale.value = resolveLocale(language.value, systemTag.value)
    setI18nLocale(activeLocale.value)
    void setTrayLocale(activeLocale.value)
  }

  async function init(): Promise<void> {
    const [prefs, tag] = await Promise.all([loadUiPrefs(), systemLocale()])
    systemTag.value = tag
    language.value = prefs.language
    notifications.value = { ...DEFAULT_NOTIFICATIONS, ...prefs.notifications }
    updates.value = { ...DEFAULT_UPDATES, ...prefs.updates }
    appearance.hydrate(prefs.appearance)
    applyLanguage()
    ready.value = true
  }

  async function persist(): Promise<void> {
    try {
      await saveUiPrefs({
        version: 1,
        language: language.value,
        appearance: appearance.prefs,
        notifications: notifications.value,
        updates: updates.value,
      })
    } catch (err) {
      console.error('Could not save UI preferences', err)
    }
  }

  async function setLanguage(value: LanguageSetting): Promise<void> {
    language.value = value
    applyLanguage()
    await persist()
  }

  async function setNotification(
    severity: keyof NotificationPrefs,
    enabled: boolean,
  ): Promise<void> {
    notifications.value = { ...notifications.value, [severity]: enabled }
    await persist()
  }

  async function setUpdateChannel(channel: UpdateChannel): Promise<void> {
    updates.value = { ...updates.value, channel }
    await persist()
  }

  async function setCheckOnStart(enabled: boolean): Promise<void> {
    updates.value = { ...updates.value, checkOnStart: enabled }
    await persist()
  }

  return {
    language,
    activeLocale,
    notifications,
    updates,
    ready,
    init,
    persist,
    setLanguage,
    setNotification,
    setUpdateChannel,
    setCheckOnStart,
  }
})

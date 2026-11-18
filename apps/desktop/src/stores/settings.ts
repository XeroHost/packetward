// SPDX-License-Identifier: GPL-3.0-or-later
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { loadUiPrefs, saveUiPrefs, systemLocale, type LanguageSetting } from '@/api/uiPrefs'
import { setI18nLocale } from '@/app/i18n'
import { resolveLocale, type Locale } from '@/app/locale'
import { useAppearanceStore } from './appearance'

/** Owns UI preferences: language, plus persistence of everything in `ui.json`. */
export const useSettingsStore = defineStore('settings', () => {
  const language = ref<LanguageSetting>('auto')
  const activeLocale = ref<Locale>('en')
  const systemTag = ref<string | null>(null)
  const ready = ref(false)
  const appearance = useAppearanceStore()

  function applyLanguage(): void {
    activeLocale.value = resolveLocale(language.value, systemTag.value)
    setI18nLocale(activeLocale.value)
  }

  async function init(): Promise<void> {
    const [prefs, tag] = await Promise.all([loadUiPrefs(), systemLocale()])
    systemTag.value = tag
    language.value = prefs.language
    appearance.hydrate(prefs.appearance)
    applyLanguage()
    ready.value = true
  }

  async function persist(): Promise<void> {
    try {
      await saveUiPrefs({ version: 1, language: language.value, appearance: appearance.prefs })
    } catch (err) {
      console.error('Could not save UI preferences', err)
    }
  }

  async function setLanguage(value: LanguageSetting): Promise<void> {
    language.value = value
    applyLanguage()
    await persist()
  }

  return { language, activeLocale, ready, init, persist, setLanguage }
})

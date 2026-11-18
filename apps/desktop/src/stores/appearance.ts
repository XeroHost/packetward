// SPDX-License-Identifier: GPL-3.0-or-later
import { useMediaQuery } from '@vueuse/core'
import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { applyAppearance, resolveTheme } from '@/app/appearance'
import {
  DEFAULT_UI_PREFS,
  type AppearancePrefs,
  type Density,
  type MonoFont,
  type TextSize,
  type ThemeSetting,
} from '@/api/uiPrefs'

export const useAppearanceStore = defineStore('appearance', () => {
  const prefs = ref<AppearancePrefs>({ ...DEFAULT_UI_PREFS.appearance })
  const osPrefersDark = useMediaQuery('(prefers-color-scheme: dark)')
  const osReducedMotion = useMediaQuery('(prefers-reduced-motion: reduce)')

  const resolvedTheme = computed(() => resolveTheme(prefs.value.theme, osPrefersDark.value))

  // Live: any change (setting or OS preference) re-applies the attributes on <html>.
  watch(
    [prefs, osPrefersDark, osReducedMotion],
    () =>
      applyAppearance(prefs.value, {
        osPrefersDark: osPrefersDark.value,
        osReducedMotion: osReducedMotion.value,
      }),
    { deep: true, immediate: true },
  )

  function hydrate(next: AppearancePrefs): void {
    prefs.value = { ...next }
  }
  function setTheme(v: ThemeSetting): void {
    prefs.value.theme = v
  }
  function setMonoFont(v: MonoFont): void {
    prefs.value.monoFont = v
  }
  function setDensity(v: Density): void {
    prefs.value.density = v
  }
  function setTextSize(v: TextSize): void {
    prefs.value.textSize = v
  }
  function setReduceMotion(v: boolean): void {
    prefs.value.reduceMotion = v
  }

  return {
    prefs,
    resolvedTheme,
    hydrate,
    setTheme,
    setMonoFont,
    setDensity,
    setTextSize,
    setReduceMotion,
  }
})

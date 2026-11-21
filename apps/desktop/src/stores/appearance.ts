// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { useMediaQuery } from '@vueuse/core'
import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { setWindowTheme } from '@/api/window'
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

  const resolvedTheme = computed(() => resolveTheme(prefs.value.theme, osPrefersDark.value))

  // Live: any change (setting or OS preference) re-applies the attributes on <html>.
  watch(
    [prefs, osPrefersDark],
    () =>
      applyAppearance(prefs.value, {
        osPrefersDark: osPrefersDark.value,
      }),
    { deep: true, immediate: true },
  )

  // The system window material follows the app's theme, not the OS one.
  watch(resolvedTheme, (theme) => void setWindowTheme(theme), { immediate: true })

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

// SPDX-License-Identifier: GPL-3.0-or-later
// Applies Appearance settings as attributes/properties on <html> so CSS alone reacts.
import type { AppearancePrefs, MonoFont } from '@/api/uiPrefs'

export const MONO_STACKS: Record<MonoFont, string> = {
  jetbrains: "'JetBrains Mono', 'Geist Mono', Consolas, 'Cascadia Mono', monospace",
  geist: "'Geist Mono', 'JetBrains Mono', Consolas, 'Cascadia Mono', monospace",
  system: "Consolas, 'Cascadia Mono', monospace",
}

export function resolveTheme(
  theme: AppearancePrefs['theme'],
  osPrefersDark: boolean,
): 'dark' | 'light' {
  if (theme === 'system') return osPrefersDark ? 'dark' : 'light'
  return theme
}

export function applyAppearance(
  prefs: AppearancePrefs,
  env: { osPrefersDark: boolean },
  root: HTMLElement = document.documentElement,
): void {
  root.dataset.theme = resolveTheme(prefs.theme, env.osPrefersDark)
  root.dataset.density = prefs.density
  // Only the app setting reduces motion. The OS preference is ignored on purpose: Windows Server
  // ships with visual effects off, which would turn every animation off for everyone.
  root.dataset.motion = prefs.reduceMotion ? 'reduced' : 'full'
  root.style.setProperty('--font-mono', MONO_STACKS[prefs.monoFont])
  root.style.fontSize = `${prefs.textSize}%`
}

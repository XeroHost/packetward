// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from 'vitest'
import { DEFAULT_UI_PREFS, type AppearancePrefs } from '@/api/uiPrefs'
import { applyAppearance, MONO_STACKS, resolveTheme } from './appearance'

const light: AppearancePrefs = DEFAULT_UI_PREFS.appearance
const env = { osPrefersDark: true }

describe('resolveTheme', () => {
  it('resolves system through the OS preference', () => {
    expect(resolveTheme('system', true)).toBe('dark')
    expect(resolveTheme('system', false)).toBe('light')
  })
  it('keeps explicit choices', () => {
    expect(resolveTheme('light', true)).toBe('light')
    expect(resolveTheme('dark', false)).toBe('dark')
  })
})

describe('applyAppearance', () => {
  let root: HTMLElement
  beforeEach(() => {
    root = document.createElement('html')
  })

  it('sets the attributes CSS reacts to', () => {
    applyAppearance({ ...light, theme: 'light', density: 'compact', textSize: 125 }, env, root)
    expect(root.dataset.theme).toBe('light')
    expect(root.dataset.density).toBe('compact')
    expect(root.dataset.motion).toBe('full')
    expect(root.style.fontSize).toBe('125%')
  })

  it('applies the chosen mono font stack', () => {
    applyAppearance({ ...light, monoFont: 'geist' }, env, root)
    expect(root.style.getPropertyValue('--font-mono')).toBe(MONO_STACKS.geist)
    applyAppearance({ ...light, monoFont: 'system' }, env, root)
    expect(root.style.getPropertyValue('--font-mono')).toBe(MONO_STACKS.system)
  })

  it('reduces motion only from the app setting, never from the OS', () => {
    applyAppearance({ ...light, reduceMotion: true }, env, root)
    expect(root.dataset.motion).toBe('reduced')
    // The OS preference is not an input at all: Windows Server ships with visual effects off,
    // which browsers report as reduced motion.
    applyAppearance({ ...light, reduceMotion: false }, env, root)
    expect(root.dataset.motion).toBe('full')
  })
})

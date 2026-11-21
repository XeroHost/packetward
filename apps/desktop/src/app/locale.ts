// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import type { LanguageSetting } from '@/api/uiPrefs'

export type Locale = 'en' | 'es' | 'pt-BR'

export const SUPPORTED_LOCALES: readonly Locale[] = ['en', 'es', 'pt-BR']

/** Maps an OS locale tag to a supported locale: es-* -> es, pt-* -> pt-BR, anything else -> en. */
export function detectLocale(tag: string | null | undefined): Locale {
  const primary = (tag ?? '').toLowerCase().split(/[-_]/)[0]
  if (primary === 'es') return 'es'
  if (primary === 'pt') return 'pt-BR'
  return 'en'
}

/** Applies the user override (if any) on top of the detected system locale. */
export function resolveLocale(setting: LanguageSetting, systemTag: string | null): Locale {
  return setting === 'auto' ? detectLocale(systemTag) : setting
}

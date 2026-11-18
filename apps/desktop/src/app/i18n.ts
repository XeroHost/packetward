// SPDX-License-Identifier: GPL-3.0-or-later
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'
import es from '@/locales/es.json'
import ptBR from '@/locales/pt-BR.json'
import type { Locale } from './locale'

// `en` is the base and fallback; `es` and `pt-BR` must stay complete (see locales.test.ts).
export const i18n = createI18n({
  legacy: false,
  locale: 'en',
  fallbackLocale: 'en',
  messages: { en, es, 'pt-BR': ptBR },
})

export function setI18nLocale(locale: Locale): void {
  i18n.global.locale.value = locale
  document.documentElement.lang = locale
}

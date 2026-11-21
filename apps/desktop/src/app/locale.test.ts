// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { describe, expect, it } from 'vitest'
import en from '@/locales/en.json'
import es from '@/locales/es.json'
import ptBR from '@/locales/pt-BR.json'
import { detectLocale, resolveLocale } from './locale'

function keysOf(obj: Record<string, unknown>, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([k, v]) =>
    v !== null && typeof v === 'object'
      ? keysOf(v as Record<string, unknown>, `${prefix}${k}.`)
      : [`${prefix}${k}`],
  )
}

describe('detectLocale', () => {
  it.each([
    ['es-MX', 'es'],
    ['es', 'es'],
    ['ES-ar', 'es'],
    ['pt-BR', 'pt-BR'],
    ['pt-PT', 'pt-BR'],
    ['pt_BR', 'pt-BR'],
    ['en-US', 'en'],
    ['de-DE', 'en'],
    ['', 'en'],
  ])('%s -> %s', (tag, expected) => {
    expect(detectLocale(tag)).toBe(expected)
  })

  it('falls back to English when the system locale is unknown', () => {
    expect(detectLocale(null)).toBe('en')
    expect(detectLocale(undefined)).toBe('en')
  })
})

describe('resolveLocale', () => {
  it('uses the system locale in auto mode', () => {
    expect(resolveLocale('auto', 'es-ES')).toBe('es')
  })
  it('lets the user override the system locale', () => {
    expect(resolveLocale('pt-BR', 'es-ES')).toBe('pt-BR')
    expect(resolveLocale('en', 'es-ES')).toBe('en')
  })
})

describe('locale files', () => {
  const base = keysOf(en).sort()
  it('es is complete against en', () => {
    expect(keysOf(es).sort()).toEqual(base)
  })
  it('pt-BR is complete against en', () => {
    expect(keysOf(ptBR).sort()).toEqual(base)
  })
})

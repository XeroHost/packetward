// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { describe, expect, it } from 'vitest'
import type { AlertView } from '@/types/generated/AlertView'
import type { BlockView } from '@/types/generated/BlockView'
import { attackerAddresses, summarizeAttackers } from './attackers'
import { buildMapOption, mix } from './mapOption'

const alert = (id: number, source: string | undefined, isProtected = false): AlertView =>
  ({ id, source, protected: isProtected }) as unknown as AlertView
const block = (cidr: string): BlockView => ({ cidr }) as unknown as BlockView

const placeOf = (addr: string) => {
  const table: Record<string, string> = {
    '1.1.1.1': 'AU',
    '1.1.1.2': 'AU',
    '2.2.2.2': 'RU',
    '203.0.113.5': 'NL',
  }
  const code = table[addr]
  return code ? { code } : null
}

describe('attackers', () => {
  it('lists each distinct source once, without trusted ones, and places blocks by their base address', () => {
    const alerts = [
      alert(1, '1.1.1.1'),
      alert(2, '1.1.1.1'),
      alert(3, '203.0.113.5', true),
      alert(4, undefined),
    ]
    const blocks = [block('2.2.2.2/32'), block('1.1.1.1/32')]
    expect(attackerAddresses(alerts, blocks).sort()).toEqual(['1.1.1.1', '2.2.2.2'])
  })

  it('counts addresses, alerts and blocks per country, biggest first', () => {
    const alerts = [
      alert(1, '1.1.1.1'),
      alert(2, '1.1.1.1'),
      alert(3, '1.1.1.2'),
      alert(4, '2.2.2.2'),
    ]
    const blocks = [block('2.2.2.2/32'), block('9.9.9.9/32')]
    const rows = summarizeAttackers(alerts, blocks, placeOf)
    expect(rows).toEqual([
      { code: 'AU', addrs: 2, alerts: 3, blocked: 0 },
      { code: 'RU', addrs: 1, alerts: 1, blocked: 1 },
    ])
  })

  it('leaves out addresses that have no country yet', () => {
    expect(summarizeAttackers([alert(1, '7.7.7.7')], [], () => undefined)).toEqual([])
  })
})

describe('map option', () => {
  const colors = {
    land: '#000000',
    border: '#111111',
    danger: '#ff0000',
    text: '#ffffff',
    surface: '#222222',
  }
  const labels = {
    addresses: (n: number) => `${n} a`,
    alerts: (n: number) => (n ? `${n} al` : ''),
    blocked: () => '',
  }

  it('mixes colours between two hex values and falls back for anything else', () => {
    expect(mix('#000000', '#ff0000', 0.5)).toBe('#800000')
    expect(mix('#000000', '#ff0000', 2)).toBe('#ff0000')
    expect(mix('rgb(0,0,0)', '#ff0000', 0.5)).toBe('#ff0000')
  })

  it('shades the busiest country the most and keeps the tooltip readable', () => {
    const rows = [
      { code: 'AU', addrs: 4, alerts: 2, blocked: 0 },
      { code: 'RU', addrs: 1, alerts: 0, blocked: 1 },
    ]
    const option = buildMapOption(rows, colors, 'en', labels) as {
      series: [{ data: { name: string; itemStyle: { areaColor: string } }[] }]
      tooltip: { formatter: (p: { name: string }) => string }
    }
    const [au, ru] = option.series[0].data
    expect(au?.itemStyle.areaColor).toBe('#ff0000')
    expect(ru?.itemStyle.areaColor).not.toBe('#ff0000')
    expect(option.tooltip.formatter({ name: 'AU' })).toContain('4 a')
    expect(option.tooltip.formatter({ name: 'AU' })).toContain('2 al')
    // A country with no attackers just shows its name.
    expect(option.tooltip.formatter({ name: 'NZ' })).toMatch(/New Zealand|NZ/)
  })
})

// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import { buildChartOption, readChartColors, type ChartColors } from './chartOption'

interface Series {
  name: string
  data: [number, number][]
  lineStyle: { color: string }
}

/** The parts of the ECharts option these tests look at. */
interface OptionShape {
  animation: boolean
  tooltip: { valueFormatter: (value: number) => string }
  yAxis: { min: number; axisLabel: { formatter: (value: number) => string } }
  series: [Series, Series]
}
const shape = (option: unknown) => option as OptionShape

const colors: ChartColors = {
  inbound: '#22d3ee',
  outbound: '#a78bfa',
  text: '#e8eaf0',
  muted: '#8a93a6',
  border: '#262c38',
  surface: '#1f2430',
}
const labels = { inbound: 'Inbound', outbound: 'Outbound' }

describe('buildChartOption', () => {
  const history = { t: [1000, 2000, 3000], inBps: [10, 20, 30], outBps: [1, 2, 3] }
  const option = shape(buildChartOption(history, labels, colors))

  it('draws inbound and outbound as two time series with the design colours', () => {
    expect(option.series).toHaveLength(2)
    expect(option.series[0].name).toBe('Inbound')
    expect(option.series[0].data).toEqual([
      [1000, 10],
      [2000, 20],
      [3000, 30],
    ])
    expect(option.series[0].lineStyle.color).toBe('#22d3ee')
    expect(option.series[1].name).toBe('Outbound')
    expect(option.series[1].data).toEqual([
      [1000, 1],
      [2000, 2],
      [3000, 3],
    ])
    expect(option.series[1].lineStyle.color).toBe('#a78bfa')
  })

  it('does not animate (the data streams in every second)', () => {
    expect(option.animation).toBe(false)
  })

  it('formats the y axis and the tooltip as bits per second, starting at zero', () => {
    expect(option.yAxis.min).toBe(0)
    expect(option.yAxis.axisLabel.formatter(2_500_000)).toBe('2.50 Mbps')
    expect(option.tooltip.valueFormatter(1_000)).toBe('1.00 Kbps')
  })

  it('copes with empty history', () => {
    const empty = shape(buildChartOption({ t: [], inBps: [], outBps: [] }, labels, colors))
    expect(empty.series[0].data).toEqual([])
  })
})

describe('readChartColors', () => {
  it('reads the tokens from the document and falls back when they are missing', () => {
    document.documentElement.style.setProperty('--chart-in', ' #123456 ')
    const read = readChartColors()
    expect(read.inbound).toBe('#123456')
    expect(read.outbound).toBe('#a78bfa') // fallback: not defined in jsdom
    document.documentElement.style.removeProperty('--chart-in')
  })
})

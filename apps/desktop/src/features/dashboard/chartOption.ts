// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import type { EChartsCoreOption } from 'echarts/core'
import { formatBitrate } from '@/lib/format'
import type { History } from '@/stores/live'

export interface ChartColors {
  inbound: string
  outbound: string
  text: string
  muted: string
  border: string
  surface: string
}

/** Resolved design tokens (ECharts needs concrete colours, not `var(--x)`). */
export function readChartColors(root: HTMLElement = document.documentElement): ChartColors {
  const style = getComputedStyle(root)
  const token = (name: string, fallback: string) => style.getPropertyValue(name).trim() || fallback
  return {
    inbound: token('--chart-in', '#22d3ee'),
    outbound: token('--chart-out', '#a78bfa'),
    text: token('--text', '#e8eaf0'),
    muted: token('--text-muted', '#8a93a6'),
    border: token('--border', '#262c38'),
    surface: token('--surface-3', '#1f2430'),
  }
}

const pairs = (times: number[], values: number[]): [number, number][] =>
  times.map((t, i) => [t, values[i] ?? 0])

/** Inbound and outbound bits per second over time. Streaming data: no animation. */
export function buildChartOption(
  history: History,
  labels: { inbound: string; outbound: string },
  colors: ChartColors,
): EChartsCoreOption {
  const line = (name: string, color: string, values: number[]) => ({
    name,
    type: 'line' as const,
    showSymbol: false,
    smooth: false,
    sampling: 'lttb' as const,
    lineStyle: { width: 2, color },
    itemStyle: { color },
    areaStyle: { color, opacity: 0.12 },
    data: pairs(history.t, values),
  })
  return {
    animation: false,
    color: [colors.inbound, colors.outbound],
    textStyle: { color: colors.muted },
    grid: { left: 8, right: 16, top: 24, bottom: 8, containLabel: true },
    tooltip: {
      trigger: 'axis',
      backgroundColor: colors.surface,
      borderColor: colors.border,
      textStyle: { color: colors.text },
      valueFormatter: (value: unknown) => formatBitrate(Number(value)),
    },
    xAxis: {
      type: 'time',
      axisLine: { lineStyle: { color: colors.border } },
      axisLabel: { color: colors.muted },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      min: 0,
      axisLabel: { color: colors.muted, formatter: (value: number) => formatBitrate(value) },
      splitLine: { lineStyle: { color: colors.border } },
    },
    series: [
      line(labels.inbound, colors.inbound, history.inBps),
      line(labels.outbound, colors.outbound, history.outBps),
    ],
  }
}

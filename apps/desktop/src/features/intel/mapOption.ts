// SPDX-License-Identifier: GPL-3.0-or-later
import type { EChartsCoreOption } from 'echarts/core'
import { countryName } from '@/lib/countries'
import type { AttackerCountry } from './attackers'

export interface MapColors {
  land: string
  border: string
  danger: string
  text: string
  surface: string
}

/** Resolved design tokens (ECharts needs concrete colours, not `var(--x)`). */
export function readMapColors(root: HTMLElement = document.documentElement): MapColors {
  const style = getComputedStyle(root)
  const token = (name: string, fallback: string) => style.getPropertyValue(name).trim() || fallback
  return {
    land: token('--surface-3', '#3a3835'),
    border: token('--surface', '#262624'),
    danger: token('--danger', '#e5786d'),
    text: token('--text', '#ece9e1'),
    surface: token('--surface-2', '#2f2e2b'),
  }
}

function rgb(hex: string): [number, number, number] | null {
  const m = /^#([0-9a-f]{6})$/i.exec(hex.trim())
  if (!m?.[1]) return null
  const n = parseInt(m[1], 16)
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}

/** Mixes two `#rrggbb` colours: 0 = `from`, 1 = `to`. Falls back to `to` for anything else. */
export function mix(from: string, to: string, t: number): string {
  const a = rgb(from)
  const b = rgb(to)
  if (!a || !b) return to
  const k = Math.min(1, Math.max(0, t))
  const c = a.map((v, i) => Math.round(v + ((b[i] ?? v) - v) * k))
  return `#${c.map((v) => v.toString(16).padStart(2, '0')).join('')}`
}

/** Where the camera is: the zoom and the centre the user left it at (the map's own until moved). */
export interface MapView {
  zoom: number
  center?: [number, number]
}

export const DEFAULT_VIEW: MapView = { zoom: 1.12 }
export const MAP_ZOOM_LIMITS = { min: 1, max: 12 } as const

/** Countries shaded from "a little" to "the most addresses" in the threat colour. */
export function buildMapOption(
  rows: readonly AttackerCountry[],
  colors: MapColors,
  locale: string,
  labels: {
    addresses: (n: number) => string
    alerts: (n: number) => string
    blocked: (n: number) => string
  },
  view: MapView = DEFAULT_VIEW,
): EChartsCoreOption {
  const most = Math.max(1, ...rows.map((r) => r.addrs))
  const byCode = new Map(rows.map((r) => [r.code, r]))
  return {
    animation: false,
    tooltip: {
      trigger: 'item',
      backgroundColor: colors.surface,
      borderColor: colors.border,
      textStyle: { color: colors.text },
      formatter: (params: { name: string }) => {
        const row = byCode.get(params.name)
        const title = countryName(params.name, locale)
        if (!row) return title
        return [
          title,
          labels.addresses(row.addrs),
          labels.alerts(row.alerts),
          labels.blocked(row.blocked),
        ]
          .filter((line) => line !== '')
          .join('<br/>')
      },
    },
    series: [
      {
        type: 'map',
        map: 'world',
        // Wheel and pinch zoom, drag to move; new data keeps the camera where the user left it.
        roam: true,
        scaleLimit: MAP_ZOOM_LIMITS,
        zoom: view.zoom,
        ...(view.center ? { center: view.center } : {}),
        selectedMode: false,
        silent: false,
        label: { show: false },
        itemStyle: { areaColor: colors.land, borderColor: colors.border, borderWidth: 0.6 },
        emphasis: { disabled: true, label: { show: false } },
        select: { disabled: true },
        data: rows.map((row) => ({
          name: row.code,
          value: row.addrs,
          itemStyle: { areaColor: mix(colors.land, colors.danger, 0.4 + 0.6 * (row.addrs / most)) },
        })),
      },
    ],
  }
}

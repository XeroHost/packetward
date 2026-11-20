// SPDX-License-Identifier: GPL-3.0-or-later
// The camera controls of the attack map, against a real ECharts instance (server-side rendering,
// no canvas): the zoom action must change the zoom, and the limits must hold.
import { MapChart } from 'echarts/charts'
import { GeoComponent, TooltipComponent } from 'echarts/components'
import { init, registerMap, use } from 'echarts/core'
import { SVGRenderer } from 'echarts/renderers'
import { describe, expect, it } from 'vitest'
import { buildMapOption, DEFAULT_VIEW, MAP_ZOOM_LIMITS } from './mapOption'
import { loadWorld } from './worldMap'

use([MapChart, GeoComponent, TooltipComponent, SVGRenderer])

const colors = {
  land: '#333333',
  border: '#222222',
  danger: '#ff0000',
  text: '#ffffff',
  surface: '#111111',
}
const labels = { addresses: () => '', alerts: () => '', blocked: () => '' }

async function chart() {
  registerMap('world', (await loadWorld()) as never)
  const instance = init(null, null, { renderer: 'svg', ssr: true, width: 800, height: 352 })
  instance.setOption(
    buildMapOption([{ code: 'FI', addrs: 2, alerts: 1, blocked: 0 }], colors, 'en', labels),
  )
  return instance
}

const zoomOf = (instance: ReturnType<typeof init>): number =>
  ((instance.getOption() as { series: { zoom: number }[] }).series[0] ?? { zoom: NaN }).zoom

describe('attack map camera', () => {
  it('starts at the default zoom and allows roaming', async () => {
    const instance = await chart()
    const series = (instance.getOption() as { series: { roam: boolean }[] }).series[0]
    expect(series?.roam).toBe(true)
    expect(zoomOf(instance)).toBeCloseTo(DEFAULT_VIEW.zoom)
  })

  it('zooms in and out around the middle with the geoRoam action, within the limits', async () => {
    const instance = await chart()
    const roam = (zoom: number) =>
      instance.dispatchAction({
        type: 'geoRoam',
        componentType: 'series',
        seriesIndex: 0,
        zoom,
        originX: 400,
        originY: 176,
      })
    roam(1.5)
    expect(zoomOf(instance)).toBeGreaterThan(DEFAULT_VIEW.zoom * 1.4)
    roam(1 / 1.5)
    expect(zoomOf(instance)).toBeCloseTo(DEFAULT_VIEW.zoom, 1)
    for (let i = 0; i < 20; i++) roam(2)
    expect(zoomOf(instance)).toBeLessThanOrEqual(MAP_ZOOM_LIMITS.max + 0.001)
    for (let i = 0; i < 20; i++) roam(0.5)
    expect(zoomOf(instance)).toBeGreaterThanOrEqual(MAP_ZOOM_LIMITS.min - 0.001)
  })

  it('keeps the camera where the user left it when new data arrives', async () => {
    const instance = await chart()
    instance.dispatchAction({
      type: 'geoRoam',
      componentType: 'series',
      seriesIndex: 0,
      zoom: 2,
      originX: 400,
      originY: 176,
    })
    const zoomed = zoomOf(instance)
    instance.setOption(
      buildMapOption([{ code: 'VN', addrs: 1, alerts: 1, blocked: 0 }], colors, 'en', labels, {
        zoom: zoomed,
      }),
    )
    expect(zoomOf(instance)).toBeCloseTo(zoomed, 3)
  })
})

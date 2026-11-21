// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import type { Feature, MultiPolygon, Polygon, Position } from 'geojson'
import { describe, expect, it } from 'vitest'
import { fixAntimeridian, splitRing } from './antimeridian'
import { loadWorld } from './worldMap'

/** Largest longitude jump between consecutive points of any ring. */
function widestJump(ring: Position[]): number {
  let widest = 0
  for (let i = 1; i < ring.length; i++) {
    widest = Math.max(widest, Math.abs((ring[i]?.[0] ?? 0) - (ring[i - 1]?.[0] ?? 0)))
  }
  return widest
}

describe('splitRing', () => {
  it('leaves a ring that stays on one side alone', () => {
    const ring: Position[] = [
      [10, 10],
      [20, 10],
      [20, 20],
      [10, 10],
    ]
    expect(splitRing(ring)).toEqual([ring])
  })

  it('splits a ring that crosses +180 into an east piece and a west piece', () => {
    // A box from lon 170 to -170 (across the meridian), as GeoJSON writes it.
    const ring: Position[] = [
      [170, 0],
      [180, 0],
      [-180, 0],
      [-170, 0],
      [-170, 10],
      [-180, 10],
      [180, 10],
      [170, 10],
      [170, 0],
    ]
    const pieces = splitRing(ring)
    expect(pieces).toHaveLength(2)
    for (const piece of pieces) expect(widestJump(piece)).toBeLessThan(180)
    const lons = pieces.map((p) => p.map((q) => q[0] ?? 0))
    expect(Math.max(...(lons[0] ?? []))).toBeLessThanOrEqual(180)
    expect(Math.min(...(lons[1] ?? []))).toBeGreaterThanOrEqual(-180)
  })
})

describe('the world map', () => {
  it('has no polygon left that jumps across the whole map', async () => {
    const world = await loadWorld()
    expect(world.features.length).toBeGreaterThan(150)
    for (const feature of world.features) {
      const geometry = feature.geometry as Polygon | MultiPolygon
      const polygons = geometry.type === 'Polygon' ? [geometry.coordinates] : geometry.coordinates
      for (const polygon of polygons) {
        for (const ring of polygon) {
          expect(widestJump(ring), String(feature.properties?.name)).toBeLessThan(180)
        }
      }
    }
  })

  it('splits Russia and Fiji, and names regions by ISO code', async () => {
    const world = await loadWorld()
    const by = (code: string): Feature => {
      const found = world.features.find((f) => f.properties?.name === code)
      if (!found) throw new Error(`no ${code}`)
      return found
    }
    expect(by('RU').geometry.type).toBe('MultiPolygon')
    expect(by('FJ').geometry.type).toBe('MultiPolygon')
    expect(world.features.some((f) => f.properties?.name === 'AQ')).toBe(false)
    expect(fixAntimeridian(by('US')).geometry.type).toBe('MultiPolygon')
  })
})

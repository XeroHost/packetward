// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Polygons that cross the 180th meridian (Russia, Fiji) jump from +180 to -180 between two
// consecutive points; drawn as they are, they smear a band across the whole map. This splits them
// at the meridian into two polygons that each stay on their own side.
import type { Feature, Geometry, Polygon, Position } from 'geojson'

type Ring = Position[]

/** Makes consecutive longitudes continuous: a jump of more than 180 degrees is a wrap, not a trip. */
function unwrap(ring: Ring): Ring {
  const out: Ring = []
  let shift = 0
  let previous: number | undefined
  for (const point of ring) {
    const lon = point[0] ?? 0
    if (previous !== undefined) {
      if (lon - previous > 180) shift -= 360
      else if (lon - previous < -180) shift += 360
    }
    previous = lon
    out.push([lon + shift, point[1] ?? 0])
  }
  return out
}

/** Sutherland-Hodgman against one vertical line, keeping the side where `keep(lon)` holds. */
function clip(ring: Ring, line: number, keep: (lon: number) => boolean): Ring {
  const out: Ring = []
  for (let i = 0; i < ring.length; i++) {
    const current = ring[i]
    const before = ring[(i + ring.length - 1) % ring.length]
    if (!current || !before) continue
    const currentIn = keep(current[0] ?? 0)
    const beforeIn = keep(before[0] ?? 0)
    if (currentIn !== beforeIn) {
      const t = (line - (before[0] ?? 0)) / ((current[0] ?? 0) - (before[0] ?? 0))
      out.push([line, (before[1] ?? 0) + t * ((current[1] ?? 0) - (before[1] ?? 0))])
    }
    if (currentIn) out.push(current)
  }
  return out
}

const close = (ring: Ring): Ring => {
  const first = ring[0]
  const last = ring[ring.length - 1]
  return first && last && (first[0] !== last[0] || first[1] !== last[1]) ? [...ring, first] : ring
}

/** One exterior ring -> the rings to draw (one if it stays on one side of the meridian, else two). */
export function splitRing(ring: Ring): Ring[] {
  const flat = unwrap(ring)
  const lons = flat.map((p) => p[0] ?? 0)
  const max = Math.max(...lons)
  const min = Math.min(...lons)
  if (max <= 180 && min >= -180) return [ring]
  const pieces: Ring[] = []
  if (max > 180) {
    pieces.push(clip(flat.slice(0, -1), 180, (x) => x <= 180))
    pieces.push(
      clip(flat.slice(0, -1), 180, (x) => x >= 180).map(([x, y]) => [(x ?? 0) - 360, y ?? 0]),
    )
  } else {
    pieces.push(clip(flat.slice(0, -1), -180, (x) => x >= -180))
    pieces.push(
      clip(flat.slice(0, -1), -180, (x) => x <= -180).map(([x, y]) => [(x ?? 0) + 360, y ?? 0]),
    )
  }
  return pieces.filter((piece) => piece.length >= 3).map(close)
}

/** The geometry of a country with every polygon that crosses the meridian split in two. */
export function fixAntimeridian<G extends Geometry>(feature: Feature<G>): Feature<Geometry> {
  const geometry = feature.geometry
  const polygons: Polygon['coordinates'][] =
    geometry.type === 'Polygon'
      ? [geometry.coordinates]
      : geometry.type === 'MultiPolygon'
        ? geometry.coordinates
        : []
  if (polygons.length === 0) return feature
  const fixed: Polygon['coordinates'][] = []
  for (const polygon of polygons) {
    const [outer] = polygon
    if (!outer) continue
    const pieces = splitRing(outer)
    if (pieces.length === 1) fixed.push(polygon)
    // A split polygon loses its holes: none of the countries that cross the meridian has one.
    else for (const piece of pieces) fixed.push([piece])
  }
  return { ...feature, geometry: { type: 'MultiPolygon', coordinates: fixed } }
}

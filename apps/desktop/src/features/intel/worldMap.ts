// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// The world for the attack map: Natural Earth countries (public domain) from `world-atlas`, turned
// into GeoJSON whose region names are ISO alpha-2 codes, so GeoIP answers match them directly.
// Loaded on demand: the map page pulls this in, nothing else does.
import type { FeatureCollection } from 'geojson'
import { fixAntimeridian } from './antimeridian'

let cached: Promise<FeatureCollection> | null = null

export function loadWorld(): Promise<FeatureCollection> {
  cached ??= (async () => {
    const [topology, topojson, iso] = await Promise.all([
      import('world-atlas/countries-110m.json'),
      import('topojson-client'),
      import('i18n-iso-countries'),
    ])
    const topo = topology.default as unknown as import('topojson-specification').Topology
    const countries = topo.objects.countries as import('topojson-specification').GeometryCollection
    const collection = topojson.feature(topo, countries)
    const features = collection.features.flatMap((feature) => {
      const code = iso.default.numericToAlpha2(String(feature.id ?? '').padStart(3, '0'))
      // No code (disputed or tiny territories) or Antarctica: not worth drawing.
      if (!code || code === 'AQ') return []
      return [fixAntimeridian({ ...feature, properties: { name: code } })]
    })
    return { type: 'FeatureCollection', features } as FeatureCollection
  })()
  return cached
}

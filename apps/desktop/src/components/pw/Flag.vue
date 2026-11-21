<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
// The flag of an address's country (or of a country code), as an SVG image from country-flag-icons
// (MIT). Emoji flags are not used: Windows draws them as two letters. Each flag is a tiny lazy
// chunk, fetched the first time that country shows up. Private and unknown addresses show nothing.
import { computed, shallowRef, watchEffect } from 'vue'
import { useGeoStore } from '@/stores/geo'

const props = defineProps<{ addr?: string; code?: string; name?: string }>()

const geo = useGeoStore()
const loaders = import.meta.glob<string>('/node_modules/country-flag-icons/3x2/*.svg', {
  query: '?url',
  import: 'default',
})
const urls = new Map<string, Promise<string | null>>()

function flagUrl(code: string): Promise<string | null> {
  let url = urls.get(code)
  if (!url) {
    const load = loaders[`/node_modules/country-flag-icons/3x2/${code}.svg`]
    url = load ? load().catch(() => null) : Promise.resolve(null)
    urls.set(code, url)
  }
  return url
}

/** `undefined`: still asking; `null`: nothing to show. */
const code = computed<string | null | undefined>(() => {
  if (props.code) return props.code.toUpperCase()
  if (!props.addr) return null
  // A block like 203.0.113.0/24 is placed by its first address.
  const place = geo.place(props.addr.split('/')[0] ?? '')
  return place === undefined ? undefined : (place?.code ?? null)
})

const src = shallowRef<string | null>(null)
watchEffect(async () => {
  const wanted = code.value
  if (!wanted) {
    src.value = null
    return
  }
  const url = await flagUrl(wanted)
  if (code.value === wanted) src.value = url
})

const label = computed(() => props.name ?? code.value ?? '')
</script>

<template>
  <!-- Reserves the flag's room while the country is being looked up, so the row does not jump. -->
  <span
    v-if="code === undefined && geo.ready !== false"
    class="bg-surface-3 inline-block h-3.5 w-[1.3125rem] shrink-0 rounded-[3px] opacity-60"
    aria-hidden="true"
  />
  <img
    v-else-if="src"
    :src="src"
    :alt="label"
    :title="label"
    class="ring-hairline-strong inline-block h-3.5 w-[1.3125rem] shrink-0 rounded-[3px] object-cover ring-1"
    draggable="false"
  />
</template>

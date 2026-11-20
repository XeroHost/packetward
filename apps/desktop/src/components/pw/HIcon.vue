<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// A Hugeicons icon with its own one-shot motion (see `.hi-a-*` in main.css): the default `draw` traces
// the stroke when `play` changes; the others (ring, spin, sweep...) play from CSS when the row, button
// or tab that holds the icon is hovered or focused. No loop, no layout, nothing at rest.
import { computed, ref, watch } from 'vue'
import type { IconAnimation, IconData } from '@/lib/icons'

const props = withDefaults(
  defineProps<{
    icon: IconData
    size?: number
    stroke?: number
    play?: number
    animation?: IconAnimation
  }>(),
  { size: 18, stroke: 1.5, play: 0, animation: 'draw' },
)

const run = ref(0)
watch(
  () => props.play,
  () => {
    run.value += 1
  },
)

/** `strokeLinecap` -> `stroke-linecap`; Hugeicons ships camelCase React props. */
function kebab(name: string): string {
  return name === 'pathLength' ? name : name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)
}

const parts = computed(() =>
  props.icon.map(([tag, attrs], index) => {
    const out: Record<string, string | number> = {}
    for (const [name, value] of Object.entries(attrs)) {
      if (name !== 'key') out[kebab(name)] = value
    }
    out['stroke-width'] = props.stroke
    out.pathLength = 1
    return { tag, index, attrs: out }
  }),
)
</script>

<template>
  <svg
    viewBox="0 0 24 24"
    fill="none"
    :width="size"
    :height="size"
    aria-hidden="true"
    focusable="false"
    :class="['hi shrink-0', 'hi-a-' + animation]"
  >
    <g :key="run" :class="{ 'hi-draw': animation === 'draw' && run > 0 }">
      <component :is="part.tag" v-for="part in parts" :key="part.index" v-bind="part.attrs" />
    </g>
  </svg>
</template>

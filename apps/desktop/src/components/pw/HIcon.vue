<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// A Hugeicons icon that draws itself when `play` changes (hover/focus of its parent). The stroke
// animation is a one-shot CSS keyframe (no loop, no layout), so it costs nothing at rest.
import { computed, ref, watch } from 'vue'
import type { IconData } from '@/lib/icons'

const props = withDefaults(
  defineProps<{ icon: IconData; size?: number; stroke?: number; play?: number }>(),
  { size: 18, stroke: 1.5, play: 0 },
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
    class="shrink-0"
  >
    <g :key="run" :class="{ 'hi-draw': run > 0 }">
      <component :is="part.tag" v-for="part in parts" :key="part.index" v-bind="part.attrs" />
    </g>
  </svg>
</template>

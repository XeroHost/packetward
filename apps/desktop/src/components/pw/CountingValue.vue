<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// A live number that eases to its new value with a spring instead of jumping. The first value is
// shown as it is (no count-up from zero on load), and nothing animates under "Reduce animations".
// With `unitClass` the last word ("Mbps") is split off and styled as a unit.
import { animate } from 'motion-v'
import { computed, onBeforeUnmount, ref, watch } from 'vue'

const props = defineProps<{
  value: number
  format: (value: number) => string
  unitClass?: string
}>()

const shown = ref(props.value)
let running: { stop: () => void } | null = null

watch(
  () => props.value,
  (to) => {
    running?.stop()
    if (document.documentElement.dataset.motion === 'reduced' || !Number.isFinite(to)) {
      shown.value = to
      return
    }
    running = animate(shown.value, to, {
      type: 'spring',
      stiffness: 190,
      damping: 28,
      mass: 0.8,
      onUpdate: (v: number) => {
        shown.value = v
      },
      onComplete: () => {
        shown.value = to
      },
    })
  },
)

onBeforeUnmount(() => running?.stop())

const text = computed(() => props.format(shown.value))
const split = computed(() => {
  const at = text.value.lastIndexOf(' ')
  return at < 0
    ? { number: text.value, unit: '' }
    : { number: text.value.slice(0, at), unit: text.value.slice(at + 1) }
})
</script>

<template>
  <span v-if="unitClass && split.unit"
    >{{ split.number }}{{ ' ' }}<span :class="unitClass">{{ split.unit }}</span></span
  >
  <span v-else>{{ text }}</span>
</template>

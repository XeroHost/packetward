<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts" generic="T extends string">
// A few mutually exclusive choices in a soft well; the selected one is a raised pill that slides
// to the new option on a spring. Arrow keys move the choice (radio-group semantics).
import { Motion } from 'motion-v'
import { useId } from 'vue'
import { springSnappy } from '@/lib/motion'

defineProps<{ options: readonly { value: T; label: string }[]; label: string }>()
const model = defineModel<T>({ required: true })
const uid = useId()

function move(options: readonly { value: T }[], step: number): void {
  const at = options.findIndex((o) => o.value === model.value)
  const next = options[(at + step + options.length) % options.length]
  if (next) model.value = next.value
}
</script>

<template>
  <div
    role="radiogroup"
    :aria-label="label"
    class="bg-surface-2 relative inline-flex gap-0.5 rounded-[12px] p-1"
  >
    <button
      v-for="option in options"
      :key="option.value"
      type="button"
      role="radio"
      :aria-checked="model === option.value"
      :tabindex="model === option.value ? 0 : -1"
      class="relative rounded-[9px] px-3.5 py-1.5 text-[13px] font-medium transition-colors"
      :class="model === option.value ? 'text-text' : 'text-text-muted hover:text-text'"
      @click="model = option.value"
      @keydown.right.prevent="move(options, 1)"
      @keydown.left.prevent="move(options, -1)"
    >
      <Motion
        v-if="model === option.value"
        :layout-id="`seg-${uid}`"
        class="bg-surface-3 absolute inset-0 rounded-[9px]"
        :transition="springSnappy"
        aria-hidden="true"
      />
      <span class="relative">{{ option.label }}</span>
    </button>
  </div>
</template>

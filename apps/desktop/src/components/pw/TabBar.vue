<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts" generic="T extends string">
// Tabs over a hairline; the selected tab's underline slides between tabs on a spring. Arrow keys
// move between tabs and focus follows (WAI-ARIA tabs). The panel is the caller's, labelled by
// `${idPrefix}-tab-${id}` and controlled through `${idPrefix}-panel`.
import { Motion } from 'motion-v'
import { nextTick } from 'vue'
import { springSnappy } from '@/lib/motion'

const props = defineProps<{
  tabs: readonly { id: T; label: string }[]
  label: string
  idPrefix: string
}>()
const model = defineModel<T>({ required: true })

async function move(step: number): Promise<void> {
  const at = props.tabs.findIndex((tab) => tab.id === model.value)
  const next = props.tabs[(at + step + props.tabs.length) % props.tabs.length]
  if (!next) return
  model.value = next.id
  await nextTick()
  document.getElementById(`${props.idPrefix}-tab-${next.id}`)?.focus()
}
</script>

<template>
  <div role="tablist" :aria-label="label" class="border-hairline flex gap-6 border-b">
    <button
      v-for="tab in tabs"
      :id="`${idPrefix}-tab-${tab.id}`"
      :key="tab.id"
      type="button"
      role="tab"
      :aria-selected="model === tab.id"
      :aria-controls="`${idPrefix}-panel`"
      :tabindex="model === tab.id ? 0 : -1"
      class="relative -mb-px py-2.5 text-[13px] font-medium transition-colors"
      :class="model === tab.id ? 'text-text' : 'text-text-muted hover:text-text'"
      @click="model = tab.id"
      @keydown.right.prevent="move(1)"
      @keydown.left.prevent="move(-1)"
    >
      {{ tab.label }}
      <Motion
        v-if="model === tab.id"
        :layout-id="`${idPrefix}-underline`"
        class="bg-text absolute right-0 -bottom-px left-0 h-0.5 rounded-full"
        :transition="springSnappy"
        aria-hidden="true"
      />
    </button>
  </div>
</template>

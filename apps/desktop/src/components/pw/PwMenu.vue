<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// The app's action menu: a button that opens a list of commands. It is portaled to the page and places
// itself away from the window edges and the sidebar (collision-aware), so it can never open behind
// them like a hand-positioned list could. Arrow keys, Home/End, Esc and typing to jump come with it.
import {
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuPortal,
  DropdownMenuRoot,
  DropdownMenuTrigger,
} from 'reka-ui'

defineProps<{
  items: readonly { key: string; label: string }[]
  disabled?: boolean
}>()
const emit = defineEmits<{ select: [key: string] }>()
</script>

<template>
  <DropdownMenuRoot>
    <DropdownMenuTrigger as-child :disabled="disabled">
      <slot />
    </DropdownMenuTrigger>
    <DropdownMenuPortal>
      <DropdownMenuContent
        align="start"
        :side-offset="6"
        :collision-padding="12"
        avoid-collisions
        class="bg-surface-3 ring-hairline-strong z-50 min-w-56 max-w-[min(20rem,calc(100vw-1.5rem))] rounded-[14px] p-1 shadow-xl ring-1"
      >
        <DropdownMenuItem
          v-for="item in items"
          :key="item.key"
          :text-value="item.label"
          class="data-[highlighted]:bg-surface-2 flex cursor-default items-center rounded-[8px] px-2.5 py-1.5 text-sm outline-hidden select-none"
          @select="emit('select', item.key)"
        >
          {{ item.label }}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenuPortal>
  </DropdownMenuRoot>
</template>

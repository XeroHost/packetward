<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts" generic="T extends string | number">
// The app's dropdown: the themed Select (floating panel, check mark) behind a plain options list, so
// forms never fall back to the operating system's native <select> popup.
import type { HTMLAttributes } from 'vue'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'

defineProps<{
  options: readonly { value: T; label: string }[]
  disabled?: boolean
  ariaLabel?: string
  class?: HTMLAttributes['class']
}>()
const model = defineModel<T>({ required: true })
</script>

<template>
  <Select v-model="model" :disabled="disabled">
    <SelectTrigger :class="cn('w-full', $props.class)" :aria-label="ariaLabel">
      <SelectValue />
    </SelectTrigger>
    <SelectContent>
      <SelectItem v-for="option in options" :key="option.value" :value="option.value">
        {{ option.label }}
      </SelectItem>
    </SelectContent>
  </Select>
</template>

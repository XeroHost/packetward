<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import type { LucideIcon } from 'lucide-vue-next'
import { computed } from 'vue'
import { cn } from '@/lib/utils'

export type PillTone = 'neutral' | 'success' | 'warning' | 'danger'

const props = defineProps<{ label: string; value: string; tone: PillTone; icon: LucideIcon }>()

// Meaning is never carried by colour alone: every pill also has an icon and a text value.
const toneClass = computed(
  () =>
    ({
      neutral: 'text-text-muted',
      success: 'text-success',
      warning: 'text-warning',
      danger: 'text-brand-fg',
    })[props.tone],
)
</script>

<template>
  <div
    class="bg-surface-2 border-border inline-flex h-7 items-center gap-2 rounded-md border px-2.5 text-xs"
    role="status"
  >
    <span class="text-text-muted">{{ label }}</span>
    <span :class="cn('inline-flex items-center gap-1.5 font-medium', toneClass)">
      <component :is="icon" class="size-3.5" aria-hidden="true" />
      {{ value }}
    </span>
  </div>
</template>

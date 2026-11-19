<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import type { LucideIcon } from 'lucide-vue-next'
import { cn } from '@/lib/utils'

defineProps<{
  label: string
  value: string
  hint?: string
  icon?: LucideIcon
  /** Colour of the icon, from the design tokens. */
  tone?: 'inbound' | 'outbound' | 'neutral' | 'warning'
}>()

const toneClass = {
  inbound: 'text-chart-in',
  outbound: 'text-chart-out',
  neutral: 'text-text-muted',
  warning: 'text-warning',
} as const
</script>

<template>
  <div
    class="bg-surface border-border flex min-w-0 flex-col gap-1 rounded-lg border p-[var(--card-p)]"
    style="box-shadow: var(--shadow-card)"
  >
    <div class="text-text-muted flex items-center gap-2 text-xs">
      <component
        :is="icon"
        v-if="icon"
        :class="cn('size-4 shrink-0', toneClass[tone ?? 'neutral'])"
        aria-hidden="true"
      />
      <span class="truncate">{{ label }}</span>
    </div>
    <div class="font-mono text-2xl leading-tight tabular-nums" data-testid="tile-value">
      {{ value }}
    </div>
    <div v-if="hint" class="text-text-muted line-clamp-2 text-xs break-words">{{ hint }}</div>
  </div>
</template>

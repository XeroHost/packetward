<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed } from 'vue'
import HIcon from '@/components/pw/HIcon.vue'
import type { IconData } from '@/lib/icons'
import { cn } from '@/lib/utils'

export type PillTone = 'neutral' | 'success' | 'warning' | 'danger'

const props = defineProps<{
  label: string
  value: string
  tone: PillTone
  icon: IconData
  /** A state that is live right now (Guardian active): the icon carries a slow halo. */
  pulse?: boolean
}>()

// Meaning is never carried by colour alone: every status has an icon and a text value.
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
  <div class="inline-flex items-center gap-2 text-xs" role="status">
    <span class="text-text-muted">{{ label }}</span>
    <span :class="cn('inline-flex items-center gap-1.5 font-medium', toneClass)">
      <span :class="cn('inline-flex rounded-full', pulse && 'pw-pulse')">
        <HIcon :icon="icon" :size="15" />
      </span>
      {{ value }}
    </span>
  </div>
</template>

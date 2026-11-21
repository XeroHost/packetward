<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
// One setting or action: what it is and why on the left, the controls on the right. Rows are
// separated by hairlines, so a long page of controls reads as a list, not a wall of boxes.
defineProps<{ title: string; description?: string }>()
</script>

<template>
  <div
    class="border-hairline grid gap-x-12 gap-y-4 border-t py-(--setting-py) first:border-t-0 first:pt-0 md:grid-cols-[16rem_minmax(0,1fr)]"
  >
    <div class="min-w-0">
      <h3 class="text-[0.9375rem] font-semibold">{{ title }}</h3>
      <p v-if="description" class="text-text-muted mt-1 text-[13px] leading-relaxed">
        {{ description }}
      </p>
      <slot name="aside" />
    </div>
    <div class="flex min-w-0 flex-col gap-(--stack-gap)">
      <slot />
    </div>
  </div>
</template>

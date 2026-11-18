<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { RouterView } from 'vue-router'
import { TooltipProvider } from '@/components/ui/tooltip'
import AppShell from '@/components/pw/AppShell.vue'
</script>

<template>
  <TooltipProvider :delay-duration="300">
    <AppShell>
      <RouterView />
    </AppShell>
  </TooltipProvider>
</template>

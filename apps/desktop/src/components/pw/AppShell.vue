<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import AuditBanner from '@/components/pw/AuditBanner.vue'
import BlockDialog from '@/components/pw/BlockDialog.vue'
import RdpPendingBanner from '@/components/pw/RdpPendingBanner.vue'
import SidebarNav from '@/components/pw/SidebarNav.vue'
import TopBar from '@/components/pw/TopBar.vue'
</script>

<template>
  <div class="bg-bg text-text flex h-screen overflow-hidden">
    <SidebarNav />
    <div class="flex min-w-0 flex-1 flex-col">
      <TopBar />
      <RdpPendingBanner />
      <AuditBanner />
      <main class="flex-1 overflow-y-auto p-5">
        <slot />
      </main>
      <BlockDialog />
    </div>
  </div>
</template>

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// Floating-panel layout: title bar on top, the sidebar melts into the window, and the page lives
// in one rounded panel inset from the window edge. Pages change with a short spring.
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterView, useRoute } from 'vue-router'
import AuditBanner from '@/components/pw/AuditBanner.vue'
import BlockDialog from '@/components/pw/BlockDialog.vue'
import RdpPendingBanner from '@/components/pw/RdpPendingBanner.vue'
import SidebarNav from '@/components/pw/SidebarNav.vue'
import TitleBar from '@/components/pw/TitleBar.vue'
import { panelTransition } from '@/lib/motion'

const { t } = useI18n()
const route = useRoute()
const title = computed(() => t(String(route.meta.titleKey ?? 'app.name')))
</script>

<template>
  <div class="pw-window text-text flex h-screen flex-col overflow-hidden">
    <TitleBar />
    <div class="flex min-h-0 flex-1">
      <SidebarNav />
      <section
        class="pw-panel mr-[var(--gutter)] mb-[var(--gutter)] flex min-w-0 flex-1 flex-col overflow-hidden"
      >
        <RdpPendingBanner />
        <AuditBanner />
        <main class="flex min-h-0 flex-1 flex-col overflow-y-auto px-9 pt-8 pb-10">
          <h1 class="mb-7 shrink-0 text-[1.75rem] leading-none font-semibold tracking-tight">
            {{ title }}
          </h1>
          <RouterView v-slot="{ Component }">
            <Transition
              :css="false"
              mode="out-in"
              @before-enter="panelTransition.beforeEnter"
              @enter="panelTransition.enter"
              @leave="panelTransition.leave"
            >
              <component :is="Component" />
            </Transition>
          </RouterView>
        </main>
      </section>
      <BlockDialog />
    </div>
  </div>
</template>

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// Floating-panel layout: title bar on top, the sidebar melts into the window, and the page lives
// in one rounded panel inset from the window edge. Pages change with a short spring.
import { animate } from 'motion-v'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterView, useRoute } from 'vue-router'
import AuditBanner from '@/components/pw/AuditBanner.vue'
import BlockDialog from '@/components/pw/BlockDialog.vue'
import RdpPendingBanner from '@/components/pw/RdpPendingBanner.vue'
import SidebarNav from '@/components/pw/SidebarNav.vue'
import TitleBar from '@/components/pw/TitleBar.vue'
import { exitFast, springPage } from '@/lib/motion'

const { t } = useI18n()
const route = useRoute()
/** Pages change with a short spring: they rise in, and drop out faster than they came. */
const reduced = (): boolean => document.documentElement.dataset.motion === 'reduced'
function beforeEnter(el: Element): void {
  if (!reduced()) (el as HTMLElement).style.opacity = '0'
}
function enter(el: Element, done: () => void): void {
  if (reduced()) return done()
  animate(el, { opacity: [0, 1], y: [10, 0] }, { ...springPage, onComplete: done })
}
function leave(el: Element, done: () => void): void {
  if (reduced()) return done()
  animate(el, { opacity: 0, y: -4 }, { ...exitFast, onComplete: done })
}

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
        <main class="min-h-0 flex-1 overflow-y-auto px-9 pt-8 pb-10">
          <h1 class="mb-7 text-[1.75rem] leading-none font-semibold tracking-tight">{{ title }}</h1>
          <RouterView v-slot="{ Component }">
            <Transition
              :css="false"
              mode="out-in"
              @before-enter="beforeEnter"
              @enter="enter"
              @leave="leave"
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

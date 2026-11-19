<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Info } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { RouterLink } from 'vue-router'
import { NAV_ITEMS } from '@/app/nav'
import BrandLogo from '@/components/pw/BrandLogo.vue'
import { useAlertsStore } from '@/stores/alerts'

const { t } = useI18n()
const alerts = useAlertsStore()
</script>

<template>
  <aside class="border-border bg-surface flex w-60 shrink-0 flex-col border-r">
    <div class="flex h-12 items-center px-4">
      <BrandLogo height-class="h-7" />
    </div>

    <nav :aria-label="t('nav.label')" class="flex-1 overflow-y-auto px-2 py-2">
      <ul class="flex flex-col gap-0.5">
        <li v-for="item in NAV_ITEMS" :key="item.id">
          <RouterLink
            :to="`/${item.id}`"
            class="text-text-muted hover:bg-surface-2 hover:text-text relative flex h-9 items-center gap-3 rounded-md px-3 text-sm font-medium transition-colors"
            active-class="!bg-surface-3 !text-text nav-active"
          >
            <component :is="item.icon" class="size-4 shrink-0" aria-hidden="true" />
            <span class="truncate">{{ t(item.labelKey) }}</span>
            <span
              v-if="item.id === 'alerts' && alerts.unread > 0"
              class="bg-danger text-text-on-brand ml-auto min-w-5 rounded-full px-1.5 text-center text-[10px] leading-5 font-semibold"
              :aria-label="t('alerts.unread', { count: alerts.unread })"
            >
              {{ alerts.unread > 99 ? '99+' : alerts.unread }}
            </span>
          </RouterLink>
        </li>
      </ul>
    </nav>

    <footer class="border-border flex items-center justify-between border-t px-4 py-3 text-xs">
      <RouterLink
        to="/about"
        class="text-text-muted hover:text-text inline-flex items-center gap-1.5 rounded-sm"
        active-class="!text-text"
      >
        <Info class="size-3.5" aria-hidden="true" />
        {{ t('app.byXeroHost') }}
      </RouterLink>
    </footer>
  </aside>
</template>

<style scoped>
/* Active page: a crimson bar on the leading edge (DESIGN.md: --brand for the active nav bar). */
.nav-active::before {
  content: '';
  position: absolute;
  left: 0;
  top: 6px;
  bottom: 6px;
  width: 3px;
  border-radius: 0 3px 3px 0;
  background: var(--brand);
}
</style>

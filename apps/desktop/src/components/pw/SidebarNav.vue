<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// The sidebar is part of the window, not a card: no background, no divider. The active page is a
// soft pill that slides between rows on a spring; each icon draws itself when its row is hovered.
import { LayoutGroup, Motion } from 'motion-v'
import { computed, reactive } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterLink, useRoute } from 'vue-router'
import { NAV_GROUPS, NAV_ITEMS } from '@/app/nav'
import HIcon from '@/components/pw/HIcon.vue'
import { InformationCircleIcon } from '@/lib/icons'
import { springSnappy } from '@/lib/motion'
import { useAlertsStore } from '@/stores/alerts'

const { t } = useI18n()
const alerts = useAlertsStore()
const route = useRoute()

const groups = computed(() =>
  NAV_GROUPS.map((group) => ({ group, items: NAV_ITEMS.filter((i) => i.group === group) })),
)

/** Replays an icon's drawing animation: bumped on hover and on keyboard focus. */
const play = reactive<Record<string, number>>({})
function replay(id: string): void {
  play[id] = (play[id] ?? 0) + 1
}
const isActive = (id: string): boolean => route.path === `/${id}`
</script>

<template>
  <aside class="flex w-[var(--sidebar-w)] shrink-0 flex-col pb-3">
    <nav :aria-label="t('nav.label')" class="flex-1 overflow-y-auto px-3">
      <LayoutGroup>
        <div v-for="section in groups" :key="section.group" class="mb-5 last:mb-0">
          <h2
            class="text-text-muted mb-1.5 px-3 font-sans text-[11px] font-medium tracking-wide uppercase opacity-70"
          >
            {{ t(`nav.groups.${section.group}`) }}
          </h2>
          <ul class="flex flex-col gap-0.5">
            <li v-for="item in section.items" :key="item.id">
              <RouterLink
                :to="`/${item.id}`"
                class="group relative flex h-9 items-center gap-3 rounded-[10px] px-3 text-[13px] font-medium"
                :class="isActive(item.id) ? 'text-text' : 'text-text-muted hover:text-text'"
                @mouseenter="replay(item.id)"
                @focus="replay(item.id)"
              >
                <Motion
                  v-if="isActive(item.id)"
                  layout-id="nav-pill"
                  class="pw-panel absolute inset-0 !rounded-[10px]"
                  :transition="springSnappy"
                  aria-hidden="true"
                />
                <span
                  v-else
                  class="bg-hairline absolute inset-0 rounded-[10px] opacity-0 transition-opacity duration-150 group-hover:opacity-100"
                  aria-hidden="true"
                />
                <HIcon :icon="item.icon" :size="17" :play="play[item.id] ?? 0" class="relative" />
                <span class="relative truncate">{{ t(item.labelKey) }}</span>
                <span
                  v-if="item.id === 'alerts' && alerts.unread > 0"
                  class="bg-danger text-on-brand relative ml-auto min-w-5 rounded-full px-1.5 text-center text-[10px] leading-5 font-semibold"
                  :aria-label="t('alerts.unread', { count: alerts.unread })"
                >
                  {{ alerts.unread > 99 ? '99+' : alerts.unread }}
                </span>
              </RouterLink>
            </li>
          </ul>
        </div>
      </LayoutGroup>
    </nav>

    <footer class="px-3 pt-2">
      <RouterLink
        to="/about"
        class="text-text-muted hover:text-text inline-flex items-center gap-2 rounded-[10px] px-3 py-2 text-xs transition-colors"
        :class="route.path === '/about' && '!text-text'"
      >
        <HIcon :icon="InformationCircleIcon" :size="15" />
        {{ t('app.byXeroHost') }}
      </RouterLink>
    </footer>
  </aside>
</template>

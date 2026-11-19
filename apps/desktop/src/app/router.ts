// SPDX-License-Identifier: GPL-3.0-or-later
import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router'
import { NAV_ITEMS } from './nav'

const PlaceholderPage = () => import('@/features/placeholder/PlaceholderPage.vue')
const DashboardPage = () => import('@/features/dashboard/DashboardPage.vue')
const SettingsPage = () => import('@/features/settings/SettingsPage.vue')
const AboutPage = () => import('@/features/about/AboutPage.vue')

const pageComponents: Record<string, RouteRecordRaw['component']> = {
  dashboard: DashboardPage,
  settings: SettingsPage,
}

const pageRoutes: RouteRecordRaw[] = NAV_ITEMS.map((item) => ({
  path: `/${item.id}`,
  name: item.id,
  component: pageComponents[item.id] ?? PlaceholderPage,
  meta: { titleKey: item.labelKey },
}))

// Hash history: the app is served from the Tauri asset protocol, not a web server.
export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', redirect: '/dashboard' },
    ...pageRoutes,
    { path: '/about', name: 'about', component: AboutPage, meta: { titleKey: 'nav.about' } },
    { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
  ],
})

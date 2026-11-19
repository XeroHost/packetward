// SPDX-License-Identifier: GPL-3.0-or-later
import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router'
import { NAV_ITEMS } from './nav'

const PlaceholderPage = () => import('@/features/placeholder/PlaceholderPage.vue')
const DashboardPage = () => import('@/features/dashboard/DashboardPage.vue')
const ConnectionsPage = () => import('@/features/connections/ConnectionsPage.vue')
const AlertsPage = () => import('@/features/alerts/AlertsPage.vue')
const FirewallPage = () => import('@/features/firewall/FirewallPage.vue')
const GuardianPage = () => import('@/features/guardian/GuardianPage.vue')
const RdpShieldPage = () => import('@/features/rdp/RdpShieldPage.vue')
const SpeedTestPage = () => import('@/features/speed/SpeedTestPage.vue')
const ThreatIntelPage = () => import('@/features/intel/ThreatIntelPage.vue')
const LogsPage = () => import('@/features/logs/LogsPage.vue')
const TrafficPage = () => import('@/features/traffic/TrafficPage.vue')
const CapturePage = () => import('@/features/capture/CapturePage.vue')
const DiagnosticsPage = () => import('@/features/diagnostics/DiagnosticsPage.vue')
const SettingsPage = () => import('@/features/settings/SettingsPage.vue')
const AboutPage = () => import('@/features/about/AboutPage.vue')

const pageComponents: Record<string, RouteRecordRaw['component']> = {
  dashboard: DashboardPage,
  alerts: AlertsPage,
  traffic: TrafficPage,
  'speed-test': SpeedTestPage,
  'threat-intel': ThreatIntelPage,
  logs: LogsPage,
  'rdp-shield': RdpShieldPage,
  firewall: FirewallPage,
  guardian: GuardianPage,
  connections: ConnectionsPage,
  capture: CapturePage,
  diagnostics: DiagnosticsPage,
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

// SPDX-License-Identifier: GPL-3.0-or-later
import {
  Activity,
  Bell,
  BrickWall,
  Gauge,
  LayoutDashboard,
  Network,
  Radar,
  Radio,
  ScrollText,
  Settings,
  Shield,
  Stethoscope,
  type LucideIcon,
} from 'lucide-vue-next'

export interface NavItem {
  /** Route path and name. */
  readonly id: string
  /** Key under `nav.*` in the locale files. */
  readonly labelKey: string
  readonly icon: LucideIcon
}

/** Sidebar entries, in display order (docs/ROADMAP.md M0). */
export const NAV_ITEMS: readonly NavItem[] = [
  { id: 'dashboard', labelKey: 'nav.dashboard', icon: LayoutDashboard },
  { id: 'alerts', labelKey: 'nav.alerts', icon: Bell },
  { id: 'traffic', labelKey: 'nav.traffic', icon: Activity },
  { id: 'connections', labelKey: 'nav.connections', icon: Network },
  { id: 'capture', labelKey: 'nav.capture', icon: Radio },
  { id: 'guardian', labelKey: 'nav.guardian', icon: Shield },
  { id: 'firewall', labelKey: 'nav.firewall', icon: BrickWall },
  { id: 'diagnostics', labelKey: 'nav.diagnostics', icon: Stethoscope },
  { id: 'speed-test', labelKey: 'nav.speedTest', icon: Gauge },
  { id: 'threat-intel', labelKey: 'nav.threatIntel', icon: Radar },
  { id: 'logs', labelKey: 'nav.logs', icon: ScrollText },
  { id: 'settings', labelKey: 'nav.settings', icon: Settings },
]

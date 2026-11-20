// SPDX-License-Identifier: GPL-3.0-or-later
import {
  Activity01Icon,
  DashboardSpeed01Icon,
  DashboardSquare01Icon,
  FirewallIcon,
  Globe02Icon,
  LockComputerIcon,
  Notification01Icon,
  RadarIcon,
  Radio01Icon,
  ScrollTextIcon,
  Settings02Icon,
  Shield01Icon,
  StethoscopeIcon,
  type IconAnimation,
  type IconData,
} from '@/lib/icons'

/** Sidebar sections, in display order. */
export type NavGroup = 'observe' | 'defend' | 'tools' | 'system'

export interface NavItem {
  /** Route path and name. */
  readonly id: string
  /** Key under `nav.*` in the locale files. */
  readonly labelKey: string
  readonly icon: IconData
  readonly group: NavGroup
  /** How the icon moves on hover: what it stands for, not one effect for all. */
  readonly anim: IconAnimation
}

/** Sidebar entries, in display order (docs/ROADMAP.md M0). */
export const NAV_ITEMS: readonly NavItem[] = [
  {
    id: 'dashboard',
    labelKey: 'nav.dashboard',
    icon: DashboardSquare01Icon,
    group: 'observe',
    anim: 'pop',
  },
  {
    id: 'alerts',
    labelKey: 'nav.alerts',
    icon: Notification01Icon,
    group: 'observe',
    anim: 'ring',
  },
  { id: 'traffic', labelKey: 'nav.traffic', icon: Activity01Icon, group: 'observe', anim: 'wave' },
  {
    id: 'connections',
    labelKey: 'nav.connections',
    icon: Globe02Icon,
    group: 'observe',
    anim: 'orbit',
  },
  { id: 'capture', labelKey: 'nav.capture', icon: Radio01Icon, group: 'observe', anim: 'blink' },
  { id: 'guardian', labelKey: 'nav.guardian', icon: Shield01Icon, group: 'defend', anim: 'pulse' },
  {
    id: 'rdp-shield',
    labelKey: 'nav.rdpShield',
    icon: LockComputerIcon,
    group: 'defend',
    anim: 'bob',
  },
  {
    id: 'firewall',
    labelKey: 'nav.firewall',
    icon: FirewallIcon,
    group: 'defend',
    anim: 'flicker',
  },
  {
    id: 'diagnostics',
    labelKey: 'nav.diagnostics',
    icon: StethoscopeIcon,
    group: 'tools',
    anim: 'tilt',
  },
  {
    id: 'speed-test',
    labelKey: 'nav.speedTest',
    icon: DashboardSpeed01Icon,
    group: 'tools',
    anim: 'sweep',
  },
  {
    id: 'threat-intel',
    labelKey: 'nav.threatIntel',
    icon: RadarIcon,
    group: 'tools',
    anim: 'ping',
  },
  { id: 'logs', labelKey: 'nav.logs', icon: ScrollTextIcon, group: 'system', anim: 'scroll' },
  { id: 'settings', labelKey: 'nav.settings', icon: Settings02Icon, group: 'system', anim: 'spin' },
]

export const NAV_GROUPS: readonly NavGroup[] = ['observe', 'defend', 'tools', 'system']

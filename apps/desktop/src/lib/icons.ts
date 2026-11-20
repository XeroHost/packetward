// SPDX-License-Identifier: GPL-3.0-or-later
// The icons the UI uses, from Hugeicons' free set (MIT, @hugeicons/core-free-icons). One place, so
// the bundle only carries these and a page never imports an icon package directly.
export {
  Activity01Icon,
  Alert02Icon,
  AlertCircleIcon,
  ArrowDownLeft01Icon,
  ArrowUpRight01Icon,
  Cancel01Icon,
  CheckmarkCircle02Icon,
  Copy01Icon,
  DashboardSquare01Icon,
  DashboardSpeed01Icon,
  FirewallIcon,
  Globe02Icon,
  InformationCircleIcon,
  Loading03Icon,
  LockComputerIcon,
  Notification01Icon,
  RadarIcon,
  Radio01Icon,
  ScrollTextIcon,
  Settings02Icon,
  Shield01Icon,
  ShieldAlertIcon,
  ShieldBanIcon,
  ShieldCheckIcon,
  StethoscopeIcon,
  Tick02Icon,
} from '@hugeicons/core-free-icons'

/** The shape every Hugeicons export has: a list of [svg tag, attributes]. */
export type IconData = readonly (readonly [string, Readonly<Record<string, string | number>>])[]

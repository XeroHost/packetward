// SPDX-License-Identifier: GPL-3.0-or-later
// The icons the UI uses, from Hugeicons' free set (MIT, @hugeicons/core-free-icons). One place, so
// the bundle only carries these and a page never imports an icon package directly.
export {
  Activity01Icon,
  Add01Icon,
  Alert02Icon,
  AlertCircleIcon,
  ArrowDown01Icon,
  ArrowDownLeft01Icon,
  ArrowUp01Icon,
  ArrowUpDownIcon,
  ArrowUpRight01Icon,
  Cancel01Icon,
  CheckListIcon,
  CheckmarkCircle02Icon,
  ClipboardCopyIcon,
  Copy01Icon,
  DashboardSpeed01Icon,
  DashboardSquare01Icon,
  Delete02Icon,
  Download04Icon,
  FileArchiveIcon,
  FirewallIcon,
  FloppyDiskIcon,
  GaugeIcon,
  Globe02Icon,
  HourglassIcon,
  InformationCircleIcon,
  Key01Icon,
  LifebuoyIcon,
  Loading03Icon,
  MinusSignIcon,
  LockComputerIcon,
  Logout01Icon,
  Notification01Icon,
  NotificationOff01Icon,
  Package01Icon,
  PlayIcon,
  PlugSocketIcon,
  PlugZapIcon,
  Refresh01Icon,
  RadarIcon,
  Radio01Icon,
  RecordIcon,
  ScrollTextIcon,
  Search01Icon,
  ServerOffIcon,
  Settings02Icon,
  Shield01Icon,
  ShieldAlertIcon,
  ShieldBanIcon,
  ShieldCheckIcon,
  ShieldKeyIcon,
  ShieldQuestionMarkIcon,
  StethoscopeIcon,
  StopIcon,
  Tick02Icon,
  Timer02Icon,
  Wrench01Icon,
} from '@hugeicons/core-free-icons'

/** How an icon moves on hover: `draw` traces its stroke, the rest are one-shot keyframes. */
export type IconAnimation =
  | 'draw'
  | 'ring'
  | 'spin'
  | 'pulse'
  | 'pop'
  | 'wave'
  | 'orbit'
  | 'blink'
  | 'bob'
  | 'flicker'
  | 'tilt'
  | 'sweep'
  | 'ping'
  | 'scroll'

/** The shape every Hugeicons export has: a list of [svg tag, attributes]. */
export type IconData = readonly (readonly [string, Readonly<Record<string, string | number>>])[]

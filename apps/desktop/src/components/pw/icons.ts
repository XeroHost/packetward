// SPDX-License-Identifier: GPL-3.0-or-later
// Icon components under the names the pages already use, drawn from Hugeicons (MIT) through HIcon.
// A page writes <Play class="size-4" /> and gets an icon that draws itself when its parent asks.
import { defineComponent, h, type Component } from 'vue'
import HIcon from '@/components/pw/HIcon.vue'
import {
  Add01Icon,
  Alert02Icon,
  ArrowDown01Icon,
  ArrowUp01Icon,
  ArrowUpDownIcon,
  ArrowUpRight01Icon,
  CheckListIcon,
  ClipboardCopyIcon,
  Copy01Icon,
  Delete02Icon,
  Download04Icon,
  FileArchiveIcon,
  FloppyDiskIcon,
  GaugeIcon,
  Globe02Icon,
  HourglassIcon,
  Key01Icon,
  LifebuoyIcon,
  Loading03Icon,
  Logout01Icon,
  NotificationOff01Icon,
  Package01Icon,
  PlayIcon,
  PlugSocketIcon,
  PlugZapIcon,
  RadarIcon,
  RecordIcon,
  ScrollTextIcon,
  Search01Icon,
  ServerOffIcon,
  ShieldBanIcon,
  ShieldCheckIcon,
  ShieldKeyIcon,
  ShieldQuestionMarkIcon,
  StopIcon,
  Tick02Icon,
  Timer02Icon,
  Wrench01Icon,
  type IconData,
} from '@/lib/icons'

function icon(data: IconData, size = 16): Component {
  return defineComponent({
    inheritAttrs: false,
    setup(_, { attrs }) {
      return () => h(HIcon, { icon: data, size, ...attrs })
    },
  })
}

export const Check = icon(Tick02Icon)
export const ChevronDown = icon(ArrowDown01Icon)
export const ChevronUp = icon(ArrowUp01Icon)
export const Copy = icon(Copy01Icon)
export const ShieldBan = icon(ShieldBanIcon)
export const Timer = icon(Timer02Icon)
export const TriangleAlert = icon(Alert02Icon)
export const ExternalLink = icon(ArrowUpRight01Icon)
export const KeyRound = icon(Key01Icon)
export const LoaderCircle = icon(Loading03Icon)
export const LogOut = icon(Logout01Icon)
export const PlugZap = icon(PlugZapIcon)
export const ServerOff = icon(ServerOffIcon)
export const Wrench = icon(Wrench01Icon)
export const BellOff = icon(NotificationOff01Icon)
export const Trash2 = icon(Delete02Icon)
export const Play = icon(PlayIcon)
export const Square = icon(StopIcon)
export const Circle = icon(RecordIcon)
export const FileArchive = icon(FileArchiveIcon)
export const Save = icon(FloppyDiskIcon)
export const ArrowDown = icon(ArrowDown01Icon)
export const ArrowUp = icon(ArrowUp01Icon)
export const ArrowUpDown = icon(ArrowUpDownIcon)
export const Search = icon(Search01Icon)
export const ClipboardCopy = icon(ClipboardCopyIcon)
export const Download = icon(Download04Icon)
export const Plug = icon(PlugSocketIcon)
export const Plus = icon(Add01Icon)
export const ShieldCheck = icon(ShieldCheckIcon)
export const Globe2 = icon(Globe02Icon)
export const ListChecks = icon(CheckListIcon)
export const Radar = icon(RadarIcon)
export const ShieldQuestion = icon(ShieldQuestionMarkIcon)
export const ScrollText = icon(ScrollTextIcon)
export const Hourglass = icon(HourglassIcon)
export const LifeBuoy = icon(LifebuoyIcon)
export const ShieldHalf = icon(ShieldKeyIcon)
export const Gauge = icon(GaugeIcon)
export const PackageX = icon(Package01Icon)

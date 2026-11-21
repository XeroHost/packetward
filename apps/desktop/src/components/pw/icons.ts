// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
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
  type IconAnimation,
  type IconData,
} from '@/lib/icons'

function icon(data: IconData, animation: IconAnimation = 'draw', size = 16): Component {
  return defineComponent({
    inheritAttrs: false,
    setup(_, { attrs }) {
      return () => h(HIcon, { icon: data, size, animation, ...attrs })
    },
  })
}

export const Check = icon(Tick02Icon, 'pop')
export const ChevronDown = icon(ArrowDown01Icon)
export const ChevronUp = icon(ArrowUp01Icon)
export const Copy = icon(Copy01Icon, 'pop')
export const ShieldBan = icon(ShieldBanIcon, 'pulse')
export const Timer = icon(Timer02Icon, 'spin')
export const TriangleAlert = icon(Alert02Icon)
export const ExternalLink = icon(ArrowUpRight01Icon, 'wave')
export const KeyRound = icon(Key01Icon)
export const LoaderCircle = icon(Loading03Icon, 'draw')
export const LogOut = icon(Logout01Icon)
export const PlugZap = icon(PlugZapIcon, 'pop')
export const ServerOff = icon(ServerOffIcon)
export const Wrench = icon(Wrench01Icon, 'tilt')
export const BellOff = icon(NotificationOff01Icon, 'ring')
export const Trash2 = icon(Delete02Icon, 'tilt')
export const Play = icon(PlayIcon, 'wave')
export const Square = icon(StopIcon, 'pop')
export const Circle = icon(RecordIcon)
export const FileArchive = icon(FileArchiveIcon)
export const Save = icon(FloppyDiskIcon, 'bob')
export const ArrowDown = icon(ArrowDown01Icon, 'bob')
export const ArrowUp = icon(ArrowUp01Icon, 'bob')
export const ArrowUpDown = icon(ArrowUpDownIcon)
export const Search = icon(Search01Icon, 'tilt')
export const ClipboardCopy = icon(ClipboardCopyIcon)
export const Download = icon(Download04Icon, 'bob')
export const Plug = icon(PlugSocketIcon, 'bob')
export const Plus = icon(Add01Icon, 'pop')
export const ShieldCheck = icon(ShieldCheckIcon, 'pulse')
export const Globe2 = icon(Globe02Icon, 'orbit')
export const ListChecks = icon(CheckListIcon)
export const Radar = icon(RadarIcon, 'ping')
export const ShieldQuestion = icon(ShieldQuestionMarkIcon)
export const ScrollText = icon(ScrollTextIcon, 'scroll')
export const Hourglass = icon(HourglassIcon)
export const LifeBuoy = icon(LifebuoyIcon)
export const ShieldHalf = icon(ShieldKeyIcon)
export const Gauge = icon(GaugeIcon, 'sweep')
export const PackageX = icon(Package01Icon)

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { onClickOutside } from '@vueuse/core'
import { Check, ChevronDown, ClipboardCopy, Download, Play, Square } from '@/components/pw/icons'
import { computed, onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { MTR_ADVANCED_MIN_MINOR, type MtrExportFormat, type MtrModeView } from '@/api/diag'
import { Button } from '@/components/ui/button'
import IpCell from '@/components/pw/IpCell.vue'
import { copyText } from '@/lib/clipboard'
import { downloadText, mimeOfExport } from '@/lib/download'
import { useAgentStore } from '@/stores/agent'
import { MTR_DEFAULT_PORT, useDiagStore, type MtrAdvanced } from '@/stores/diag'
import { useSpeedStore } from '@/stores/speed'
import { formatLoss, formatMs, isIcmpRateLimited, lossLevel } from './diagFormat'
import FailureNote from './FailureNote.vue'
import { FIELD } from './fieldClass'
import PwSelect from '@/components/pw/PwSelect.vue'

const { t } = useI18n()
const diag = useDiagStore()
const agent = useAgentStore()
const speed = useSpeedStore()

/** Agents older than protocol 1.10 only know ICMP and cannot export. */
const advancedSupported = computed(() => agent.protocolMinor >= MTR_ADVANCED_MIN_MINOR)

const target = ref('')
const cycles = ref(20)
const resolveNames = ref(true)
const mode = ref<MtrModeView>('icmp')
// An empty field means "the agent's default": it is simply not sent.
const port = ref<number | string>('')
const packetSize = ref<number | string>('')
const intervalMs = ref<number | string>('')
const maxHops = ref<number | string>('')
const preferIpv6 = ref(false)

const copied = ref(false)
const copyFailed = ref(false)
let copiedTimer: ReturnType<typeof setTimeout> | null = null
const exportOpen = ref(false)
const exportMenu = ref<HTMLElement | null>(null)
const exportNote = ref<{ kind: 'saved' | 'copied' | 'failed'; name?: string } | null>(null)
let noteTimer: ReturnType<typeof setTimeout> | null = null

onClickOutside(exportMenu, () => (exportOpen.value = false))

const usesPort = computed(() => mode.value !== 'icmp')
const canStart = computed(() => target.value.trim() !== '' && !diag.mtrRunning)
const hops = computed(() => diag.mtrSnapshot?.hops ?? [])
const snapshotMode = computed<MtrModeView>(() => diag.mtrSnapshot?.mode ?? 'icmp')

/** `''` (not given) or a whole number clamped into `min..max`. */
function optional(value: number | string, min: number, max: number): number | undefined {
  if (value === '' || value === null) return undefined
  const n = Math.floor(Number(value))
  if (!Number.isFinite(n)) return undefined
  return Math.min(max, Math.max(min, n))
}

function advancedOptions(): MtrAdvanced {
  const advanced: MtrAdvanced = {
    packetSize: optional(packetSize.value, 0, 1472),
    maxHops: optional(maxHops.value, 1, 64),
  }
  if (advancedSupported.value) {
    advanced.mode = mode.value
    advanced.intervalMs = optional(intervalMs.value, 200, 60_000)
    advanced.preferIpv6 = preferIpv6.value
    if (usesPort.value) advanced.port = optional(port.value, 1, 65_535)
  }
  return advanced
}

function start(): void {
  if (!canStart.value) return
  exportNote.value = null
  void diag.runMtr(
    target.value.trim(),
    Math.min(200, Math.max(1, Math.floor(cycles.value) || 1)),
    resolveNames.value,
    advancedOptions(),
  )
}

function flash(note: NonNullable<typeof exportNote.value>): void {
  exportNote.value = note
  if (noteTimer !== null) clearTimeout(noteTimer)
  noteTimer = setTimeout(() => (exportNote.value = null), 4000)
}

async function copyReport(): Promise<void> {
  const text = await diag.mtrReportText()
  if (text === null) return
  copyFailed.value = !(await copyText(text))
  copied.value = !copyFailed.value
  if (copiedTimer !== null) clearTimeout(copiedTimer)
  copiedTimer = setTimeout(() => {
    copied.value = false
    copyFailed.value = false
  }, 2500)
}

/** Renders the current table in `format` on the agent, then saves it as a file or copies it. */
async function exportAs(format: MtrExportFormat, action: 'save' | 'copy'): Promise<void> {
  exportOpen.value = false
  const sourceIp = speed.results.find((r) => r.source_ip)?.source_ip
  const file = await diag.mtrExport(format, sourceIp)
  if (file === null) return
  if (action === 'copy') {
    flash({ kind: (await copyText(file.content)) ? 'copied' : 'failed' })
  } else {
    flash(
      downloadText(file.filename, file.content, mimeOfExport(format))
        ? { kind: 'saved', name: file.filename }
        : { kind: 'failed' },
    )
  }
}

onBeforeUnmount(() => {
  if (copiedTimer !== null) clearTimeout(copiedTimer)
  if (noteTimer !== null) clearTimeout(noteTimer)
})

const LEVEL_CLASS = { ok: '', warn: 'text-warning', bad: 'text-danger' } as const
const EXPORT_ITEMS: { format: MtrExportFormat; action: 'save' | 'copy'; key: string }[] = [
  { format: 'csv', action: 'save', key: 'saveCsv' },
  { format: 'json', action: 'save', key: 'saveJson' },
  { format: 'text', action: 'save', key: 'saveText' },
  { format: 'csv', action: 'copy', key: 'copyCsv' },
  { format: 'json', action: 'copy', key: 'copyJson' },
]

/** `echo-reply` -> the translated "ICMP echo reply" etc. */
function reachLabel(reach: string): string {
  return t(`diagnostics.mtr.reach.${reach.replace(/-/g, '_')}`)
}

const modeOptions = [
  { value: 'icmp', label: 'ICMP' },
  { value: 'udp', label: 'UDP' },
  { value: 'tcp', label: 'TCP SYN' },
] as const
</script>

<template>
  <div class="flex flex-col gap-4">
    <form class="flex flex-wrap items-end gap-3" @submit.prevent="start">
      <label class="flex min-w-64 flex-1 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.target') }}</span>
        <input
          v-model="target"
          :class="[FIELD, 'font-mono']"
          type="text"
          spellcheck="false"
          autocomplete="off"
          :placeholder="t('diagnostics.targetPlaceholder')"
          :disabled="diag.mtrRunning"
        />
      </label>
      <label class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.mtr.cycles') }}</span>
        <input
          v-model.number="cycles"
          :class="FIELD"
          type="number"
          min="1"
          max="200"
          :disabled="diag.mtrRunning"
        />
      </label>
      <label class="flex h-9 items-center gap-2 text-sm">
        <input v-model="resolveNames" type="checkbox" :disabled="diag.mtrRunning" />
        {{ t('diagnostics.mtr.resolveNames') }}
      </label>
      <Button v-if="!diag.mtrRunning" type="submit" :disabled="!canStart">
        <Play aria-hidden="true" />{{ t('diagnostics.mtr.start') }}
      </Button>
      <Button v-else type="button" variant="outline" @click="diag.stopMtr()">
        <Square aria-hidden="true" />{{ t('diagnostics.stop') }}
      </Button>
      <Button type="button" variant="outline" :disabled="hops.length === 0" @click="copyReport">
        <Check v-if="copied" class="text-success" aria-hidden="true" />
        <ClipboardCopy v-else aria-hidden="true" />
        {{ copied ? t('diagnostics.mtr.reportCopied') : t('diagnostics.mtr.copyReport') }}
      </Button>
      <div v-if="advancedSupported" ref="exportMenu" class="relative">
        <Button
          type="button"
          variant="outline"
          :disabled="hops.length === 0"
          aria-haspopup="menu"
          :aria-expanded="exportOpen"
          @click="exportOpen = !exportOpen"
        >
          <Download aria-hidden="true" />{{ t('diagnostics.mtr.export.button') }}
          <ChevronDown aria-hidden="true" />
        </Button>
        <ul
          v-if="exportOpen"
          class="bg-surface-3 absolute right-0 z-10 mt-1 flex w-56 flex-col rounded-[12px] p-1 text-sm shadow-lg"
          role="menu"
          @keydown.esc="exportOpen = false"
        >
          <li v-for="item in EXPORT_ITEMS" :key="`${item.action}-${item.format}`" role="none">
            <button
              type="button"
              role="menuitem"
              class="hover:bg-surface focus-visible:ring-brand w-full rounded px-3 py-1.5 text-left focus-visible:ring-2 focus-visible:outline-none"
              @click="exportAs(item.format, item.action)"
            >
              {{ t(`diagnostics.mtr.export.${item.key}`) }}
            </button>
          </li>
        </ul>
      </div>
    </form>

    <fieldset class="flex flex-wrap items-end gap-3">
      <legend class="sr-only">{{ t('diagnostics.mtr.options') }}</legend>
      <label v-if="advancedSupported" class="flex w-32 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.mtr.mode') }}</span>
        <PwSelect v-model="mode" :options="modeOptions" :disabled="diag.mtrRunning" />
      </label>
      <label v-if="advancedSupported && usesPort" class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.mtr.port') }}</span>
        <input
          v-model.number="port"
          :class="[FIELD, 'font-mono']"
          type="number"
          min="1"
          max="65535"
          :placeholder="String(MTR_DEFAULT_PORT[mode === 'udp' ? 'udp' : 'tcp'])"
          :disabled="diag.mtrRunning"
        />
      </label>
      <label class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.mtr.packetSize') }}</span>
        <input
          v-model.number="packetSize"
          :class="FIELD"
          type="number"
          min="0"
          max="1472"
          placeholder="32"
          :disabled="diag.mtrRunning || mode === 'tcp'"
          :title="mode === 'tcp' ? t('diagnostics.mtr.packetSizeTcp') : undefined"
        />
      </label>
      <label v-if="advancedSupported" class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.mtr.interval') }}</span>
        <input
          v-model.number="intervalMs"
          :class="FIELD"
          type="number"
          min="200"
          max="60000"
          step="100"
          placeholder="1000"
          :disabled="diag.mtrRunning"
        />
      </label>
      <label class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.mtr.maxHops') }}</span>
        <input
          v-model.number="maxHops"
          :class="FIELD"
          type="number"
          min="1"
          max="64"
          placeholder="30"
          :disabled="diag.mtrRunning"
        />
      </label>
      <label v-if="advancedSupported" class="flex h-9 items-center gap-2 text-sm">
        <input v-model="preferIpv6" type="checkbox" :disabled="diag.mtrRunning" />
        {{ t('diagnostics.mtr.preferIpv6') }}
      </label>
    </fieldset>
    <p v-if="!advancedSupported" class="text-text-muted text-xs">
      {{ t('diagnostics.mtr.agentTooOld') }}
    </p>

    <p v-if="copyFailed" class="text-danger text-sm" role="alert">
      {{ t('diagnostics.mtr.copyFailed') }}
    </p>
    <p
      v-if="exportNote"
      class="text-sm"
      :class="exportNote.kind === 'failed' ? 'text-danger' : ''"
      role="status"
    >
      <template v-if="exportNote.kind === 'saved'">
        {{ t('diagnostics.mtr.export.saved', { name: exportNote.name }) }}
      </template>
      <template v-else-if="exportNote.kind === 'copied'">
        {{ t('diagnostics.mtr.export.copied') }}
      </template>
      <template v-else>{{ t('diagnostics.mtr.export.failed') }}</template>
    </p>
    <FailureNote v-if="diag.mtrError" :failure="diag.mtrError" />

    <div v-if="diag.mtrTarget" class="flex flex-col gap-3">
      <p class="text-text-muted flex flex-wrap items-center gap-2 text-sm">
        <span class="text-text font-mono">{{ diag.mtrTarget }}</span>
        <template v-if="diag.mtrResolved && diag.mtrResolved !== diag.mtrTarget">
          <span>→</span><IpCell :addr="diag.mtrResolved" />
        </template>
        <span v-if="diag.mtrSnapshot" role="status">
          ·
          {{
            diag.mtrRunning
              ? t('diagnostics.mtr.progress', {
                  cycle: diag.mtrSnapshot.cycle,
                  total: diag.mtrSnapshot.total_cycles,
                })
              : diag.mtrCancelled
                ? t('diagnostics.mtr.stopped')
                : t('diagnostics.mtr.finished')
          }}
        </span>
        <span v-if="diag.mtrSnapshot?.mode" data-test="mtr-mode">
          ·
          {{
            diag.mtrSnapshot.port
              ? t('diagnostics.mtr.modeWithPort', {
                  mode: t(`diagnostics.mtr.modes.${snapshotMode}`),
                  port: diag.mtrSnapshot.port,
                })
              : t(`diagnostics.mtr.modes.${snapshotMode}`)
          }}
        </span>
        <span v-if="diag.mtrSnapshot?.reach" data-test="mtr-reach">
          · {{ reachLabel(diag.mtrSnapshot.reach) }}
        </span>
      </p>

      <div v-if="hops.length > 0" class="bg-surface-2 overflow-auto rounded-[12px]">
        <table class="w-full text-sm">
          <thead class="text-text-muted text-left text-[11px] tracking-wide uppercase">
            <tr>
              <th class="px-3 py-2 font-medium">{{ t('diagnostics.mtr.hop') }}</th>
              <th class="px-3 py-2 font-medium">{{ t('diagnostics.mtr.host') }}</th>
              <th class="px-3 py-2 font-medium">{{ t('diagnostics.mtr.asn') }}</th>
              <th class="px-3 py-2 font-medium">{{ t('diagnostics.mtr.country') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.loss') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.sent') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.last') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.avg') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.best') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.worst') }}</th>
              <th class="px-3 py-2 text-right font-medium">{{ t('diagnostics.mtr.jitter') }}</th>
            </tr>
          </thead>
          <tbody class="divide-hairline divide-y font-mono">
            <tr v-for="(hop, index) in hops" :key="hop.ttl">
              <td class="text-text-muted px-3 py-1.5">{{ hop.ttl }}</td>
              <td class="px-3 py-1.5">
                <span v-if="hop.addr" class="flex flex-wrap items-center gap-x-2">
                  <span v-if="hop.name" class="font-sans">{{ hop.name }}</span>
                  <IpCell :addr="hop.addr" />
                  <span
                    v-if="hop.other_addrs.length > 0"
                    class="text-text-muted font-sans text-xs"
                    :title="hop.other_addrs.join(', ')"
                  >
                    {{ t('diagnostics.mtr.otherRouters', { count: hop.other_addrs.length }) }}
                  </span>
                </span>
                <span v-else class="text-text-muted">{{ t('diagnostics.mtr.noReply') }}</span>
              </td>
              <td class="px-3 py-1.5" data-test="hop-asn">
                <span v-if="hop.asn !== undefined" class="flex items-center gap-x-2">
                  <span>AS{{ hop.asn }}</span>
                  <span
                    v-if="hop.as_org"
                    class="text-text-muted max-w-48 truncate font-sans text-xs"
                    :title="hop.as_org"
                  >
                    {{ hop.as_org }}
                  </span>
                </span>
                <span v-else class="text-text-muted">—</span>
              </td>
              <td class="px-3 py-1.5" data-test="hop-country">
                <span v-if="hop.country">{{ hop.country }}</span>
                <span v-else class="text-text-muted">—</span>
              </td>
              <td
                class="px-3 py-1.5 text-right"
                :class="LEVEL_CLASS[lossLevel(hop.loss_percent)]"
                :title="
                  isIcmpRateLimited(hops, index) ? t('diagnostics.mtr.rateLimitedTip') : undefined
                "
              >
                {{ formatLoss(hop.loss_percent) }}
                <span v-if="isIcmpRateLimited(hops, index)" class="font-sans text-xs">*</span>
              </td>
              <td class="px-3 py-1.5 text-right">{{ hop.sent }}</td>
              <td class="px-3 py-1.5 text-right">{{ formatMs(hop.rtt?.last_ms) }}</td>
              <td class="px-3 py-1.5 text-right">{{ formatMs(hop.rtt?.avg_ms) }}</td>
              <td class="px-3 py-1.5 text-right">{{ formatMs(hop.rtt?.min_ms) }}</td>
              <td class="px-3 py-1.5 text-right">{{ formatMs(hop.rtt?.max_ms) }}</td>
              <td class="px-3 py-1.5 text-right">{{ formatMs(hop.rtt?.jitter_ms) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="hops.some((_, i) => isIcmpRateLimited(hops, i))" class="text-text-muted text-xs">
        * {{ t('diagnostics.mtr.rateLimitedNote') }}
      </p>
    </div>
    <p v-else class="text-text-muted text-sm">{{ t('diagnostics.mtr.hint') }}</p>
  </div>
</template>

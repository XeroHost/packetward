<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// Everything PacketWard knows about one address, in one place: where it is, whether it is blocked or
// protected, what it did (alerts), what it is connected to right now, and what AbuseIPDB says if the
// user configured a key. Block and allow are one click away. Opened from any address in the app.
import { onKeyStroke } from '@vueuse/core'
import { computed, nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { geoLookup } from '@/api/intel'
import Flag from '@/components/pw/Flag.vue'
import HIcon from '@/components/pw/HIcon.vue'
import { Button } from '@/components/ui/button'
import { copyText } from '@/lib/clipboard'
import { countryName } from '@/lib/countries'
import { Cancel01Icon, Copy01Icon } from '@/lib/icons'
import { exitFast, runTransition, springDialog } from '@/lib/motion'
import { useAlertsStore } from '@/stores/alerts'
import { useDefenseStore } from '@/stores/defense'
import { useGeoStore } from '@/stores/geo'
import { useIntelStore } from '@/stores/intel'
import { useIpDetailStore } from '@/stores/ipDetail'
import { useLiveStore } from '@/stores/live'
import type { AlertSeverity } from '@/types/generated/AlertSeverity'
import type { GeoEntry } from '@/types/generated/GeoEntry'

const { t, locale } = useI18n()
const detail = useIpDetailStore()
const route = useRoute()
const alerts = useAlertsStore()
const defense = useDefenseStore()
const geo = useGeoStore()
const intel = useIntelStore()
const live = useLiveStore()

const closeButton = ref<HTMLButtonElement | null>(null)
const place = ref<GeoEntry | null>(null)
const placeFailed = ref(false)
const copied = ref(false)
const allowed = ref(false)
let previousFocus: HTMLElement | null = null

const addr = computed(() => detail.addr)
// Going to another page closes the panel: it belongs to the page it was opened from.
watch(
  () => route.fullPath,
  () => detail.close(),
)
onKeyStroke('Escape', () => {
  if (detail.addr !== null) detail.close()
})

const SEVERITY_TONE: Record<AlertSeverity, string> = {
  low: 'text-text-muted',
  medium: 'text-warning',
  high: 'text-danger',
  critical: 'text-danger',
}

const mine = computed(() => alerts.items.filter((a) => a.source === addr.value))
const shownAlerts = computed(() => mine.value.slice(0, 5))
const worst = computed(() => mine.value.some((a) => a.phase !== 'ended'))

const blocks = computed(() =>
  defense.blocks.filter(
    (b) => addr.value !== null && (b.cidr === addr.value || b.cidr.startsWith(`${addr.value}/`)),
  ),
)
const protectedBy = computed(() => {
  const value = addr.value
  if (value === null) return null
  if (defense.allowlist.allowlist.includes(value)) return 'allowlist'
  if (live.rdpTrusted.has(value)) return 'rdpTrusted'
  return null
})
const rdpPeer = computed(() => addr.value !== null && live.rdpPeers.has(addr.value))
const connections = computed(() =>
  live.rows.filter((c) => c.remote_addr === addr.value).slice(0, 8),
)

const abuseReady = computed(() => intel.abuse?.state === 'ready')
const abuse = computed(() => (intel.check?.addr === addr.value ? intel.check : null))

watch(addr, async (value) => {
  place.value = null
  placeFailed.value = false
  copied.value = false
  allowed.value = false
  if (value === null) {
    previousFocus?.focus()
    previousFocus = null
    return
  }
  previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
  void alerts.load()
  void defense.loadBlocks()
  void defense.loadAllowlist()
  void live.loadConnections()
  void intel.refresh()
  void geo.warm([value])
  try {
    const result = await geoLookup([value])
    if (detail.addr === value) place.value = result.entries[0] ?? null
  } catch {
    placeFailed.value = true
  }
  await nextTick()
  closeButton.value?.focus()
})

/** Keeps Tab inside the panel while it is open (it is modal: the page behind is out of reach). */
function trapFocus(event: KeyboardEvent): void {
  const root = event.currentTarget as HTMLElement
  const items = [
    ...root.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input, select, [tabindex]',
    ),
  ].filter((el) => el.tabIndex >= 0)
  const first = items[0]
  const last = items[items.length - 1]
  if (!first || !last) return
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first.focus()
  }
}

function when(ms: number): string {
  return new Date(ms).toLocaleString()
}

function expires(ms: number | undefined): string {
  return ms === undefined ? t('ipDetail.permanent') : t('ipDetail.until', { when: when(ms) })
}

async function copy(): Promise<void> {
  if (addr.value && (await copyText(addr.value))) {
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  }
}

async function allow(): Promise<void> {
  const value = addr.value
  if (value === null) return
  const config = defense.allowlist
  if (config.allowlist.includes(value)) return
  allowed.value = await defense.updateAllowlist({
    ...config,
    allowlist: [...config.allowlist, value],
  })
}

function unblock(): void {
  void defense.unblock(blocks.value.map((b) => b.cidr))
}

function onEnter(el: Element, done: () => void): void {
  if (document.documentElement.dataset.motion === 'reduced') return done()
  runTransition(el, { opacity: [0, 1], x: [28, 0] }, springDialog, done, 900, () => {
    // Whatever happened to the animation, the panel ends fully visible and in place.
    const style = (el as HTMLElement).style
    style.opacity = ''
    style.transform = ''
  })
}
function onLeave(el: Element, done: () => void): void {
  if (document.documentElement.dataset.motion === 'reduced') return done()
  runTransition(el, { opacity: [1, 0], x: [0, 28] }, exitFast, done, 250)
}
</script>

<template>
  <Teleport to="body">
    <div
      v-if="addr !== null"
      class="fixed inset-0 z-40 bg-black/30"
      aria-hidden="true"
      @click="detail.close()"
    />
    <Transition :css="false" @enter="onEnter" @leave="onLeave">
      <aside
        v-if="addr !== null"
        class="pw-drawer bg-surface-3 text-text fixed top-[var(--titlebar-h,2.5rem)] right-3 bottom-3 z-50 flex w-[26rem] max-w-[calc(100vw-1.5rem)] flex-col overflow-hidden rounded-[18px] shadow-2xl"
        role="dialog"
        aria-modal="true"
        :aria-label="t('ipDetail.title', { addr })"
        data-testid="ip-detail"
        @keydown.tab="trapFocus"
      >
        <header class="border-hairline flex items-start gap-3 border-b px-5 py-4">
          <Flag :addr="addr" class="mt-1" />
          <div class="min-w-0 flex-1">
            <h2 class="truncate font-mono text-base font-semibold" data-testid="ip-detail-addr">
              {{ addr }}
            </h2>
            <p class="text-text-muted mt-0.5 truncate text-[13px]">
              <template v-if="place && !place.reserved && place.country_code">
                {{ place.country_name ?? countryName(place.country_code, locale) }}
              </template>
              <template v-else-if="place?.reserved">{{ t('ipDetail.reserved') }}</template>
              <template v-else-if="geo.ready === false">{{ t('ipDetail.noGeo') }}</template>
              <template v-else-if="placeFailed">{{ t('ipDetail.placeFailed') }}</template>
              <template v-else>…</template>
            </p>
          </div>
          <button
            type="button"
            class="text-text-muted hover:text-text hover:bg-surface-2 flex size-8 items-center justify-center rounded-[10px]"
            :aria-label="copied ? t('common.copied') : t('common.copyAddress', { addr })"
            @click="copy"
          >
            <HIcon :icon="Copy01Icon" :size="16" />
          </button>
          <button
            ref="closeButton"
            type="button"
            class="text-text-muted hover:text-text hover:bg-surface-2 flex size-8 items-center justify-center rounded-[10px]"
            :aria-label="t('ipDetail.close')"
            @click="detail.close()"
          >
            <HIcon :icon="Cancel01Icon" :size="16" />
          </button>
        </header>

        <div class="flex min-h-0 flex-1 flex-col gap-6 overflow-y-auto px-5 py-5">
          <!-- State -->
          <section class="flex flex-wrap gap-2" :aria-label="t('ipDetail.state')">
            <span
              v-if="blocks.length > 0"
              class="bg-danger/15 text-danger rounded-full px-2.5 py-1 text-xs font-medium"
              data-testid="ip-state-blocked"
              >{{ t('ipDetail.blocked') }}</span
            >
            <span
              v-if="protectedBy"
              class="bg-success/15 text-success rounded-full px-2.5 py-1 text-xs font-medium"
              >{{ t(`ipDetail.protected.${protectedBy}`) }}</span
            >
            <span
              v-if="rdpPeer"
              class="bg-warning/15 text-warning rounded-full px-2.5 py-1 text-xs font-medium"
              >{{ t('ipDetail.rdpPeer') }}</span
            >
            <span
              v-if="worst"
              class="bg-danger/15 text-danger rounded-full px-2.5 py-1 text-xs font-medium"
              >{{ t('ipDetail.ongoing') }}</span
            >
            <span
              v-if="blocks.length === 0 && !protectedBy && !rdpPeer && !worst"
              class="text-text-muted text-sm"
              >{{ t('ipDetail.nothing') }}</span
            >
          </section>

          <!-- Network -->
          <section v-if="place && !place.reserved && (place.asn || place.as_org)">
            <h3 class="text-text-muted mb-2 text-xs font-medium tracking-wide uppercase">
              {{ t('ipDetail.network') }}
            </h3>
            <dl class="grid grid-cols-[6rem_1fr] gap-y-1.5 text-sm">
              <dt class="text-text-muted">ASN</dt>
              <dd class="font-mono">{{ place.asn ? `AS${place.asn}` : '—' }}</dd>
              <dt class="text-text-muted">{{ t('ipDetail.organization') }}</dt>
              <dd class="truncate">{{ place.as_org ?? '—' }}</dd>
            </dl>
          </section>

          <!-- Blocks -->
          <section v-if="blocks.length > 0">
            <h3 class="text-text-muted mb-2 text-xs font-medium tracking-wide uppercase">
              {{ t('ipDetail.blocks') }}
            </h3>
            <ul class="flex flex-col gap-2">
              <li
                v-for="block in blocks"
                :key="block.cidr + block.created_unix_ms"
                class="bg-surface-2 rounded-[12px] px-3 py-2 text-[13px]"
              >
                <div class="flex items-center justify-between gap-2">
                  <span class="font-mono">{{ block.cidr }}</span>
                  <span class="text-text-muted text-xs">{{ block.source }}</span>
                </div>
                <p class="text-text-muted mt-0.5 text-xs">
                  {{ expires(block.expires_unix_ms) }}
                  <template v-if="block.reason"> · {{ block.reason }}</template>
                </p>
              </li>
            </ul>
          </section>

          <!-- Alerts -->
          <section v-if="shownAlerts.length > 0">
            <h3 class="text-text-muted mb-2 text-xs font-medium tracking-wide uppercase">
              {{ t('ipDetail.alerts', { count: mine.length }) }}
            </h3>
            <ul class="flex flex-col gap-2" data-testid="ip-alerts">
              <li
                v-for="alert in shownAlerts"
                :key="alert.id"
                class="bg-surface-2 rounded-[12px] px-3 py-2 text-[13px]"
              >
                <div class="flex items-center justify-between gap-2">
                  <span class="font-medium">{{ t(`alerts.summary.${alert.summary_key}`) }}</span>
                  <span class="text-xs font-medium" :class="SEVERITY_TONE[alert.severity]">{{
                    t(`alerts.severity.${alert.severity}`)
                  }}</span>
                </div>
                <p class="text-text-muted mt-0.5 text-xs">
                  {{ when(alert.last_seen_unix_ms) }}
                  <template v-if="alert.phase !== 'ended'">
                    · {{ t('alerts.ongoingBadge') }}</template
                  >
                </p>
              </li>
            </ul>
          </section>

          <!-- Connections -->
          <section v-if="connections.length > 0">
            <h3 class="text-text-muted mb-2 text-xs font-medium tracking-wide uppercase">
              {{ t('ipDetail.connections') }}
            </h3>
            <ul class="flex flex-col gap-1.5 font-mono text-xs" data-testid="ip-connections">
              <li v-for="c in connections" :key="c.id" class="flex items-center gap-2">
                <span class="text-text-muted w-8 uppercase">{{ c.proto }}</span>
                <span>:{{ c.local_port }} ← :{{ c.remote_port }}</span>
                <span class="text-text-muted ml-auto truncate">{{ c.process || c.state }}</span>
              </li>
            </ul>
          </section>

          <!-- Reputation -->
          <section>
            <h3 class="text-text-muted mb-2 text-xs font-medium tracking-wide uppercase">
              {{ t('ipDetail.reputation') }}
            </h3>
            <div v-if="abuse" class="bg-surface-2 rounded-[12px] px-3 py-2.5 text-[13px]">
              <p>
                {{ t('ipDetail.abuseScore') }}
                <span
                  class="font-semibold"
                  :class="
                    abuse.score >= 50
                      ? 'text-danger'
                      : abuse.score >= 10
                        ? 'text-warning'
                        : 'text-success'
                  "
                  >{{ abuse.score }}/100</span
                >
                · {{ t('ipDetail.abuseReports', { n: abuse.total_reports }) }}
              </p>
              <p v-if="abuse.isp" class="text-text-muted mt-0.5 text-xs">{{ abuse.isp }}</p>
            </div>
            <template v-else-if="abuseReady">
              <Button
                size="sm"
                variant="outline"
                :disabled="intel.busy"
                @click="intel.checkAddress(addr)"
              >
                {{ t('ipDetail.abuseCheck') }}
              </Button>
              <p v-if="intel.error" class="text-danger mt-2 text-xs" role="alert">
                {{ intel.error }}
              </p>
            </template>
            <p v-else class="text-text-muted text-sm">{{ t('ipDetail.abuseOff') }}</p>
          </section>
        </div>

        <footer class="border-hairline flex flex-wrap items-center gap-2 border-t px-5 py-4">
          <Button
            v-if="blocks.length === 0"
            variant="destructive"
            size="sm"
            data-testid="ip-block"
            @click="defense.requestBlock(addr)"
          >
            {{ t('ipDetail.block') }}
          </Button>
          <Button v-else variant="outline" size="sm" data-testid="ip-unblock" @click="unblock">
            {{ t('ipDetail.unblock') }}
          </Button>
          <Button
            variant="outline"
            size="sm"
            :disabled="protectedBy === 'allowlist' || allowed"
            data-testid="ip-allow"
            @click="allow"
          >
            {{ allowed ? t('ipDetail.allowed') : t('ipDetail.allow') }}
          </Button>
        </footer>
      </aside>
    </Transition>
  </Teleport>
</template>

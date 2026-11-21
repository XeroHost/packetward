<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
import { Check, Copy, ShieldBan } from '@/components/pw/icons'
import { computed, onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Flag from '@/components/pw/Flag.vue'
import { Badge } from '@/components/ui/badge'
import { copyText } from '@/lib/clipboard'
import { useDefenseStore } from '@/stores/defense'
import { useIpDetailStore } from '@/stores/ipDetail'

const props = defineProps<{
  addr: string
  port?: number | null
  /** A TCP peer of the RDP port (connected; not necessarily logged in). */
  rdp?: boolean
  /** Also has a successful RDP logon in the trust window. */
  trusted?: boolean
}>()

const { t } = useI18n()
const defense = useDefenseStore()
const detail = useIpDetailStore()

/** Only a single address (no CIDR) can be blocked from here, and never a private one. */
const blockable = computed(() => props.addr !== '' && !props.addr.includes('/'))

/** IPv6 with a port needs brackets: [2001:db8::1]:443. */
const text = computed(() => {
  if (!props.addr) return ''
  if (props.port === undefined || props.port === null) return props.addr
  return props.addr.includes(':') ? `[${props.addr}]:${props.port}` : `${props.addr}:${props.port}`
})

const copied = ref(false)
let timer: ReturnType<typeof setTimeout> | null = null

async function copy(): Promise<void> {
  if (!props.addr || !(await copyText(props.addr))) return
  copied.value = true
  if (timer !== null) clearTimeout(timer)
  timer = setTimeout(() => (copied.value = false), 1500)
}

onBeforeUnmount(() => {
  if (timer !== null) clearTimeout(timer)
})
</script>

<template>
  <span v-if="addr" class="group inline-flex min-w-0 items-center gap-1.5">
    <Flag :addr="addr" />
    <button
      type="button"
      class="hover:text-brand-fg focus-visible:ring-brand min-w-0 truncate rounded text-left font-mono hover:underline focus-visible:ring-2 focus-visible:outline-none"
      :title="text"
      :aria-label="t('ipDetail.open', { addr })"
      data-testid="ip-open"
      @click.stop="detail.open(addr)"
    >
      {{ text }}
    </button>
    <Badge
      v-if="rdp"
      variant="outline"
      class="h-4 px-1.5 text-[10px] leading-none"
      :class="trusted ? 'border-success/50 text-success' : 'border-warning/50 text-warning'"
      :title="trusted ? t('connections.rdpTrustedBadgeTip') : t('connections.rdpBadgeTip')"
    >
      {{ trusted ? t('connections.rdpTrustedBadge') : t('connections.rdpBadge') }}
    </Badge>
    <button
      type="button"
      class="text-text-muted hover:text-text focus-visible:ring-brand shrink-0 rounded p-0.5 opacity-0 group-hover:opacity-100 focus-visible:opacity-100 focus-visible:ring-2 focus-visible:outline-none"
      :aria-label="t('common.copyAddress', { addr })"
      :title="copied ? t('common.copied') : t('common.copy')"
      @click.stop="copy"
    >
      <Check v-if="copied" class="text-success size-3.5" aria-hidden="true" />
      <Copy v-else class="size-3.5" aria-hidden="true" />
    </button>
    <button
      v-if="blockable"
      type="button"
      class="text-text-muted hover:text-danger focus-visible:ring-brand shrink-0 rounded p-0.5 opacity-0 group-hover:opacity-100 focus-visible:opacity-100 focus-visible:ring-2 focus-visible:outline-none"
      :aria-label="t('firewall.dialog.blockAddr', { addr })"
      :title="t('firewall.dialog.blockAddr', { addr })"
      @click.stop="defense.requestBlock(addr)"
    >
      <ShieldBan class="size-3.5" aria-hidden="true" />
    </button>
  </span>
  <span v-else class="text-text-muted">—</span>
</template>

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Check, Copy } from 'lucide-vue-next'
import { computed, onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Badge } from '@/components/ui/badge'
import { copyText } from '@/lib/clipboard'

const props = defineProps<{
  addr: string
  port?: number | null
  /** A TCP peer of the RDP port (connected; not necessarily logged in). */
  rdp?: boolean
  /** Also has a successful RDP logon in the trust window. */
  trusted?: boolean
}>()

const { t } = useI18n()

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
    <span class="truncate font-mono" :title="text">{{ text }}</span>
    <Badge
      v-if="rdp"
      variant="outline"
      class="h-4 px-1.5 text-[10px] leading-none"
      :class="trusted ? 'border-success/50 text-success' : 'border-brand-fg/50 text-brand-fg'"
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
  </span>
  <span v-else class="text-text-muted">—</span>
</template>

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DnsPanel from './DnsPanel.vue'
import LocalPortsPanel from './LocalPortsPanel.vue'
import MtrPanel from './MtrPanel.vue'
import PingPanel from './PingPanel.vue'
import PortPanel from './PortPanel.vue'

const { t } = useI18n()

const TABS = ['ping', 'mtr', 'dns', 'port', 'local'] as const
type Tab = (typeof TABS)[number]
const active = ref<Tab>('ping')

const panel = computed(
  () =>
    ({ ping: PingPanel, mtr: MtrPanel, dns: DnsPanel, port: PortPanel, local: LocalPortsPanel })[
      active.value
    ],
)

function move(step: number, event: KeyboardEvent): void {
  const next = TABS[(TABS.indexOf(active.value) + step + TABS.length) % TABS.length]
  if (next === undefined) return
  active.value = next
  event.preventDefault()
  document.getElementById(`diag-tab-${next}`)?.focus()
}
</script>

<template>
  <section class="flex flex-col gap-4">
    <div
      role="tablist"
      :aria-label="t('nav.diagnostics')"
      class="border-border flex gap-1 border-b"
    >
      <button
        v-for="tab in TABS"
        :id="`diag-tab-${tab}`"
        :key="tab"
        type="button"
        role="tab"
        :aria-selected="active === tab"
        aria-controls="diag-panel"
        :tabindex="active === tab ? 0 : -1"
        class="focus-visible:ring-brand -mb-px rounded-t-md border-b-2 px-4 py-2 text-sm font-medium focus-visible:ring-2 focus-visible:outline-none"
        :class="
          active === tab
            ? 'border-brand text-text'
            : 'text-text-muted hover:text-text border-transparent'
        "
        @click="active = tab"
        @keydown.right="move(1, $event)"
        @keydown.left="move(-1, $event)"
      >
        {{ t(`diagnostics.tabs.${tab}`) }}
      </button>
    </div>
    <div
      id="diag-panel"
      role="tabpanel"
      :aria-labelledby="`diag-tab-${active}`"
      class="bg-surface border-border rounded-lg border p-[var(--card-p)]"
      style="box-shadow: var(--shadow-card)"
    >
      <component :is="panel" />
    </div>
  </section>
</template>

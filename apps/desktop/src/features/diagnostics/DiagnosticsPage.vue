<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import TabBar from '@/components/pw/TabBar.vue'
import { panelTransition } from '@/lib/motion'
import DnsPanel from './DnsPanel.vue'
import LocalPortsPanel from './LocalPortsPanel.vue'
import MtrPanel from './MtrPanel.vue'
import PingPanel from './PingPanel.vue'
import PortPanel from './PortPanel.vue'

const { t } = useI18n()

const IDS = ['ping', 'mtr', 'dns', 'port', 'local'] as const
type Tab = (typeof IDS)[number]
const active = ref<Tab>('ping')
const tabs = computed(() => IDS.map((id) => ({ id, label: t(`diagnostics.tabs.${id}`) })))

const panel = computed(
  () =>
    ({ ping: PingPanel, mtr: MtrPanel, dns: DnsPanel, port: PortPanel, local: LocalPortsPanel })[
      active.value
    ],
)
</script>

<template>
  <section class="flex max-w-[72rem] flex-col gap-8">
    <TabBar v-model="active" :tabs="tabs" :label="t('nav.diagnostics')" id-prefix="diag" />
    <div id="diag-panel" role="tabpanel" :aria-labelledby="`diag-tab-${active}`">
      <Transition
        :css="false"
        mode="out-in"
        @before-enter="panelTransition.beforeEnter"
        @enter="panelTransition.enter"
        @leave="panelTransition.leave"
      >
        <component :is="panel" />
      </Transition>
    </div>
  </section>
</template>

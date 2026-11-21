<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import TabBar from '@/components/pw/TabBar.vue'
import { panelTransition } from '@/lib/motion'
import BlocksPanel from './BlocksPanel.vue'
import ProtectedPanel from './ProtectedPanel.vue'
import RulesPanel from './RulesPanel.vue'

const { t } = useI18n()

const IDS = ['blocks', 'rules', 'protected'] as const
type Tab = (typeof IDS)[number]
const active = ref<Tab>('blocks')
const tabs = computed(() => IDS.map((id) => ({ id, label: t(`firewall.tabs.${id}`) })))

const panel = computed(
  () => ({ blocks: BlocksPanel, rules: RulesPanel, protected: ProtectedPanel })[active.value],
)
</script>

<template>
  <section class="flex max-w-[72rem] flex-col gap-8">
    <TabBar v-model="active" :tabs="tabs" :label="t('nav.firewall')" id-prefix="fw" />
    <div id="fw-panel" role="tabpanel" :aria-labelledby="`fw-tab-${active}`">
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

<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import FailureNote from '@/features/diagnostics/FailureNote.vue'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { splitTargets, useDefenseStore } from '@/stores/defense'

const { t } = useI18n()
const defense = useDefenseStore()

const allow = ref('')
const management = ref('')
const saved = ref(false)

watch(
  () => defense.allowlist,
  (config) => {
    allow.value = config.allowlist.join('\n')
    management.value = config.management.join('\n')
  },
  { immediate: true },
)

async function save(): Promise<void> {
  saved.value = false
  saved.value = await defense.updateAllowlist({
    allowlist: splitTargets(allow.value),
    management: splitTargets(management.value),
  })
}

onMounted(() => {
  void defense.loadAllowlist()
  void defense.loadGuardian()
})
</script>

<template>
  <div class="flex flex-col gap-4">
    <p class="text-text-muted text-sm">{{ t('firewall.protected.hint') }}</p>

    <h3 class="text-sm font-medium">{{ t('firewall.protected.never') }}</h3>
    <ul class="bg-surface-2 divide-hairline divide-y rounded-[12px] text-sm">
      <li
        v-for="entry in defense.guardian?.protected ?? []"
        :key="entry.cidr + entry.reason"
        class="flex items-center gap-3 px-3 py-1.5"
      >
        <span class="font-mono">{{ entry.cidr }}</span>
        <span class="text-text-muted">{{ t(`firewall.protectedReasons.${entry.reason}`) }}</span>
      </li>
    </ul>

    <FailureNote v-if="defense.guardianError" :failure="defense.guardianError" />

    <div class="grid gap-4 md:grid-cols-2">
      <label class="flex flex-col gap-1 text-sm">
        <span class="font-medium">{{ t('firewall.protected.allowlist') }}</span>
        <span class="text-text-muted text-xs">{{ t('firewall.protected.allowlistHint') }}</span>
        <textarea v-model="allow" :class="[FIELD, 'h-32 py-2 font-mono']" spellcheck="false" />
      </label>
      <label class="flex flex-col gap-1 text-sm">
        <span class="font-medium">{{ t('firewall.protected.management') }}</span>
        <span class="text-text-muted text-xs">{{ t('firewall.protected.managementHint') }}</span>
        <textarea v-model="management" :class="[FIELD, 'h-32 py-2 font-mono']" spellcheck="false" />
      </label>
    </div>
    <div class="flex items-center gap-3">
      <Button :disabled="defense.busy" @click="save">{{ t('firewall.protected.save') }}</Button>
      <span v-if="saved" class="text-success text-sm" role="status">{{
        t('firewall.protected.saved')
      }}</span>
    </div>
  </div>
</template>

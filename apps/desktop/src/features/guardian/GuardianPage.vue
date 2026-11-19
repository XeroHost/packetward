<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { useIntervalFn } from '@vueuse/core'
import { ShieldCheck, TriangleAlert } from 'lucide-vue-next'
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import IpCell from '@/components/pw/IpCell.vue'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import FailureNote from '@/features/diagnostics/FailureNote.vue'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { useAppVisible } from '@/lib/visibility'
import { useDefenseStore } from '@/stores/defense'
import type { AlertSeverity } from '@/types/generated/AlertSeverity'
import type { GuardianMode } from '@/types/generated/GuardianMode'
import type { GuardianPolicy } from '@/types/generated/GuardianPolicy'
import type { GuardianPreset } from '@/types/generated/GuardianPreset'

const { t } = useI18n()
const defense = useDefenseStore()
const visible = useAppVisible()

const status = computed(() => defense.guardian)
const MODES: readonly GuardianMode[] = ['off', 'monitor', 'active']
const PRESETS: readonly GuardianPreset[] = ['gentle', 'balanced', 'strict']
const SEVERITIES: readonly AlertSeverity[] = ['low', 'medium', 'high', 'critical']

// Editable copy of the policy (ladder in minutes for readability).
const preset = ref<GuardianPreset>('balanced')
const minSeverity = ref<AlertSeverity>('high')
const ladderText = ref('15, 60, 1440, 10080')
const maxPerHour = ref(20)
const confirmingActive = ref(false)
const reviewed = ref(false)
const saved = ref(false)

watch(
  status,
  (value) => {
    if (!value) return
    preset.value = value.policy.preset
    minSeverity.value = value.policy.min_severity
    ladderText.value = value.policy.ttl_ladder_secs.map((s) => Math.round(s / 60)).join(', ')
    maxPerHour.value = value.policy.max_blocks_per_hour
  },
  { immediate: true },
)

function buildPolicy(mode: GuardianMode): GuardianPolicy {
  const ladder = ladderText.value
    .split(/[\s,;]+/)
    .map((x) => Number(x))
    .filter((x) => Number.isFinite(x) && x > 0)
    .map((minutes) => Math.round(minutes * 60))
  return {
    mode,
    preset: preset.value,
    min_severity: minSeverity.value,
    ttl_ladder_secs: ladder,
    max_blocks_per_hour: Math.floor(maxPerHour.value) || 20,
  }
}

async function setMode(mode: GuardianMode): Promise<void> {
  saved.value = false
  if (mode === 'active') {
    confirmingActive.value = true
    reviewed.value = false
    return
  }
  saved.value = await defense.updatePolicy(buildPolicy(mode), false)
}

async function confirmActive(): Promise<void> {
  if (!reviewed.value) return
  if (await defense.updatePolicy(buildPolicy('active'), true)) {
    confirmingActive.value = false
    saved.value = true
  }
}

async function saveSettings(): Promise<void> {
  if (!status.value) return
  saved.value = await defense.updatePolicy(
    buildPolicy(status.value.policy.mode),
    status.value.policy.mode === 'active',
  )
}

const { pause, resume } = useIntervalFn(() => void defense.loadGuardian(), 3000, {
  immediate: false,
})
onMounted(() => {
  void defense.loadGuardian()
  if (visible.value) resume()
  else pause()
})
watch(visible, (shown) => (shown ? resume() : pause()))

function when(ms: number): string {
  return new Date(ms).toLocaleString()
}

const OUTCOME_TONE: Record<string, string> = {
  blocked: 'border-danger/50 text-danger',
  would_block: 'border-warning/50 text-warning',
  skipped_protected: 'border-success/50 text-success',
  skipped_circuit: 'border-danger/50 text-danger',
  skipped_below_threshold: 'border-border text-text-muted',
  skipped_failed: 'border-danger/50 text-danger',
}

const card = 'bg-surface border-border flex flex-col gap-3 rounded-lg border p-[var(--card-p)]'
</script>

<template>
  <section class="flex flex-col gap-4">
    <FailureNote v-if="defense.guardianError" :failure="defense.guardianError" />

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <div class="flex flex-wrap items-center gap-3">
        <ShieldCheck class="text-brand-fg size-5" aria-hidden="true" />
        <h2 class="text-base">{{ t('guardian.mode.title') }}</h2>
        <div role="group" :aria-label="t('guardian.mode.title')" class="ml-auto flex gap-1">
          <Button
            v-for="mode in MODES"
            :key="mode"
            size="sm"
            :variant="status?.policy.mode === mode ? 'default' : 'outline'"
            :disabled="defense.busy || !status"
            @click="setMode(mode)"
          >
            {{ t(`topbar.guardian.${mode}`) }}
          </Button>
        </div>
      </div>
      <p class="text-sm">{{ t(`guardian.mode.explain.${status?.policy.mode ?? 'monitor'}`) }}</p>

      <div
        v-if="confirmingActive"
        class="border-warning/40 bg-warning/10 flex flex-col gap-2 rounded-md border p-3 text-sm"
        role="alertdialog"
      >
        <p class="flex items-start gap-2">
          <TriangleAlert class="text-warning mt-0.5 size-4 shrink-0" aria-hidden="true" />
          <span>
            {{ t('guardian.active.warning') }}
            {{ t('guardian.active.report', { count: status?.would_block_24h ?? 0 }) }}
          </span>
        </p>
        <label class="flex items-center gap-2">
          <input v-model="reviewed" type="checkbox" />
          {{ t('guardian.active.reviewed') }}
        </label>
        <div class="flex gap-2">
          <Button size="sm" :disabled="!reviewed || defense.busy" @click="confirmActive">
            {{ t('guardian.active.confirm') }}
          </Button>
          <Button size="sm" variant="outline" @click="confirmingActive = false">
            {{ t('capture.files.cancel') }}
          </Button>
        </div>
      </div>

      <dl class="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <div>
          <dt class="text-text-muted">{{ t('guardian.status.circuit') }}</dt>
          <dd :class="status?.circuit_open ? 'text-danger' : 'text-success'">
            {{ status?.circuit_open ? t('guardian.status.open') : t('guardian.status.closed') }}
          </dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('guardian.status.lastHour') }}</dt>
          <dd class="font-mono">
            {{ status?.blocks_last_hour ?? 0 }} / {{ status?.policy.max_blocks_per_hour ?? 0 }}
          </dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('guardian.status.wouldBlock') }}</dt>
          <dd class="font-mono">{{ status?.would_block_24h ?? 0 }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('guardian.status.protected') }}</dt>
          <dd class="font-mono">{{ status?.protected.length ?? 0 }}</dd>
        </div>
      </dl>
      <p v-if="status?.circuit_open" class="text-danger text-sm" role="alert">
        {{ t('guardian.status.circuitNote') }}
      </p>
    </div>

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <h2 class="text-base">{{ t('guardian.policy.title') }}</h2>
      <div class="flex flex-wrap items-end gap-3">
        <label class="flex w-40 flex-col gap-1 text-sm">
          <span class="text-text-muted">{{ t('guardian.policy.preset') }}</span>
          <select v-model="preset" :class="FIELD">
            <option v-for="p in PRESETS" :key="p" :value="p">
              {{ t(`guardian.policy.presets.${p}`) }}
            </option>
          </select>
        </label>
        <label class="flex w-40 flex-col gap-1 text-sm">
          <span class="text-text-muted">{{ t('guardian.policy.minSeverity') }}</span>
          <select v-model="minSeverity" :class="FIELD">
            <option v-for="s in SEVERITIES" :key="s" :value="s">
              {{ t(`alerts.severity.${s}`) }}
            </option>
          </select>
        </label>
        <label class="flex min-w-56 flex-1 flex-col gap-1 text-sm">
          <span class="text-text-muted">{{ t('guardian.policy.ladder') }}</span>
          <input v-model="ladderText" :class="[FIELD, 'font-mono']" type="text" />
        </label>
        <label class="flex w-36 flex-col gap-1 text-sm">
          <span class="text-text-muted">{{ t('guardian.policy.perHour') }}</span>
          <input v-model.number="maxPerHour" :class="FIELD" type="number" min="1" max="500" />
        </label>
        <Button variant="outline" :disabled="defense.busy || !status" @click="saveSettings">
          {{ t('firewall.protected.save') }}
        </Button>
        <span v-if="saved" class="text-success pb-2 text-sm" role="status">{{
          t('firewall.protected.saved')
        }}</span>
      </div>
      <p class="text-text-muted text-xs">{{ t('guardian.policy.hint') }}</p>
    </div>

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <h2 class="text-base">{{ t('guardian.decisions.title') }}</h2>
      <p class="text-text-muted text-xs">{{ t('guardian.decisions.hint') }}</p>
      <ul
        v-if="status && status.decisions.length > 0"
        class="divide-border border-border max-h-96 divide-y overflow-auto rounded-md border text-sm"
      >
        <li
          v-for="(decision, index) in status.decisions"
          :key="index"
          class="flex flex-col gap-1 px-3 py-2"
        >
          <div class="flex flex-wrap items-center gap-2">
            <Badge variant="outline" :class="OUTCOME_TONE[decision.outcome]">
              {{ t(`guardian.decisions.outcomes.${decision.outcome}`) }}
            </Badge>
            <IpCell :addr="decision.source" />
            <span class="text-text-muted">{{ t(`alerts.summary.${decision.summary_key}`) }}</span>
            <span class="text-text-muted ml-auto text-xs">{{ when(decision.unix_ms) }}</span>
          </div>
          <p class="text-text-muted">{{ decision.why }}</p>
        </li>
      </ul>
      <p v-else class="text-text-muted text-sm">{{ t('guardian.decisions.none') }}</p>
    </div>
  </section>
</template>

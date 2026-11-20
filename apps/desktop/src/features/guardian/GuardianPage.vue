<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// The Guardian: three stages to choose from (Off, Monitor, Active), each explained where you pick it;
// the chosen one is outlined, and only Active uses crimson because Active is the one that acts.
import { useIntervalFn } from '@vueuse/core'
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import HIcon from '@/components/pw/HIcon.vue'
import { TriangleAlert } from '@/components/pw/icons'
import IpCell from '@/components/pw/IpCell.vue'
import { Button } from '@/components/ui/button'
import FailureNote from '@/features/diagnostics/FailureNote.vue'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { ShieldAlertIcon, ShieldBanIcon, ShieldCheckIcon } from '@/lib/icons'
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
const MODE_ICON = { off: ShieldBanIcon, monitor: ShieldAlertIcon, active: ShieldCheckIcon } as const
const MODE_RING: Record<GuardianMode, string> = {
  off: 'ring-hairline-strong',
  monitor: 'ring-warning/70',
  active: 'ring-brand',
}
const MODE_TEXT: Record<GuardianMode, string> = {
  off: 'text-text-muted',
  monitor: 'text-warning',
  active: 'text-brand-fg',
}

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
  blocked: 'text-brand-fg',
  would_block: 'text-warning',
  skipped_protected: 'text-success',
  skipped_circuit: 'text-brand-fg',
  skipped_below_threshold: 'text-text-muted',
  skipped_failed: 'text-brand-fg',
}

const card = 'flex flex-col gap-4'
</script>

<template>
  <section class="flex max-w-[64rem] flex-col gap-14">
    <FailureNote v-if="defense.guardianError" :failure="defense.guardianError" />

    <div :class="card">
      <h2 class="text-[1.0625rem] font-semibold">{{ t('guardian.mode.title') }}</h2>
      <div
        role="radiogroup"
        :aria-label="t('guardian.mode.title')"
        class="grid gap-3 md:grid-cols-3"
      >
        <button
          v-for="mode in MODES"
          :key="mode"
          type="button"
          role="radio"
          :aria-checked="status?.policy.mode === mode"
          :disabled="defense.busy || !status"
          class="pw-well flex flex-col items-start gap-2 text-left transition-[box-shadow,background-color] duration-200 disabled:opacity-60"
          :class="
            status?.policy.mode === mode ? ['ring-2', MODE_RING[mode]] : 'hover:bg-surface-3 ring-0'
          "
          @click="setMode(mode)"
        >
          <span class="flex items-center gap-2 font-semibold" :class="MODE_TEXT[mode]">
            <HIcon :icon="MODE_ICON[mode]" :size="18" />
            {{ t(`topbar.guardian.${mode}`) }}
          </span>
          <span class="text-text-muted text-[13px] leading-relaxed">
            {{ t(`guardian.mode.explain.${mode}`) }}
          </span>
        </button>
      </div>

      <div
        v-if="confirmingActive"
        class="pw-note pw-appear flex flex-col gap-3"
        data-tone="warning"
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

      <dl class="border-hairline grid grid-cols-2 gap-y-5 border-y py-6 sm:grid-cols-4">
        <div class="pr-5">
          <dt class="text-text-muted text-xs">{{ t('guardian.status.circuit') }}</dt>
          <dd
            class="font-heading mt-1 text-xl font-semibold"
            :class="status?.circuit_open ? 'text-brand-fg' : 'text-success'"
          >
            {{ status?.circuit_open ? t('guardian.status.open') : t('guardian.status.closed') }}
          </dd>
        </div>
        <div class="border-hairline border-l px-5">
          <dt class="text-text-muted text-xs">{{ t('guardian.status.lastHour') }}</dt>
          <dd class="font-heading mt-1 text-xl font-semibold">
            {{ status?.blocks_last_hour ?? 0 }}
            <span class="text-text-muted text-sm font-medium"
              >/ {{ status?.policy.max_blocks_per_hour ?? 0 }}</span
            >
          </dd>
        </div>
        <div class="border-hairline border-l px-5 max-sm:!border-l-0 max-sm:!pl-0">
          <dt class="text-text-muted text-xs">{{ t('guardian.status.wouldBlock') }}</dt>
          <dd class="font-heading mt-1 text-xl font-semibold">
            {{ status?.would_block_24h ?? 0 }}
          </dd>
        </div>
        <div class="border-hairline border-l pl-5">
          <dt class="text-text-muted text-xs">{{ t('guardian.status.protected') }}</dt>
          <dd class="font-heading mt-1 text-xl font-semibold">
            {{ status?.protected.length ?? 0 }}
          </dd>
        </div>
      </dl>
      <p v-if="status?.circuit_open" class="pw-note" data-tone="danger" role="alert">
        {{ t('guardian.status.circuitNote') }}
      </p>
    </div>

    <div :class="card">
      <h2 class="text-[1.0625rem] font-semibold">{{ t('guardian.policy.title') }}</h2>
      <div class="flex flex-wrap items-end gap-3">
        <label class="flex w-40 flex-col gap-1.5 text-sm">
          <span class="text-text-muted text-xs">{{ t('guardian.policy.preset') }}</span>
          <select v-model="preset" :class="FIELD">
            <option v-for="p in PRESETS" :key="p" :value="p">
              {{ t(`guardian.policy.presets.${p}`) }}
            </option>
          </select>
        </label>
        <label class="flex w-40 flex-col gap-1.5 text-sm">
          <span class="text-text-muted text-xs">{{ t('guardian.policy.minSeverity') }}</span>
          <select v-model="minSeverity" :class="FIELD">
            <option v-for="s in SEVERITIES" :key="s" :value="s">
              {{ t(`alerts.severity.${s}`) }}
            </option>
          </select>
        </label>
        <label class="flex min-w-56 flex-1 flex-col gap-1.5 text-sm">
          <span class="text-text-muted text-xs">{{ t('guardian.policy.ladder') }}</span>
          <input v-model="ladderText" :class="[FIELD, 'font-mono']" type="text" />
        </label>
        <label class="flex w-36 flex-col gap-1.5 text-sm">
          <span class="text-text-muted text-xs">{{ t('guardian.policy.perHour') }}</span>
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

    <div :class="card">
      <div>
        <h2 class="text-[1.0625rem] font-semibold">{{ t('guardian.decisions.title') }}</h2>
        <p class="text-text-muted mt-0.5 text-xs">{{ t('guardian.decisions.hint') }}</p>
      </div>
      <ul
        v-if="status && status.decisions.length > 0"
        class="divide-hairline max-h-[28rem] divide-y overflow-auto text-sm"
      >
        <li
          v-for="(decision, index) in status.decisions"
          :key="index"
          class="grid grid-cols-[9rem_minmax(0,1fr)] gap-x-6 py-3"
        >
          <div class="flex flex-col gap-1">
            <span class="text-xs font-semibold" :class="OUTCOME_TONE[decision.outcome]">
              {{ t(`guardian.decisions.outcomes.${decision.outcome}`) }}
            </span>
            <span class="text-text-muted text-xs">{{ when(decision.unix_ms) }}</span>
          </div>
          <div class="flex min-w-0 flex-col gap-1">
            <div class="flex flex-wrap items-center gap-x-3">
              <IpCell :addr="decision.source" />
              <span class="text-text-muted">{{ t(`alerts.summary.${decision.summary_key}`) }}</span>
            </div>
            <p class="text-text-muted text-[13px]">{{ decision.why }}</p>
          </div>
        </li>
      </ul>
      <p v-else class="text-text-muted text-sm">{{ t('guardian.decisions.none') }}</p>
    </div>
  </section>
</template>

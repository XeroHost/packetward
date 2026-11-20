<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// RDP Shield: the optional country restriction (decision RS-2, option A). It is reactive: when an
// address from a refused country connects to the RDP port, the Guardian blocks it, but only in Active
// mode, never an address that is protected, and never one whose country is unknown. Off by default.
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Flag from '@/components/pw/Flag.vue'
import HIcon from '@/components/pw/HIcon.vue'
import SegmentedControl from '@/components/pw/SegmentedControl.vue'
import SettingRow from '@/components/pw/SettingRow.vue'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { countryName } from '@/lib/countries'
import { Cancel01Icon } from '@/lib/icons'
import { useAgentStore } from '@/stores/agent'
import { useRdpStore } from '@/stores/rdp'
import type { RdpCountryMode } from '@/types/generated/RdpCountryMode'

const { t, locale } = useI18n()
const rdp = useRdpStore()
const agent = useAgentStore()

const enabled = ref(false)
const mode = ref<RdpCountryMode>('deny')
const countries = ref<string[]>([])
const query = ref('')
const allCodes = ref<string[]>([])
const saved = ref(false)

onMounted(async () => {
  await rdp.loadCountry()
  // The list of ISO codes is not needed anywhere else: load it only with this row.
  const iso = (await import('i18n-iso-countries')).default
  allCodes.value = Object.keys(iso.getAlpha2Codes())
})

const status = computed(() => rdp.country)
watch(
  status,
  (value) => {
    if (!value) return
    enabled.value = value.policy.enabled
    mode.value = value.policy.mode
    countries.value = [...value.policy.countries]
  },
  { once: true },
)

const modeOptions = computed(() => [
  { value: 'deny' as const, label: t('rdp.country.deny') },
  { value: 'allow' as const, label: t('rdp.country.allow') },
])

/** Countries matching the search that are not chosen yet, by name in the language of the UI. */
const matches = computed(() => {
  const needle = query.value.trim().toLowerCase()
  if (needle === '') return []
  return allCodes.value
    .filter((code) => !countries.value.includes(code))
    .map((code) => ({ code, name: countryName(code, locale.value) }))
    .filter((c) => c.code.toLowerCase() === needle || c.name.toLowerCase().includes(needle))
    .sort((a, b) => a.name.localeCompare(b.name, locale.value))
    .slice(0, 6)
})

function add(code: string): void {
  if (!countries.value.includes(code)) countries.value = [...countries.value, code]
  query.value = ''
  saved.value = false
}
function remove(code: string): void {
  countries.value = countries.value.filter((c) => c !== code)
  saved.value = false
}

const geoReady = computed(() => status.value?.geo_ready ?? false)
const operator = computed(() => status.value?.operator_countries ?? [])
/** Allow mode that would shut out the country the operator is connected from. */
const locksOutOperator = computed(
  () =>
    enabled.value &&
    mode.value === 'allow' &&
    operator.value.some((code) => !countries.value.includes(code)),
)
const emptyAllow = computed(
  () => enabled.value && mode.value === 'allow' && countries.value.length === 0,
)
const monitorOnly = computed(() => agent.guardianMode !== 'active')

async function save(): Promise<void> {
  saved.value = await rdp.saveCountry({
    enabled: enabled.value,
    mode: mode.value,
    countries: countries.value,
  })
}
</script>

<template>
  <SettingRow :title="t('rdp.country.title')" :description="t('rdp.country.hint')">
    <div class="flex items-center gap-3">
      <Switch id="sw-rdp-country" v-model="enabled" @update:model-value="saved = false" />
      <Label for="sw-rdp-country">{{ t('rdp.country.enable') }}</Label>
    </div>

    <template v-if="enabled">
      <SegmentedControl v-model="mode" :options="modeOptions" :label="t('rdp.country.mode')" />

      <div class="flex flex-col gap-2">
        <Label for="rdp-country-search" class="text-text-muted text-xs">{{
          t('rdp.country.search')
        }}</Label>
        <input
          id="rdp-country-search"
          v-model="query"
          class="bg-surface-2 text-text focus-visible:ring-brand h-(--control-h) max-w-xs rounded-[10px] px-3 text-sm focus-visible:ring-2 focus-visible:outline-none"
          autocomplete="off"
          spellcheck="false"
          :placeholder="t('rdp.country.searchPlaceholder')"
        />
        <ul
          v-if="matches.length > 0"
          class="bg-surface-3 max-w-xs overflow-hidden rounded-[12px] p-1 shadow-md"
          role="listbox"
        >
          <li v-for="c in matches" :key="c.code" role="option" :aria-selected="false">
            <button
              type="button"
              class="hover:bg-surface-2 flex w-full items-center gap-2 rounded-[8px] px-2.5 py-1.5 text-left text-sm"
              @click="add(c.code)"
            >
              <Flag :code="c.code" :name="c.name" />
              <span class="min-w-0 flex-1 truncate">{{ c.name }}</span>
              <span class="text-text-muted font-mono text-xs">{{ c.code }}</span>
            </button>
          </li>
        </ul>
      </div>

      <ul v-if="countries.length > 0" class="flex flex-wrap gap-2" data-testid="country-chips">
        <li
          v-for="code in countries"
          :key="code"
          class="bg-surface-2 flex items-center gap-2 rounded-full py-1 pr-1.5 pl-2.5 text-[13px]"
        >
          <Flag :code="code" :name="countryName(code, locale)" />
          {{ countryName(code, locale) }}
          <button
            type="button"
            class="text-text-muted hover:text-text hover:bg-surface-3 flex size-5 items-center justify-center rounded-full"
            :aria-label="t('rdp.country.remove', { country: countryName(code, locale) })"
            @click="remove(code)"
          >
            <HIcon :icon="Cancel01Icon" :size="12" />
          </button>
        </li>
      </ul>
      <p v-else class="text-text-muted text-sm">{{ t('rdp.country.none') }}</p>
    </template>

    <p v-if="!geoReady" class="pw-note" data-tone="info" role="status">
      {{ t('rdp.country.noGeo') }}
    </p>
    <p v-if="emptyAllow" class="pw-note" data-tone="warning" role="alert">
      {{ t('rdp.country.emptyAllow') }}
    </p>
    <p v-if="locksOutOperator" class="pw-note" data-tone="danger" role="alert">
      {{
        t('rdp.country.locksYouOut', {
          countries: operator.map((code) => countryName(code, locale)).join(', '),
        })
      }}
    </p>
    <p v-if="enabled && monitorOnly" class="pw-note" data-tone="info" role="status">
      {{ t('rdp.country.monitor') }}
    </p>

    <div class="flex flex-wrap items-center gap-3">
      <Button :disabled="rdp.busy || emptyAllow" data-testid="country-save" @click="save">
        {{ t('rdp.country.save') }}
      </Button>
      <span v-if="saved && !rdp.countryError" class="text-sm" role="status">{{
        t('rdp.country.saved')
      }}</span>
      <span
        v-if="status && (status.blocked_24h > 0 || status.would_block_24h > 0)"
        class="text-text-muted text-xs"
      >
        {{
          t('rdp.country.activity', { blocked: status.blocked_24h, would: status.would_block_24h })
        }}
      </span>
    </div>
    <p v-if="rdp.countryError" class="text-danger text-sm" role="alert">
      {{ rdp.countryError.message }}
    </p>
  </SettingRow>
</template>

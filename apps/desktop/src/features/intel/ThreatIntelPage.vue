<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Globe2, ListChecks, Radar, ShieldQuestion, TriangleAlert } from 'lucide-vue-next'
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import IpCell from '@/components/pw/IpCell.vue'
import { Button } from '@/components/ui/button'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { useIntelStore } from '@/stores/intel'
import { useLiveStore } from '@/stores/live'
import type { ListStatusView } from '@/types/generated/ListStatusView'

const { t } = useI18n()
const intel = useIntelStore()
const live = useLiveStore()

const key = ref('')
const address = ref('')
/** The list whose switch-on is waiting for the second click. */
const pending = ref<string | null>(null)

let timer: ReturnType<typeof setInterval> | undefined

async function tick(): Promise<void> {
  if (intel.geo?.updating) await intel.refresh()
  if (intel.geoReady) await intel.updateCountries(live.stats?.top_remote ?? [])
}

onMounted(async () => {
  await intel.refresh()
  await tick()
  timer = setInterval(() => void tick(), 5000)
})
onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
})

function toggle(list: ListStatusView): void {
  if (list.enabled) {
    void intel.toggleList(list.id, false)
  } else {
    pending.value = list.id
  }
}

async function confirmEnable(id: string): Promise<void> {
  pending.value = null
  await intel.toggleList(id, true)
  await intel.refreshList(id)
}

async function saveKey(): Promise<void> {
  if (key.value.trim() === '') return
  await intel.saveKey(key.value.trim())
  key.value = ''
}

function when(secs: number | undefined): string {
  return secs === undefined ? t('intel.never') : new Date(secs * 1000).toLocaleString()
}

function every(secs: number): string {
  return secs >= 3600 ? `${Math.round(secs / 3600)} h` : `${Math.round(secs / 60)} min`
}

const card = 'bg-surface border-border flex flex-col gap-3 rounded-lg border p-[var(--card-p)]'
</script>

<template>
  <section class="flex flex-col gap-4">
    <p
      v-if="intel.error"
      class="border-danger/40 bg-danger/10 flex items-start gap-2 rounded-md border p-3 text-sm"
      role="alert"
    >
      <TriangleAlert class="text-danger mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{{ intel.error }}</span>
    </p>

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <div class="flex items-center gap-3">
        <Globe2 class="text-brand-fg size-5" aria-hidden="true" />
        <h2 class="text-base">{{ t('intel.geo.title') }}</h2>
      </div>
      <p class="text-text-muted text-sm">{{ t('intel.geo.hint') }}</p>
      <div v-if="intel.geo" class="flex flex-wrap items-center gap-3 text-sm">
        <span>{{ t(`intel.geo.state.${intel.geo.state}`) }}</span>
        <span v-if="intel.geo.build_date" class="text-text-muted">
          {{ t('intel.geo.built') }} {{ when(intel.geo.build_date) }}
        </span>
        <span v-if="intel.geo.updating" class="text-text-muted" role="status">{{
          t('intel.geo.updating')
        }}</span>
        <Button size="sm" :disabled="intel.geo.updating" @click="intel.updateGeo()">{{
          intel.geoReady ? t('intel.geo.update') : t('intel.geo.download')
        }}</Button>
      </div>
      <p v-if="intel.geo?.last_error" class="text-warning text-sm">{{ intel.geo.last_error }}</p>
      <p v-if="intel.geo" class="text-text-muted text-xs">{{ intel.geo.attribution }}</p>
    </div>

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <div class="flex items-center gap-3">
        <Radar class="text-brand-fg size-5" aria-hidden="true" />
        <h2 class="text-base">{{ t('intel.countries.title') }}</h2>
      </div>
      <p class="text-text-muted text-sm">{{ t('intel.countries.hint') }}</p>
      <p v-if="!intel.geoReady" class="text-text-muted text-sm">{{ t('intel.countries.noDb') }}</p>
      <p v-else-if="intel.countries.length === 0" class="text-text-muted text-sm">
        {{ t('intel.countries.empty') }}
      </p>
      <table v-else class="w-full text-sm">
        <thead class="text-text-muted text-left text-xs">
          <tr>
            <th class="py-1">{{ t('intel.countries.country') }}</th>
            <th class="py-1 text-right">{{ t('intel.countries.sources') }}</th>
            <th class="py-1 text-right">{{ t('intel.countries.connections') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in intel.countries" :key="row.code" class="border-border border-t">
            <td class="py-1">
              <span class="font-mono">{{ row.code }}</span> {{ row.name }}
            </td>
            <td class="py-1 text-right font-mono">{{ row.sources }}</td>
            <td class="py-1 text-right font-mono">{{ row.connections }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <div class="flex items-center gap-3">
        <ListChecks class="text-brand-fg size-5" aria-hidden="true" />
        <h2 class="text-base">{{ t('intel.lists.title') }}</h2>
      </div>
      <p class="text-text-muted text-sm">{{ t('intel.lists.hint') }}</p>
      <ul class="flex flex-col gap-3">
        <li
          v-for="list in intel.lists"
          :key="list.id"
          class="border-border flex flex-col gap-2 rounded-md border p-3"
        >
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-medium">{{ list.name }}</h3>
            <span v-if="list.signed" class="text-text-muted text-xs">{{
              t('intel.lists.signed')
            }}</span>
            <span class="text-text-muted ml-auto text-xs">
              {{ t('intel.lists.every', { interval: every(list.refresh_interval_secs) }) }}
            </span>
          </div>
          <p class="text-text-muted text-xs">{{ list.description }}</p>
          <p v-if="list.unavailable" class="text-warning text-xs">{{ list.unavailable }}</p>
          <p class="text-xs">
            {{ t('intel.lists.entries', { n: list.entries }) }} Â· {{ t('intel.lists.lastUpdate') }}
            {{ when(list.last_success) }}
          </p>
          <p v-if="list.last_error" class="text-warning text-xs">{{ list.last_error }}</p>
          <div class="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              :variant="list.enabled ? 'outline' : 'default'"
              :disabled="intel.busy || (!list.enabled && !!list.unavailable)"
              @click="toggle(list)"
            >
              {{ list.enabled ? t('intel.lists.disable') : t('intel.lists.enable') }}
            </Button>
            <Button
              v-if="list.enabled"
              size="sm"
              variant="outline"
              :disabled="intel.busy"
              @click="intel.refreshList(list.id)"
            >
              {{ t('intel.lists.refresh') }}
            </Button>
          </div>
          <div
            v-if="pending === list.id"
            class="border-warning/40 bg-warning/10 flex flex-col gap-2 rounded-md border p-3 text-sm"
            role="alertdialog"
          >
            <p>{{ t('intel.lists.confirm') }}</p>
            <div class="flex gap-2">
              <Button size="sm" @click="confirmEnable(list.id)">{{
                t('intel.lists.confirmYes')
              }}</Button>
              <Button size="sm" variant="outline" @click="pending = null">{{
                t('intel.lists.cancel')
              }}</Button>
            </div>
          </div>
        </li>
      </ul>
    </div>

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <div class="flex items-center gap-3">
        <ShieldQuestion class="text-brand-fg size-5" aria-hidden="true" />
        <h2 class="text-base">{{ t('intel.abuse.title') }}</h2>
      </div>
      <p class="text-text-muted text-sm">{{ t('intel.abuse.hint') }}</p>
      <p class="text-sm" role="status">
        {{ intel.abuse ? t(`intel.abuse.state.${intel.abuse.state}`) : 'â€¦' }}
      </p>
      <div class="flex flex-wrap items-end gap-2">
        <label class="flex min-w-60 flex-1 flex-col gap-1 text-sm">
          <span class="text-text-muted">{{ t('intel.abuse.key') }}</span>
          <input
            v-model="key"
            :class="FIELD"
            type="password"
            autocomplete="off"
            spellcheck="false"
          />
        </label>
        <Button size="sm" :disabled="key.trim() === ''" @click="saveKey()">{{
          t('intel.abuse.save')
        }}</Button>
        <Button
          v-if="intel.abuse?.configured"
          size="sm"
          variant="outline"
          @click="intel.saveKey(null)"
        >
          {{ t('intel.abuse.remove') }}
        </Button>
      </div>
      <div v-if="intel.abuse?.configured" class="flex flex-wrap items-end gap-2">
        <label class="flex min-w-60 flex-1 flex-col gap-1 text-sm">
          <span class="text-text-muted">{{ t('intel.abuse.address') }}</span>
          <input v-model="address" :class="[FIELD, 'font-mono']" spellcheck="false" />
        </label>
        <Button size="sm" :disabled="address.trim() === ''" @click="intel.checkAddress(address)">{{
          t('intel.abuse.check')
        }}</Button>
      </div>
      <p class="text-text-muted text-xs">{{ t('intel.abuse.privacy') }}</p>
      <dl v-if="intel.check" class="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <div>
          <dt class="text-text-muted">{{ t('intel.abuse.address') }}</dt>
          <dd><IpCell :addr="intel.check.addr" /></dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('intel.abuse.score') }}</dt>
          <dd class="font-mono text-lg">{{ intel.check.score }}%</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('intel.abuse.reports') }}</dt>
          <dd class="font-mono text-lg">{{ intel.check.total_reports }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('intel.abuse.isp') }}</dt>
          <dd>{{ intel.check.isp ?? 'â€”' }}</dd>
          <dd v-if="intel.check.from_cache" class="text-text-muted text-xs">
            {{ t('intel.abuse.cached') }}
          </dd>
        </div>
      </dl>
    </div>
  </section>
</template>

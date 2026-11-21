<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
// Threat intelligence as rows of "what it is / how it is set": the local GeoIP database, where the
// connections come from, the blocklists (each with its own switch and a confirmation before it
// touches the firewall) and the optional AbuseIPDB lookup.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { TriangleAlert } from '@/components/pw/icons'
import IpCell from '@/components/pw/IpCell.vue'
import SettingRow from '@/components/pw/SettingRow.vue'
import { Button } from '@/components/ui/button'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { useIntelStore } from '@/stores/intel'
import { useLiveStore } from '@/stores/live'
import AttackMap from './AttackMap.vue'
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

const mostConnections = computed(() => Math.max(1, ...intel.countries.map((c) => c.connections)))
</script>

<template>
  <section class="flex max-w-[64rem] flex-col">
    <p v-if="intel.error" class="pw-note mb-8" data-tone="danger" role="alert">
      <TriangleAlert class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{{ intel.error }}</span>
    </p>

    <div class="border-hairline mb-2 border-b pb-10">
      <AttackMap />
    </div>

    <SettingRow :title="t('intel.geo.title')" :description="t('intel.geo.hint')">
      <div v-if="intel.geo" class="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
        <span class="font-medium" :class="intel.geoReady ? 'text-success' : ''">{{
          t(`intel.geo.state.${intel.geo.state}`)
        }}</span>
        <span v-if="intel.geo.build_date" class="text-text-muted">
          {{ t('intel.geo.built') }} {{ when(intel.geo.build_date) }}
        </span>
        <span v-if="intel.geo.updating" class="text-text-muted" role="status">{{
          t('intel.geo.updating')
        }}</span>
        <Button
          class="ml-auto"
          size="sm"
          :variant="intel.geoReady ? 'outline' : 'default'"
          :disabled="intel.geo.updating"
          @click="intel.updateGeo()"
        >
          {{ intel.geoReady ? t('intel.geo.update') : t('intel.geo.download') }}
        </Button>
      </div>
      <p v-if="intel.geo?.last_error" class="pw-note" data-tone="warning">
        {{ intel.geo.last_error }}
      </p>
      <p v-if="intel.geo" class="text-text-muted text-xs">{{ intel.geo.attribution }}</p>
    </SettingRow>

    <SettingRow :title="t('intel.countries.title')" :description="t('intel.countries.hint')">
      <p v-if="!intel.geoReady" class="text-text-muted text-sm">{{ t('intel.countries.noDb') }}</p>
      <p v-else-if="intel.countries.length === 0" class="text-text-muted text-sm">
        {{ t('intel.countries.empty') }}
      </p>
      <table v-else class="pw-rows">
        <thead>
          <tr>
            <th>{{ t('intel.countries.country') }}</th>
            <th class="!text-right">{{ t('intel.countries.sources') }}</th>
            <th class="!text-right">{{ t('intel.countries.connections') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in intel.countries" :key="row.code">
            <td>
              <span class="font-mono">{{ row.code }}</span> {{ row.name }}
              <div
                class="bg-hairline mt-1 h-0.5 w-36 overflow-hidden rounded-full"
                aria-hidden="true"
              >
                <div
                  class="bg-chart-in h-full rounded-full opacity-60"
                  :style="{ width: `${(row.connections / mostConnections) * 100}%` }"
                />
              </div>
            </td>
            <td class="text-right font-mono">{{ row.sources }}</td>
            <td class="text-right font-mono">{{ row.connections }}</td>
          </tr>
        </tbody>
      </table>
    </SettingRow>

    <SettingRow :title="t('intel.lists.title')" :description="t('intel.lists.hint')">
      <ul class="divide-hairline divide-y">
        <li v-for="list in intel.lists" :key="list.id" class="flex flex-col gap-2 py-4 first:pt-0">
          <div class="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <h4 class="text-sm font-semibold">{{ list.name }}</h4>
            <span v-if="list.signed" class="text-text-muted text-xs">{{
              t('intel.lists.signed')
            }}</span>
            <span class="text-text-muted ml-auto text-xs">
              {{ t('intel.lists.every', { interval: every(list.refresh_interval_secs) }) }}
            </span>
          </div>
          <p class="text-text-muted text-[13px]">{{ list.description }}</p>
          <p v-if="list.unavailable" class="text-warning text-xs">{{ list.unavailable }}</p>
          <p class="text-xs">
            {{ t('intel.lists.entries', { n: list.entries }) }} ·
            <span class="text-text-muted"
              >{{ t('intel.lists.lastUpdate') }} {{ when(list.last_success) }}</span
            >
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
            class="pw-note pw-appear flex flex-col gap-3"
            data-tone="warning"
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
    </SettingRow>

    <SettingRow :title="t('intel.abuse.title')" :description="t('intel.abuse.hint')">
      <p class="text-sm font-medium" role="status">
        {{ intel.abuse ? t(`intel.abuse.state.${intel.abuse.state}`) : '…' }}
      </p>
      <div class="flex flex-wrap items-end gap-2">
        <label class="flex min-w-60 flex-1 flex-col gap-1.5 text-sm">
          <span class="text-text-muted text-xs">{{ t('intel.abuse.key') }}</span>
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
        <label class="flex min-w-60 flex-1 flex-col gap-1.5 text-sm">
          <span class="text-text-muted text-xs">{{ t('intel.abuse.address') }}</span>
          <input v-model="address" :class="[FIELD, 'font-mono']" spellcheck="false" />
        </label>
        <Button size="sm" :disabled="address.trim() === ''" @click="intel.checkAddress(address)">{{
          t('intel.abuse.check')
        }}</Button>
      </div>
      <p class="text-text-muted text-xs">{{ t('intel.abuse.privacy') }}</p>
      <dl
        v-if="intel.check"
        class="pw-appear border-hairline grid grid-cols-2 gap-y-4 border-t pt-5 sm:grid-cols-4"
      >
        <div>
          <dt class="text-text-muted text-xs">{{ t('intel.abuse.address') }}</dt>
          <dd class="mt-1"><IpCell :addr="intel.check.addr" /></dd>
        </div>
        <div>
          <dt class="text-text-muted text-xs">{{ t('intel.abuse.score') }}</dt>
          <dd class="font-heading mt-1 text-2xl font-semibold">{{ intel.check.score }}%</dd>
        </div>
        <div>
          <dt class="text-text-muted text-xs">{{ t('intel.abuse.reports') }}</dt>
          <dd class="font-heading mt-1 text-2xl font-semibold">{{ intel.check.total_reports }}</dd>
        </div>
        <div>
          <dt class="text-text-muted text-xs">{{ t('intel.abuse.isp') }}</dt>
          <dd class="mt-1">{{ intel.check.isp ?? '—' }}</dd>
          <dd v-if="intel.check.from_cache" class="text-text-muted text-xs">
            {{ t('intel.abuse.cached') }}
          </dd>
        </div>
      </dl>
    </SettingRow>
  </section>
</template>

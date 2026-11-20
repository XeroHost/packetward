<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { refDebounced } from '@vueuse/core'
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Plus, Trash2 } from '@/components/pw/icons'
import { LOCKOUT_PHRASE } from '@/api/defense'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { FIELD } from '@/features/diagnostics/fieldClass'
import FailureNote from '@/features/diagnostics/FailureNote.vue'
import { useDefenseStore } from '@/stores/defense'
import type { FirewallRuleView } from '@/types/generated/FirewallRuleView'
import PwSelect from '@/components/pw/PwSelect.vue'

const { t } = useI18n()
const defense = useDefenseStore()

const text = ref('')
const managedOnly = ref(false)
const debounced = refDebounced(text, 250)

/** The rule an action is waiting to be confirmed for. */
const pending = ref<{ rule: FirewallRuleView; action: 'disable' | 'enable' | 'delete' } | null>(
  null,
)
const phrase = ref('')

const adding = ref(false)
const draft = ref(blankRule())

function blankRule(): FirewallRuleView {
  return {
    name: '',
    description: '',
    group: '',
    direction: 'inbound',
    action: 'block',
    enabled: true,
    protocol: 'tcp',
    local_ports: '*',
    remote_ports: '*',
    local_addresses: '*',
    remote_addresses: '*',
    managed: false,
    builtin_rdp: false,
  }
}

async function reload(): Promise<void> {
  await defense.loadRules({
    managed_only: managedOnly.value,
    text: debounced.value.trim() === '' ? undefined : debounced.value.trim(),
  })
}
watch([debounced, managedOnly], () => void reload())
onMounted(() => void reload())

const needsPhrase = computed(() => pending.value?.rule.builtin_rdp === true)
const phraseOk = computed(() => !needsPhrase.value || phrase.value.trim() !== '')

function ask(rule: FirewallRuleView, action: 'disable' | 'enable' | 'delete'): void {
  // Enabling is harmless; turning off or removing needs a second click, and the built-in Remote
  // Desktop rules need the typed phrase.
  if (action === 'enable') {
    void run({ rule, action })
    return
  }
  pending.value = { rule, action }
  phrase.value = ''
}

async function run(item: {
  rule: FirewallRuleView
  action: 'disable' | 'enable' | 'delete'
}): Promise<void> {
  const confirmation = item.rule.builtin_rdp ? phrase.value : undefined
  const ok =
    item.action === 'delete'
      ? await defense.deleteRule(item.rule, confirmation)
      : await defense.setRuleEnabled(item.rule, item.action === 'enable', confirmation)
  pending.value = null
  phrase.value = ''
  if (ok) await reload()
}

async function create(): Promise<void> {
  if (await defense.createRule(draft.value)) {
    adding.value = false
    draft.value = blankRule()
    await reload()
  }
}

function summary(rule: FirewallRuleView): string {
  const ports = rule.local_ports !== '*' ? `:${rule.local_ports}` : ''
  const remote =
    rule.remote_addresses !== '*' && rule.remote_addresses !== ''
      ? ` ← ${rule.remote_addresses}`
      : ''
  return `${rule.protocol}${ports}${remote}`
}

const card = 'flex flex-col gap-4'

const directionOptions = computed(() => [
  { value: 'inbound' as const, label: t('firewall.rules.inbound') },
  { value: 'outbound' as const, label: t('firewall.rules.outbound') },
])

const actionOptions = computed(() => [
  { value: 'allow' as const, label: t('firewall.rules.allow') },
  { value: 'block' as const, label: t('firewall.rules.block') },
])

const protocolOptions = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'any', label: 'Any' },
] as const
</script>

<template>
  <div :class="card">
    <div class="flex flex-wrap items-end gap-3">
      <label class="flex min-w-64 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('connections.filters.search') }}</span>
        <input
          v-model="text"
          :class="FIELD"
          type="search"
          :placeholder="t('firewall.rules.searchPlaceholder')"
        />
      </label>
      <label class="flex h-(--control-h) items-center gap-2 text-sm">
        <input v-model="managedOnly" type="checkbox" />
        {{ t('firewall.rules.managedOnly') }}
      </label>
      <p class="text-text-muted pb-2 text-sm">
        {{ t('firewall.rules.count', { shown: defense.rules.length, total: defense.rulesTotal }) }}
      </p>
      <Button class="ml-auto" variant="outline" @click="adding = !adding">
        <Plus aria-hidden="true" />{{ t('firewall.rules.add') }}
      </Button>
    </div>
    <p class="text-text-muted text-xs">{{ t('firewall.rules.foreignNote') }}</p>

    <form
      v-if="adding"
      class="bg-surface-2 flex flex-wrap items-end gap-3 rounded-[12px] p-3"
      @submit.prevent="create"
    >
      <label class="flex w-48 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('firewall.rules.name') }}</span>
        <input v-model="draft.name" :class="FIELD" type="text" required />
      </label>
      <label class="flex w-32 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('firewall.rules.direction') }}</span>
        <PwSelect v-model="draft.direction" :options="directionOptions" />
      </label>
      <label class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('firewall.rules.action') }}</span>
        <PwSelect v-model="draft.action" :options="actionOptions" />
      </label>
      <label class="flex w-28 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('diagnostics.port.protocol') }}</span>
        <PwSelect v-model="draft.protocol" :options="protocolOptions" />
      </label>
      <label class="flex w-36 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('firewall.rules.localPorts') }}</span>
        <input v-model="draft.local_ports" :class="[FIELD, 'font-mono']" type="text" />
      </label>
      <label class="flex min-w-48 flex-1 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('firewall.rules.remoteAddresses') }}</span>
        <input v-model="draft.remote_addresses" :class="[FIELD, 'font-mono']" type="text" />
      </label>
      <Button type="submit" :disabled="defense.busy">{{ t('firewall.rules.create') }}</Button>
    </form>

    <FailureNote v-if="defense.rulesError" :failure="defense.rulesError" />

    <div v-if="pending" class="pw-note flex flex-col gap-2" data-tone="warning" role="alertdialog">
      <p>
        {{ t(`firewall.rules.confirm.${pending.action}`, { name: pending.rule.name }) }}
      </p>
      <p v-if="!pending.rule.managed" class="text-warning">
        {{ t('firewall.rules.foreignWarning') }}
      </p>
      <label v-if="needsPhrase" class="flex flex-col gap-1">
        <span>{{ t('firewall.rules.lockoutPhrase', { phrase: LOCKOUT_PHRASE }) }}</span>
        <input v-model="phrase" :class="FIELD" type="text" :placeholder="LOCKOUT_PHRASE" />
      </label>
      <div class="flex gap-2">
        <Button
          size="sm"
          variant="destructive"
          :disabled="!phraseOk || defense.busy"
          @click="run(pending)"
        >
          {{ t('firewall.rules.confirmYes') }}
        </Button>
        <Button size="sm" variant="outline" @click="pending = null">{{
          t('capture.files.cancel')
        }}</Button>
      </div>
    </div>

    <div class="bg-surface-2 max-h-[32rem] overflow-auto rounded-[12px]">
      <table class="w-full text-sm">
        <thead class="text-text-muted sticky top-0 text-left text-[11px] tracking-wide uppercase">
          <tr>
            <th class="px-3 py-2 font-medium">{{ t('firewall.rules.name') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('firewall.rules.direction') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('firewall.rules.action') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('firewall.rules.what') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('firewall.rules.state') }}</th>
            <th class="px-3 py-2" />
          </tr>
        </thead>
        <tbody class="divide-hairline divide-y">
          <!-- Windows allows several rules with the same name and direction (one per profile). -->
          <tr
            v-for="(rule, index) in defense.rules"
            :key="`${rule.name}|${rule.direction}|${index}`"
          >
            <td class="px-3 py-1.5">
              <span>{{ rule.name }}</span>
              <Badge
                v-if="rule.managed"
                variant="outline"
                class="border-brand-fg/50 text-brand-fg ml-2"
                >PacketWard</Badge
              >
              <Badge
                v-if="rule.builtin_rdp"
                variant="outline"
                class="border-warning/50 text-warning ml-2"
                >RDP</Badge
              >
            </td>
            <td class="px-3 py-1.5">{{ t(`firewall.rules.${rule.direction}`) }}</td>
            <td class="px-3 py-1.5" :class="rule.action === 'block' ? 'text-danger' : ''">
              {{ t(`firewall.rules.${rule.action}`) }}
            </td>
            <td class="text-text-muted px-3 py-1.5 font-mono text-xs">{{ summary(rule) }}</td>
            <td class="px-3 py-1.5">
              <button
                type="button"
                class="focus-visible:ring-brand rounded px-1 underline focus-visible:ring-2 focus-visible:outline-none"
                :class="rule.enabled ? 'text-success' : 'text-text-muted'"
                @click="ask(rule, rule.enabled ? 'disable' : 'enable')"
              >
                {{ rule.enabled ? t('firewall.rules.enabled') : t('firewall.rules.disabled') }}
              </button>
            </td>
            <td class="px-3 py-1.5 text-right">
              <Button
                size="icon-xs"
                variant="ghost"
                :aria-label="t('firewall.rules.delete', { name: rule.name })"
                @click="ask(rule, 'delete')"
              >
                <Trash2 aria-hidden="true" />
              </Button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-if="defense.rulesTruncated" class="text-text-muted text-xs">
      {{ t('firewall.rules.truncated') }}
    </p>
  </div>
</template>

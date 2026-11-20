<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ShieldBan, Trash2 } from '@/components/pw/icons'
import IpCell from '@/components/pw/IpCell.vue'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { FIELD } from '@/features/diagnostics/fieldClass'
import FailureNote from '@/features/diagnostics/FailureNote.vue'
import { LOCKOUT_PHRASE } from '@/api/defense'
import { splitTargets, useDefenseStore } from '@/stores/defense'

const { t } = useI18n()
const defense = useDefenseStore()

const targetsText = ref('')
const duration = ref<number | 'forever'>(3600)
const reason = ref('')
const confirmAll = ref(false)
const purgeOpen = ref(false)
const purgePhrase = ref('')
const purged = ref<string[] | null>(null)

const DURATIONS: readonly (number | 'forever')[] = [900, 3600, 86400, 604800, 'forever']

function durationLabel(value: number | 'forever'): string {
  if (value === 'forever') return t('firewall.blocks.forever')
  if (value < 3600) return t('firewall.blocks.minutes', { n: value / 60 })
  if (value < 86400) return t('firewall.blocks.hours', { n: value / 3600 })
  return t('firewall.blocks.days', { n: value / 86400 })
}

async function submit(): Promise<void> {
  const targets = splitTargets(targetsText.value)
  if (targets.length === 0) return
  const result = await defense.block(
    targets,
    duration.value === 'forever' ? undefined : duration.value,
    reason.value.trim(),
  )
  if (result && result.refused_protected.length === 0 && result.refused_broad.length === 0) {
    targetsText.value = ''
  }
}

function when(ms: number | undefined): string {
  return ms === undefined ? t('firewall.blocks.untilRemoved') : new Date(ms).toLocaleString()
}

async function unblockAll(): Promise<void> {
  confirmAll.value = false
  await defense.unblockEverything()
}

async function doPurge(): Promise<void> {
  const removed = await defense.purge(
    purgePhrase.value.trim() === '' ? undefined : purgePhrase.value,
  )
  if (removed) {
    purged.value = removed
    purgeOpen.value = false
    purgePhrase.value = ''
  }
}

onMounted(() => void defense.loadBlocks())
</script>

<template>
  <div class="flex flex-col gap-4">
    <p class="text-text-muted text-sm">{{ t('firewall.blocks.hint') }}</p>

    <form class="flex flex-wrap items-end gap-3" @submit.prevent="submit">
      <label class="flex min-w-72 flex-1 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('firewall.blocks.targets') }}</span>
        <textarea
          v-model="targetsText"
          :class="[FIELD, 'h-20 py-2 font-mono']"
          spellcheck="false"
          placeholder="203.0.113.7&#10;198.51.100.0/24"
        />
      </label>
      <label class="flex w-44 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('firewall.blocks.duration') }}</span>
        <select v-model="duration" :class="FIELD">
          <option v-for="value in DURATIONS" :key="value" :value="value">
            {{ durationLabel(value) }}
          </option>
        </select>
      </label>
      <label class="flex w-56 flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('firewall.blocks.reason') }}</span>
        <input v-model="reason" :class="FIELD" type="text" />
      </label>
      <Button type="submit" :disabled="defense.busy || splitTargets(targetsText).length === 0">
        <ShieldBan aria-hidden="true" />{{ t('firewall.blocks.block') }}
      </Button>
    </form>

    <FailureNote v-if="defense.blocksError" :failure="defense.blocksError" />

    <div
      v-if="
        defense.lastBlockResult &&
        (defense.lastBlockResult.refused_protected.length > 0 ||
          defense.lastBlockResult.refused_broad.length > 0)
      "
      class="pw-note flex flex-col gap-1"
      data-tone="warning"
      role="alert"
    >
      <p v-for="item in defense.lastBlockResult.refused_protected" :key="item.target">
        <span class="font-mono">{{ item.target }}</span> —
        {{
          t('firewall.blocks.refusedProtected', {
            reason: t(`firewall.protectedReasons.${item.reason}`),
          })
        }}
      </p>
      <p v-for="item in defense.lastBlockResult.refused_broad" :key="item">
        <span class="font-mono">{{ item }}</span> — {{ t('firewall.blocks.refusedBroad') }}
      </p>
    </div>

    <div class="flex flex-wrap items-center justify-between gap-3">
      <p class="text-text-muted text-sm">
        {{ t('firewall.blocks.count', { count: defense.blocks.length, rules: defense.rulesUsed }) }}
      </p>
      <div v-if="!confirmAll" class="flex gap-2">
        <Button
          size="sm"
          variant="outline"
          :disabled="defense.blocks.length === 0"
          @click="confirmAll = true"
        >
          {{ t('firewall.blocks.unblockAll') }}
        </Button>
      </div>
      <div v-else class="flex items-center gap-2 text-sm">
        <span class="text-warning">{{ t('firewall.blocks.unblockAllConfirm') }}</span>
        <Button size="sm" variant="destructive" @click="unblockAll">{{
          t('firewall.blocks.unblockAllYes')
        }}</Button>
        <Button size="sm" variant="outline" @click="confirmAll = false">{{
          t('capture.files.cancel')
        }}</Button>
      </div>
    </div>

    <div v-if="defense.blocks.length > 0" class="bg-surface-2 overflow-auto rounded-[12px]">
      <table class="w-full text-sm">
        <thead class="text-text-muted text-left text-[11px] tracking-wide uppercase">
          <tr>
            <th class="px-3 py-2 font-medium">{{ t('firewall.blocks.address') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('firewall.blocks.source') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('firewall.blocks.why') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('firewall.blocks.until') }}</th>
            <th class="px-3 py-2" />
          </tr>
        </thead>
        <tbody class="divide-hairline divide-y">
          <tr v-for="item in defense.blocks" :key="item.cidr">
            <td class="px-3 py-1.5 font-mono"><IpCell :addr="item.cidr" /></td>
            <td class="px-3 py-1.5">
              <Badge variant="outline">{{ t(`firewall.blocks.sources.${item.source}`) }}</Badge>
              <span v-if="item.escalation > 1" class="text-text-muted ml-1 text-xs">
                {{ t('firewall.blocks.repeat', { n: item.escalation }) }}
              </span>
            </td>
            <td class="text-text-muted px-3 py-1.5">{{ item.reason || '—' }}</td>
            <td class="px-3 py-1.5">{{ when(item.expires_unix_ms) }}</td>
            <td class="px-3 py-1.5 text-right">
              <Button
                size="icon-xs"
                variant="ghost"
                :aria-label="t('firewall.blocks.unblock', { addr: item.cidr })"
                @click="defense.unblock([item.cidr])"
              >
                <Trash2 aria-hidden="true" />
              </Button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-else class="text-text-muted text-sm">{{ t('firewall.blocks.none') }}</p>

    <details
      class="bg-surface-2 rounded-[12px] p-3 text-sm"
      :open="purgeOpen"
      @toggle="purgeOpen = ($event.target as HTMLDetailsElement).open"
    >
      <summary class="cursor-pointer font-medium">{{ t('firewall.purge.title') }}</summary>
      <p class="text-text-muted mt-2">{{ t('firewall.purge.hint') }}</p>
      <label class="mt-3 flex flex-col gap-1">
        <span class="text-text-muted">{{
          t('firewall.purge.phrase', { phrase: LOCKOUT_PHRASE })
        }}</span>
        <input v-model="purgePhrase" :class="FIELD" type="text" :placeholder="LOCKOUT_PHRASE" />
      </label>
      <Button
        class="mt-3"
        variant="destructive"
        size="sm"
        :disabled="defense.busy"
        @click="doPurge"
      >
        {{ t('firewall.purge.run') }}
      </Button>
      <p v-if="purged" class="mt-2" role="status">
        {{ t('firewall.purge.done', { count: purged.length }) }}
      </p>
    </details>
  </div>
</template>

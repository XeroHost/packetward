<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { animate } from 'motion-v'
import { computed, nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { springDialog } from '@/lib/motion'
import { useDefenseStore } from '@/stores/defense'
import PwSelect from '@/components/pw/PwSelect.vue'

const { t } = useI18n()
const defense = useDefenseStore()

const dialog = ref<HTMLDialogElement | null>(null)
const duration = ref<number | 'forever'>(3600)
const reason = ref('')
const done = ref(false)

const DURATIONS: readonly (number | 'forever')[] = [900, 3600, 86400, 604800, 'forever']
const target = computed(() => defense.blockTarget)

function label(value: number | 'forever'): string {
  if (value === 'forever') return t('firewall.blocks.forever')
  if (value < 3600) return t('firewall.blocks.minutes', { n: value / 60 })
  if (value < 86400) return t('firewall.blocks.hours', { n: value / 3600 })
  return t('firewall.blocks.days', { n: value / 86400 })
}

watch(target, async (addr) => {
  await nextTick()
  if (addr) {
    done.value = false
    reason.value = ''
    dialog.value?.showModal()
    // The dialog grows out of the page with a spring (unless animations are off).
    if (dialog.value && document.documentElement.dataset.motion !== 'reduced') {
      animate(dialog.value, { opacity: [0, 1], scale: [0.95, 1], y: [10, 0] }, springDialog)
    }
  } else {
    dialog.value?.close()
  }
})

async function confirm(): Promise<void> {
  if (!target.value) return
  const result = await defense.block(
    [target.value],
    duration.value === 'forever' ? undefined : duration.value,
    reason.value.trim(),
  )
  done.value = result !== undefined && result.blocked.length > 0
  if (done.value) defense.closeBlock()
}

async function allow(): Promise<void> {
  if (!target.value) return
  // Start from what the agent has now, so another change is not overwritten.
  await defense.loadAllowlist()
  const current = [...defense.allowlist.allowlist]
  const merged = current.includes(target.value) ? current : [...current, target.value]
  if (await defense.updateAllowlist({ ...defense.allowlist, allowlist: merged }))
    defense.closeBlock()
}

const durationOptions = computed(() => DURATIONS.map((value) => ({ value, label: label(value) })))
</script>

<template>
  <dialog
    ref="dialog"
    class="pw-dialog m-auto w-[28rem] max-w-[90vw]"
    @close="defense.closeBlock()"
  >
    <form v-if="target" class="flex flex-col gap-3" method="dialog" @submit.prevent="confirm">
      <h2 class="text-xl">{{ t('firewall.dialog.title') }}</h2>
      <p class="pw-well font-mono text-sm">{{ target }}</p>
      <p class="text-text-muted text-sm">{{ t('firewall.dialog.consequence') }}</p>
      <label class="flex flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('firewall.blocks.duration') }}</span>
        <PwSelect v-model="duration" :options="durationOptions" />
      </label>
      <label class="flex flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('firewall.blocks.reason') }}</span>
        <input v-model="reason" :class="FIELD" type="text" />
      </label>
      <div
        v-if="defense.lastBlockResult && defense.lastBlockResult.refused_protected.length > 0"
        class="pw-note"
        data-tone="warning"
        role="alert"
      >
        {{
          t('firewall.blocks.refusedProtected', {
            reason: t(
              `firewall.protectedReasons.${defense.lastBlockResult.refused_protected[0]?.reason ?? 'allowlist'}`,
            ),
          })
        }}
      </div>
      <div class="flex flex-wrap justify-end gap-2">
        <Button type="button" variant="ghost" size="sm" :disabled="defense.busy" @click="allow">
          {{ t('firewall.dialog.allow') }}
        </Button>
        <Button type="button" variant="outline" size="sm" @click="defense.closeBlock()">
          {{ t('capture.files.cancel') }}
        </Button>
        <Button type="submit" variant="destructive" size="sm" :disabled="defense.busy">
          {{ t('firewall.blocks.block') }}
        </Button>
      </div>
    </form>
  </dialog>
</template>

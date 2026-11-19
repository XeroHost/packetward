<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { LifeBuoy, ShieldHalf } from 'lucide-vue-next'
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { LOCKOUT_PHRASE } from '@/api/defense'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import FailureNote from '@/features/diagnostics/FailureNote.vue'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { splitTargets } from '@/stores/defense'
import { useLiveStore } from '@/stores/live'
import { useRdpStore } from '@/stores/rdp'
import type { AlertSeverity } from '@/types/generated/AlertSeverity'

const { t } = useI18n()
const rdp = useRdpStore()
const live = useLiveStore()

const audit = computed(() => rdp.audit)
const locked = computed(() => rdp.pending !== null || rdp.busy)

const TONE: Record<AlertSeverity, string> = {
  low: 'border-border text-text-muted',
  medium: 'border-warning/50 text-warning',
  high: 'border-danger/50 text-danger',
  critical: 'border-danger bg-danger/15 text-danger',
}

// Restrict
const allowedText = ref('')
const disableBuiltin = ref(false)
const phrase = ref('')
// Port
const newPort = ref(43389)
const understandPort = ref(false)
// Lockout
const lockThreshold = ref(10)
const lockWindow = ref(15)
const lockDuration = ref(15)
const understandDos = ref(false)
// Attempts
const attempts = ref({ threshold: 10, window_secs: 300 })
// Sessions + reset
const endingSession = ref<{ id: number; logoff: boolean } | null>(null)
const confirmReset = ref(false)

watch(
  audit,
  (value) => {
    if (!value) return
    attempts.value = { ...value.attempts }
    if (value.lockout_threshold > 0) {
      lockThreshold.value = value.lockout_threshold
      lockWindow.value = value.lockout_window_mins
      lockDuration.value = value.lockout_duration_mins
    }
  },
  { once: true },
)

async function restrict(): Promise<void> {
  await rdp.restrict({
    allowed: splitTargets(allowedText.value),
    disable_builtin: disableBuiltin.value,
    confirmation: disableBuiltin.value ? phrase.value : undefined,
  })
}

async function changePort(): Promise<void> {
  if (
    await rdp.changePort({ port: Math.floor(newPort.value), i_understand: understandPort.value })
  ) {
    understandPort.value = false
  }
}

async function applyLockout(): Promise<void> {
  await rdp.setLockout({
    threshold: Math.floor(lockThreshold.value),
    window_mins: Math.floor(lockWindow.value),
    duration_mins: Math.floor(lockDuration.value),
    understand_dos: understandDos.value,
  })
}

async function endSession(): Promise<void> {
  if (!endingSession.value) return
  await rdp.endSession(endingSession.value.id, endingSession.value.logoff)
  endingSession.value = null
}

async function doReset(): Promise<void> {
  confirmReset.value = false
  await rdp.reset()
}

onMounted(() => void rdp.load())

const card = 'bg-surface border-border flex flex-col gap-3 rounded-lg border p-[var(--card-p)]'
</script>

<template>
  <section class="flex flex-col gap-4">
    <FailureNote v-if="rdp.error" :failure="rdp.error" />

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <div class="flex items-center gap-3">
        <ShieldHalf class="text-brand-fg size-5" aria-hidden="true" />
        <h2 class="text-base">{{ t('rdp.audit.title') }}</h2>
      </div>
      <dl v-if="audit" class="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <div>
          <dt class="text-text-muted">{{ t('rdp.audit.service') }}</dt>
          <dd>{{ audit.enabled ? t('rdp.audit.on') : t('rdp.audit.off') }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('diagnostics.port.port') }}</dt>
          <dd class="font-mono">{{ audit.port }}</dd>
        </div>
        <div>
          <dt class="text-text-muted">NLA</dt>
          <dd :class="audit.nla_required ? '' : 'text-danger'">
            {{ audit.nla_required ? t('rdp.audit.required') : t('rdp.audit.notRequired') }}
          </dd>
        </div>
        <div>
          <dt class="text-text-muted">{{ t('rdp.audit.firewall') }}</dt>
          <dd :class="audit.open_to_any && !audit.restricted ? 'text-danger' : ''">
            {{
              audit.restricted
                ? t('rdp.audit.restricted', { count: audit.allowed.length })
                : audit.open_to_any
                  ? t('rdp.audit.openToAny')
                  : t('rdp.audit.notOpen')
            }}
          </dd>
        </div>
      </dl>
      <ul v-if="audit && audit.findings.length > 0" class="flex flex-col gap-2">
        <li
          v-for="finding in audit.findings"
          :key="finding.id"
          class="border-border flex flex-col gap-1 rounded-md border p-3 text-sm"
        >
          <div class="flex items-center gap-2">
            <Badge variant="outline" :class="TONE[finding.severity]">
              {{ t(`alerts.severity.${finding.severity}`) }}
            </Badge>
            <span class="font-medium">{{ t(`rdp.findings.${finding.id}.title`) }}</span>
          </div>
          <p class="text-text-muted">{{ t(`rdp.findings.${finding.id}.fix`) }}</p>
        </li>
      </ul>
      <p v-else-if="audit" class="text-success text-sm">{{ t('rdp.audit.clean') }}</p>
    </div>

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <h2 class="text-base">{{ t('rdp.restrict.title') }}</h2>
      <p class="text-text-muted text-sm">{{ t('rdp.restrict.hint') }}</p>
      <label class="flex flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('rdp.restrict.allowed') }}</span>
        <textarea
          v-model="allowedText"
          :class="[FIELD, 'h-24 py-2 font-mono']"
          spellcheck="false"
          :placeholder="audit?.allowed.join('\n')"
        />
      </label>
      <label class="flex items-center gap-2 text-sm">
        <input v-model="disableBuiltin" type="checkbox" />
        {{ t('rdp.restrict.disableBuiltin') }}
      </label>
      <label v-if="disableBuiltin" class="flex flex-col gap-1 text-sm">
        <span class="text-warning">{{
          t('firewall.rules.lockoutPhrase', { phrase: LOCKOUT_PHRASE })
        }}</span>
        <input v-model="phrase" :class="FIELD" type="text" :placeholder="LOCKOUT_PHRASE" />
      </label>
      <div class="flex flex-wrap gap-2">
        <Button :disabled="locked" @click="restrict">{{ t('rdp.restrict.apply') }}</Button>
        <Button
          v-if="audit?.restricted"
          variant="outline"
          :disabled="locked"
          @click="rdp.unrestrict()"
        >
          {{ t('rdp.restrict.remove') }}
        </Button>
      </div>
    </div>

    <div class="grid gap-4 lg:grid-cols-2">
      <div :class="card" style="box-shadow: var(--shadow-card)">
        <h2 class="text-base">{{ t('rdp.port.title') }}</h2>
        <p class="text-text-muted text-sm">{{ t('rdp.port.hint') }}</p>
        <div class="flex flex-wrap items-end gap-3">
          <label class="flex w-32 flex-col gap-1 text-sm">
            <span class="text-text-muted">{{ t('rdp.port.new') }}</span>
            <input v-model.number="newPort" :class="FIELD" type="number" min="1024" max="65535" />
          </label>
          <Button :disabled="locked || !understandPort" @click="changePort">{{
            t('rdp.port.apply')
          }}</Button>
        </div>
        <label class="flex items-start gap-2 text-sm">
          <input v-model="understandPort" type="checkbox" class="mt-1" />
          {{ t('rdp.port.understand') }}
        </label>
      </div>

      <div :class="card" style="box-shadow: var(--shadow-card)">
        <h2 class="text-base">{{ t('rdp.nla.title') }}</h2>
        <p class="text-text-muted text-sm">{{ t('rdp.nla.hint') }}</p>
        <div class="flex gap-2">
          <Button :disabled="locked || audit?.nla_required" @click="rdp.setNla(true)">{{
            t('rdp.nla.require')
          }}</Button>
          <Button
            variant="outline"
            :disabled="locked || !audit?.nla_required"
            @click="rdp.setNla(false)"
          >
            {{ t('rdp.nla.allowOff') }}
          </Button>
        </div>
      </div>

      <div :class="card" style="box-shadow: var(--shadow-card)">
        <h2 class="text-base">{{ t('rdp.attempts.title') }}</h2>
        <p class="text-text-muted text-sm">{{ t('rdp.attempts.hint') }}</p>
        <div class="flex flex-wrap items-end gap-3">
          <label class="flex w-32 flex-col gap-1 text-sm">
            <span class="text-text-muted">{{ t('rdp.attempts.threshold') }}</span>
            <input
              v-model.number="attempts.threshold"
              :class="FIELD"
              type="number"
              min="3"
              max="100"
            />
          </label>
          <label class="flex w-36 flex-col gap-1 text-sm">
            <span class="text-text-muted">{{ t('rdp.attempts.window') }}</span>
            <input
              v-model.number="attempts.window_secs"
              :class="FIELD"
              type="number"
              min="30"
              max="3600"
            />
          </label>
          <Button variant="outline" :disabled="rdp.busy" @click="rdp.setAttempts({ ...attempts })">
            {{ t('firewall.protected.save') }}
          </Button>
        </div>
        <p class="text-text-muted text-xs">{{ t('rdp.attempts.guardian') }}</p>
      </div>

      <div :class="card" style="box-shadow: var(--shadow-card)">
        <h2 class="text-base">{{ t('rdp.lockout.title') }}</h2>
        <p class="text-warning text-sm">{{ t('rdp.lockout.warning') }}</p>
        <div class="flex flex-wrap items-end gap-3">
          <label class="flex w-28 flex-col gap-1 text-sm">
            <span class="text-text-muted">{{ t('rdp.lockout.threshold') }}</span>
            <input v-model.number="lockThreshold" :class="FIELD" type="number" min="0" max="50" />
          </label>
          <label class="flex w-28 flex-col gap-1 text-sm">
            <span class="text-text-muted">{{ t('rdp.lockout.window') }}</span>
            <input v-model.number="lockWindow" :class="FIELD" type="number" min="1" max="1440" />
          </label>
          <label class="flex w-28 flex-col gap-1 text-sm">
            <span class="text-text-muted">{{ t('rdp.lockout.duration') }}</span>
            <input v-model.number="lockDuration" :class="FIELD" type="number" min="1" max="1440" />
          </label>
        </div>
        <label class="flex items-start gap-2 text-sm">
          <input v-model="understandDos" type="checkbox" class="mt-1" />
          {{ t('rdp.lockout.understand') }}
        </label>
        <div class="flex flex-wrap gap-2">
          <Button :disabled="locked || (lockThreshold > 0 && !understandDos)" @click="applyLockout">
            {{ t('rdp.lockout.apply') }}
          </Button>
          <Button
            v-if="(audit?.lockout_threshold ?? 0) > 0"
            variant="outline"
            :disabled="locked"
            @click="
              rdp.setLockout({
                threshold: 0,
                window_mins: 15,
                duration_mins: 15,
                understand_dos: false,
              })
            "
          >
            {{ t('rdp.lockout.turnOff') }}
          </Button>
        </div>
      </div>
    </div>

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <h2 class="text-base">{{ t('rdp.sessions.title') }}</h2>
      <ul
        v-if="live.stats && live.stats.rdp_sessions.length > 0"
        class="divide-border border-border divide-y rounded-md border text-sm"
      >
        <li
          v-for="session in live.stats.rdp_sessions"
          :key="session.session_id"
          class="flex flex-wrap items-center gap-3 px-3 py-2"
        >
          <span class="font-mono">#{{ session.session_id }}</span>
          <span>{{ session.user || '—' }}</span>
          <Badge variant="outline">{{ session.state }}</Badge>
          <span class="text-text-muted">{{ session.client_name }}</span>
          <span class="ml-auto flex gap-2">
            <template v-if="endingSession?.id === session.session_id">
              <span class="text-warning">{{
                endingSession.logoff
                  ? t('rdp.sessions.confirmLogoff')
                  : t('rdp.sessions.confirmDisconnect')
              }}</span>
              <Button size="xs" variant="destructive" @click="endSession">{{
                t('firewall.rules.confirmYes')
              }}</Button>
              <Button size="xs" variant="outline" @click="endingSession = null">{{
                t('capture.files.cancel')
              }}</Button>
            </template>
            <template v-else>
              <Button
                size="xs"
                variant="outline"
                @click="endingSession = { id: session.session_id, logoff: false }"
                >{{ t('rdp.sessions.disconnect') }}</Button
              >
              <Button
                size="xs"
                variant="outline"
                @click="endingSession = { id: session.session_id, logoff: true }"
                >{{ t('rdp.sessions.logoff') }}</Button
              >
            </template>
          </span>
        </li>
      </ul>
      <p v-else class="text-text-muted text-sm">{{ t('rdp.sessions.none') }}</p>
    </div>

    <div :class="card" style="box-shadow: var(--shadow-card)">
      <div class="flex items-center gap-3">
        <LifeBuoy class="text-brand-fg size-5" aria-hidden="true" />
        <h2 class="text-base">{{ t('rdp.recovery.title') }}</h2>
      </div>
      <p class="text-sm">{{ t('rdp.recovery.hint') }}</p>
      <code class="bg-surface-2 rounded-md px-2 py-1 font-mono text-xs">pwctl rdp reset</code>
      <div v-if="!confirmReset">
        <Button variant="outline" :disabled="rdp.busy" @click="confirmReset = true">{{
          t('rdp.recovery.reset')
        }}</Button>
      </div>
      <div v-else class="flex items-center gap-2 text-sm">
        <span class="text-warning">{{ t('rdp.recovery.confirm') }}</span>
        <Button size="sm" variant="destructive" @click="doReset">{{
          t('rdp.recovery.yes')
        }}</Button>
        <Button size="sm" variant="outline" @click="confirmReset = false">{{
          t('capture.files.cancel')
        }}</Button>
      </div>
    </div>
  </section>
</template>

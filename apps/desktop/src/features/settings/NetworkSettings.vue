<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<script setup lang="ts">
import SettingRow from '@/components/pw/SettingRow.vue'
import { TriangleAlert } from '@/components/pw/icons'
import { onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { FIELD } from '@/features/diagnostics/fieldClass'
import { useLogsStore } from '@/stores/logs'

const { t } = useI18n()
const logs = useLogsStore()
const proxy = ref('')
const username = ref('')
const password = ref('')
const saved = ref(false)

onMounted(async () => {
  await logs.loadSettings()
})
watch(
  () => logs.settings?.proxy,
  (value) => {
    proxy.value = value ?? ''
  },
  { immediate: true },
)
watch(
  () => logs.settings?.proxy_username,
  (value) => {
    username.value = value ?? ''
  },
  { immediate: true },
)

async function save(): Promise<void> {
  saved.value = await logs.saveProxy(proxy.value, {
    username: username.value.trim(),
    password: password.value,
  })
  // The password is never shown again: the agent keeps it in the Windows Credential Manager.
  if (saved.value) password.value = ''
}

async function removeCredentials(): Promise<void> {
  saved.value = await logs.saveProxy(proxy.value, { clearCredentials: true })
  if (saved.value) {
    username.value = ''
    password.value = ''
  }
}
</script>

<template>
  <SettingRow :title="t('settings.network.title')" :description="t('settings.network.description')">
    <form class="flex flex-col gap-3" @submit.prevent="save">
      <label class="flex max-w-xl flex-col gap-1 text-sm">
        <span class="text-text-muted">{{ t('settings.network.proxy') }}</span>
        <input
          v-model="proxy"
          :class="[FIELD, 'font-mono']"
          spellcheck="false"
          autocomplete="off"
          placeholder="http://proxy.example.com:3128"
        />
      </label>
      <div v-if="proxy.trim() !== ''" class="flex flex-wrap gap-3">
        <label class="flex w-56 flex-col gap-1 text-sm">
          <span class="text-text-muted">{{ t('settings.network.username') }}</span>
          <input
            v-model="username"
            :class="FIELD"
            spellcheck="false"
            autocomplete="off"
            data-testid="proxy-username"
          />
        </label>
        <label class="flex w-56 flex-col gap-1 text-sm">
          <span class="text-text-muted">{{ t('settings.network.password') }}</span>
          <input
            v-model="password"
            :class="FIELD"
            type="password"
            autocomplete="new-password"
            :placeholder="
              logs.settings?.proxy_credentials ? t('settings.network.passwordKeep') : ''
            "
            data-testid="proxy-password"
          />
        </label>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <Button type="submit" size="sm">{{ t('settings.network.save') }}</Button>
        <Button
          v-if="logs.settings?.proxy_credentials"
          type="button"
          size="sm"
          variant="outline"
          @click="removeCredentials"
        >
          {{ t('settings.network.credentialsRemove') }}
        </Button>
      </div>
    </form>
    <p class="text-text-muted text-xs">{{ t('settings.network.hint') }}</p>
    <p v-if="logs.settings?.proxy_credentials" class="text-text-muted text-xs">
      {{ t('settings.network.credentialsSaved', { user: logs.settings.proxy_username ?? '' }) }}
    </p>
    <p v-if="saved && !logs.settingsError" class="text-sm" role="status">
      {{ t('settings.network.saved') }}
    </p>
    <p
      v-if="logs.settings?.restart_required"
      class="pw-note flex items-start gap-2"
      data-tone="warning"
      role="status"
    >
      <TriangleAlert class="text-warning mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{{ t('settings.network.restart') }}</span>
    </p>
    <p v-if="logs.settingsError" class="text-danger text-sm" role="alert">
      {{ logs.settingsError }}
    </p>
  </SettingRow>
</template>

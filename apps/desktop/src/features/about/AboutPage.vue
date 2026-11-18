<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { ExternalLink } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import pkg from '../../../package.json'
import { openExternal, XEROHOST_URL } from '@/api/links'
import BrandLogo from '@/components/pw/BrandLogo.vue'
import { Button } from '@/components/ui/button'

const { t } = useI18n()
</script>

<template>
  <section
    class="bg-surface border-border flex max-w-xl flex-col gap-4 rounded-lg border p-[var(--card-p)]"
    style="box-shadow: var(--shadow-card)"
  >
    <BrandLogo height-class="h-12" />
    <h2 class="text-lg">{{ t('about.title') }}</h2>
    <p class="text-text-muted">{{ t('about.tagline') }}</p>

    <dl class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5">
      <dt class="text-text-muted">{{ t('about.version') }}</dt>
      <dd class="font-mono">{{ pkg.version }}</dd>
      <dt class="text-text-muted">{{ t('about.license') }}</dt>
      <dd class="font-mono">{{ t('about.licenseValue') }}</dd>
    </dl>

    <p class="text-text-muted">{{ t('about.madeBy') }}</p>

    <div>
      <Button variant="outline" size="sm" @click="openExternal(XEROHOST_URL)">
        <ExternalLink aria-hidden="true" />
        {{ t('app.contactSupport') }}
      </Button>
    </div>
  </section>
</template>

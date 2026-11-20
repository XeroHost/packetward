<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import pkg from '../../../package.json'
import { openExternal, XEROHOST_URL } from '@/api/links'
import { ExternalLink } from '@/components/pw/icons'
import BrandLogo from '@/components/pw/BrandLogo.vue'
import { Button } from '@/components/ui/button'

const { t } = useI18n()
</script>

<template>
  <section class="grid max-w-[60rem] gap-x-14 gap-y-10 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
    <div class="flex flex-col gap-5">
      <BrandLogo height-class="h-14" />
      <h2 class="text-xl font-semibold">{{ t('about.title') }}</h2>
      <p class="text-text-muted max-w-prose leading-relaxed">{{ t('about.tagline') }}</p>

      <dl class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
        <dt class="text-text-muted">{{ t('about.version') }}</dt>
        <dd class="font-mono">{{ pkg.version }}</dd>
        <dt class="text-text-muted">{{ t('about.license') }}</dt>
        <dd class="font-mono">{{ t('about.licenseValue') }}</dd>
      </dl>

      <p class="text-text-muted text-sm">{{ t('about.madeBy') }}</p>

      <div>
        <Button variant="outline" size="sm" @click="openExternal(XEROHOST_URL)">
          <ExternalLink aria-hidden="true" />
          {{ t('app.contactSupport') }}
        </Button>
      </div>
    </div>

    <div class="border-hairline flex flex-col gap-2 text-[13px] md:border-l md:pl-14">
      <h3 class="text-[0.9375rem] font-semibold">{{ t('about.credits.title') }}</h3>
      <p class="text-text-muted leading-relaxed">{{ t('about.credits.geoip') }}</p>
      <p class="text-text-muted leading-relaxed">{{ t('about.credits.motion') }}</p>
      <p class="text-text-muted leading-relaxed">{{ t('about.credits.icons') }}</p>
      <p class="text-text-muted leading-relaxed">{{ t('about.credits.maps') }}</p>
      <p class="text-text-muted leading-relaxed">{{ t('about.credits.fonts') }}</p>
      <p class="text-text-muted leading-relaxed">{{ t('about.credits.ui') }}</p>
      <p class="text-text-muted mt-2 text-xs leading-relaxed">{{ t('about.credits.note') }}</p>
    </div>
  </section>
</template>

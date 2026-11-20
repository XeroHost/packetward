<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { Hourglass } from '@/components/pw/icons'

const { t } = useI18n()
</script>

<template>
  <section class="flex max-w-xl flex-col items-start gap-3">
    <Hourglass class="text-text-muted size-5" aria-hidden="true" />
    <h2 class="text-[1.0625rem] font-semibold">{{ t('placeholder.title') }}</h2>
    <p class="text-text-muted">{{ t('placeholder.description') }}</p>
  </section>
</template>

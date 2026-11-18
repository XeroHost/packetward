<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { Hourglass } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
</script>

<template>
  <section
    class="bg-surface border-border flex max-w-xl flex-col items-start gap-3 rounded-lg border p-[var(--card-p)]"
    style="box-shadow: var(--shadow-card)"
  >
    <Hourglass class="text-text-muted size-5" aria-hidden="true" />
    <h2 class="text-base">{{ t('placeholder.title') }}</h2>
    <p class="text-text-muted">{{ t('placeholder.description') }}</p>
  </section>
</template>

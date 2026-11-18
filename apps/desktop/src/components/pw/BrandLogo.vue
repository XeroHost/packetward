<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// Official branding-kit logo, unmodified: the dark variant has light text for dark backgrounds.
import { useI18n } from 'vue-i18n'
import logoDark from '@/assets/brand/logo-dark.svg'
import logoLight from '@/assets/brand/logo-light.svg'
import { useAppearanceStore } from '@/stores/appearance'

defineProps<{ heightClass?: string }>()

const { t } = useI18n()
const appearance = useAppearanceStore()
</script>

<template>
  <img
    :src="appearance.resolvedTheme === 'dark' ? logoDark : logoLight"
    :alt="t('app.name')"
    :class="heightClass ?? 'h-8'"
    class="w-auto select-none"
    draggable="false"
  />
</template>

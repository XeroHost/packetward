<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
// A global banner: an AI client (through the MCP server) is asking for something that needs the
// owner's decision. It sits above every page, next to the RDP confirmation banner.
import { Wrench } from '@/components/pw/icons'
import { onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button } from '@/components/ui/button'
import { useMcpStore } from '@/stores/mcp'

const { t } = useI18n()
const mcp = useMcpStore()

onMounted(() => mcp.start())
onUnmounted(() => mcp.stop())
</script>

<template>
  <div
    v-if="mcp.count > 0"
    class="pw-note pw-appear mx-9 mt-5 flex-wrap items-center"
    data-tone="info"
    role="alert"
    data-testid="mcp-banner"
  >
    <Wrench class="text-info size-4 shrink-0" aria-hidden="true" />
    <span class="min-w-0 flex-1">
      <strong>{{ t('mcp.approval.banner') }}</strong>
      {{ t('mcp.approval.bannerCount', { count: mcp.count }) }}
    </span>
    <Button size="sm" @click="mcp.openDialog()">{{ t('mcp.approval.open') }}</Button>
  </div>
</template>

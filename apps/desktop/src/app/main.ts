// SPDX-License-Identifier: GPL-3.0-or-later
import { createPinia } from 'pinia'
import { createApp } from 'vue'
import '@/styles/main.css'
import { startWindowVisibility } from '@/lib/visibility'
import { useAgentStore } from '@/stores/agent'
import { useSettingsStore } from '@/stores/settings'
import App from './App.vue'
import { i18n } from './i18n'
import { router } from './router'

async function bootstrap(): Promise<void> {
  const app = createApp(App)
  const pinia = createPinia()
  app.use(pinia).use(i18n).use(router)

  // Load saved preferences first so the first paint already has the right theme and language.
  await useSettingsStore(pinia).init()

  app.mount('#app')

  void startWindowVisibility()

  // Follow the agent for the whole life of the window; the shell reconnects on its own.
  useAgentStore(pinia).start()
}

void bootstrap()

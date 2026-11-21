// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { defineStore } from 'pinia'
import { ref } from 'vue'

/** Which address the detail drawer shows (null = closed). Any IP in the app opens it from here. */
export const useIpDetailStore = defineStore('ipDetail', () => {
  const addr = ref<string | null>(null)

  function open(value: string): void {
    // A CIDR is not one address: the drawer is about a single host.
    if (value === '' || value.includes('/')) return
    addr.value = value
  }

  function close(): void {
    addr.value = null
  }

  return { addr, open, close }
})

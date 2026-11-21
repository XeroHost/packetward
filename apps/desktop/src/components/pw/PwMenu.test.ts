// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import PwMenu from './PwMenu.vue'

const ITEMS = [
  { key: 'save-csv', label: 'Save as CSV' },
  { key: 'copy-json', label: 'Copy as JSON' },
]

afterEach(() => {
  document.body.innerHTML = ''
})

function menu(disabled = false) {
  return mount(PwMenu, {
    attachTo: document.body,
    props: { items: ITEMS, disabled },
    slots: { default: '<button type="button">Export</button>' },
  })
}

describe('PwMenu', () => {
  it('opens in the page body (portaled, so no parent can clip or hide it) and reports the chosen key', async () => {
    const wrapper = menu()
    const trigger = wrapper.find('button')
    trigger.element.focus()
    await trigger.trigger('keydown', { key: 'Enter' })
    await flushPromises()
    const items = [...document.body.querySelectorAll<HTMLElement>('[role="menuitem"]')]
    expect(items.map((i) => i.textContent?.trim())).toEqual(['Save as CSV', 'Copy as JSON'])
    // Not inside the component's own element: that is what keeps it from opening behind the sidebar.
    expect(wrapper.element.contains(items[0] as HTMLElement)).toBe(false)
    items[1]?.click()
    await flushPromises()
    expect(wrapper.emitted('select')).toEqual([['copy-json']])
  })

  it('does not open while disabled', async () => {
    const wrapper = menu(true)
    await wrapper.find('button').trigger('keydown', { key: 'Enter' })
    await flushPromises()
    expect(document.body.querySelector('[role="menuitem"]')).toBeNull()
  })
})

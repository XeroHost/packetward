// SPDX-License-Identifier: GPL-3.0-or-later
import { mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Notification01Icon } from '@/lib/icons'
import { panelTransition } from '@/lib/motion'
import CountingValue from './CountingValue.vue'
import HIcon from './HIcon.vue'
import SegmentedControl from './SegmentedControl.vue'
import TabBar from './TabBar.vue'

afterEach(() => {
  delete document.documentElement.dataset.motion
  vi.useRealTimers()
})

describe('HIcon', () => {
  it('draws the Hugeicons data as an svg with real SVG attribute names', () => {
    const wrapper = mount(HIcon, { props: { icon: Notification01Icon, size: 20 } })
    const svg = wrapper.get('svg')
    expect(svg.attributes('width')).toBe('20')
    const paths = svg.findAll('path')
    expect(paths.length).toBeGreaterThan(0)
    // camelCase React props become kebab-case attributes, and the stroke weight is ours.
    expect(paths[0]?.attributes('stroke-linecap')).toBe('round')
    expect(paths[0]?.attributes('strokeLinecap')).toBeUndefined()
    expect(paths[0]?.attributes('stroke-width')).toBe('1.5')
    expect(paths[0]?.attributes('pathLength')).toBe('1')
  })

  it('replays its drawing animation when `play` changes', async () => {
    const wrapper = mount(HIcon, { props: { icon: Notification01Icon, play: 0 } })
    expect(wrapper.find('g').classes()).not.toContain('hi-draw')
    await wrapper.setProps({ play: 1 })
    expect(wrapper.find('g').classes()).toContain('hi-draw')
  })
})

describe('CountingValue', () => {
  const fmt = (n: number): string => `${Math.round(n)} Mbps`

  it('shows the first value as it is, with no count-up from zero', () => {
    const wrapper = mount(CountingValue, { props: { value: 42, format: fmt } })
    expect(wrapper.text()).toBe('42 Mbps')
  })

  it('jumps straight to the new value under "Reduce animations"', async () => {
    document.documentElement.dataset.motion = 'reduced'
    const wrapper = mount(CountingValue, { props: { value: 10, format: fmt } })
    await wrapper.setProps({ value: 99 })
    expect(wrapper.text()).toBe('99 Mbps')
  })

  it('splits the unit when asked to', () => {
    const wrapper = mount(CountingValue, {
      props: { value: 5, format: fmt, unitClass: 'unit' },
    })
    expect(wrapper.get('.unit').text()).toBe('Mbps')
    expect(wrapper.text()).toBe('5 Mbps')
  })
})

describe('SegmentedControl', () => {
  const options = [
    { value: 'a', label: 'Alpha' },
    { value: 'b', label: 'Beta' },
    { value: 'c', label: 'Gamma' },
  ] as const

  it('is a radio group whose arrow keys move the choice and wrap around', async () => {
    const wrapper = mount(SegmentedControl, {
      props: {
        options,
        label: 'Letters',
        modelValue: 'a',
        'onUpdate:modelValue': (v: unknown) => wrapper.setProps({ modelValue: v as string }),
      },
    })
    expect(wrapper.attributes('role')).toBe('radiogroup')
    const radios = wrapper.findAll('[role="radio"]')
    expect(radios.map((r) => r.attributes('aria-checked'))).toEqual(['true', 'false', 'false'])
    await radios[0]?.trigger('keydown.right')
    expect(wrapper.findAll('[role="radio"]')[1]?.attributes('aria-checked')).toBe('true')
    await wrapper.findAll('[role="radio"]')[1]?.trigger('keydown.left')
    await wrapper.findAll('[role="radio"]')[0]?.trigger('keydown.left')
    expect(wrapper.findAll('[role="radio"]')[2]?.attributes('aria-checked')).toBe('true')
  })
})

describe('TabBar', () => {
  it('labels each tab for its panel and moves with the arrow keys', async () => {
    const wrapper = mount(TabBar, {
      attachTo: document.body,
      props: {
        tabs: [
          { id: 'one', label: 'One' },
          { id: 'two', label: 'Two' },
        ],
        label: 'Things',
        idPrefix: 'x',
        modelValue: 'one',
        'onUpdate:modelValue': (v: unknown) => wrapper.setProps({ modelValue: v as string }),
      },
    })
    const tabs = wrapper.findAll('[role="tab"]')
    expect(tabs[0]?.attributes('id')).toBe('x-tab-one')
    expect(tabs[0]?.attributes('aria-controls')).toBe('x-panel')
    expect(tabs[1]?.attributes('tabindex')).toBe('-1')
    await tabs[0]?.trigger('keydown.right')
    expect(wrapper.findAll('[role="tab"]')[1]?.attributes('aria-selected')).toBe('true')
    wrapper.unmount()
  })
})

describe('panelTransition', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  it('always finishes, even when no animation frame ever comes', () => {
    const el = document.createElement('div')
    const entered = vi.fn()
    const left = vi.fn()
    panelTransition.beforeEnter(el)
    expect(el.style.opacity).toBe('0')
    panelTransition.enter(el, entered)
    panelTransition.leave(el, left)
    vi.advanceTimersByTime(1000)
    expect(entered).toHaveBeenCalledTimes(1)
    expect(left).toHaveBeenCalledTimes(1)
    // The entering page ends visible and in place whatever the animation did.
    expect(el.style.opacity).toBe('')
    expect(el.style.transform).toBe('')
  })

  it('does not animate at all under "Reduce animations"', () => {
    document.documentElement.dataset.motion = 'reduced'
    const el = document.createElement('div')
    const done = vi.fn()
    panelTransition.beforeEnter(el)
    expect(el.style.opacity).toBe('')
    panelTransition.enter(el, done)
    expect(done).toHaveBeenCalledTimes(1)
  })
})

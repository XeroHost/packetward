// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import { formatUptime } from './format'

describe('formatUptime', () => {
  it.each([
    [0, '0s'],
    [59, '59s'],
    [60, '1m 0s'],
    [65, '1m 5s'],
    [3600, '1h 0m 0s'],
    [3725, '1h 2m 5s'],
    [86400, '1d 0h 0m 0s'],
    [93784, '1d 2h 3m 4s'],
  ])('%i seconds -> %s', (seconds, expected) => {
    expect(formatUptime(seconds)).toBe(expected)
  })

  it('never goes negative or fractional', () => {
    expect(formatUptime(-5)).toBe('0s')
    expect(formatUptime(9.9)).toBe('9s')
  })
})

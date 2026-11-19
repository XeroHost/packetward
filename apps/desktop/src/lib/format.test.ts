// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import { formatBitrate, formatRate, formatUptime } from './format'

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

describe('formatBitrate', () => {
  it.each([
    [0, '0 bps'],
    [999, '999 bps'],
    [1000, '1.00 Kbps'],
    [12_345, '12.3 Kbps'],
    [1_500_000, '1.50 Mbps'],
    [123_456_789, '123 Mbps'],
    [10_000_000_000, '10.0 Gbps'],
    [2_500_000_000_000, '2.50 Tbps'],
  ])('%d bps -> %s', (bps, expected) => {
    expect(formatBitrate(bps)).toBe(expected)
  })

  it('treats negative and non-finite values as zero', () => {
    expect(formatBitrate(-5)).toBe('0 bps')
    expect(formatBitrate(Number.NaN)).toBe('0 bps')
    expect(formatBitrate(Number.POSITIVE_INFINITY)).toBe('0 bps')
  })
})

describe('formatRate', () => {
  it.each([
    [0, '0'],
    [950, '950'],
    [12_400, '12.4 K'],
    [2_000_000, '2.00 M'],
  ])('%d/s -> %s', (value, expected) => {
    expect(formatRate(value)).toBe(expected)
  })
})

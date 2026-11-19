// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import type { MtrHopView } from '@/types/generated/MtrHopView'
import { formatLoss, formatMs, isIcmpRateLimited, lossLevel, portScope } from './diagFormat'

const hop = (ttl: number, loss: number, received = 10): MtrHopView => ({
  ttl,
  other_addrs: [],
  sent: 10,
  received,
  loss_percent: loss,
  address_changes: 0,
})

describe('formatting', () => {
  it('shows milliseconds with sensible precision and a dash for no data', () => {
    expect(formatMs(0.424)).toBe('0.42 ms')
    expect(formatMs(12.345)).toBe('12.3 ms')
    expect(formatMs(250.4)).toBe('250 ms')
    expect(formatMs(undefined)).toBe('—')
    expect(formatMs(Number.NaN)).toBe('—')
  })

  it('shows loss as a percentage', () => {
    expect(formatLoss(0)).toBe('0%')
    expect(formatLoss(3.33)).toBe('3.3%')
    expect(formatLoss(50)).toBe('50%')
    expect(formatLoss(-1)).toBe('0%')
  })

  it('grades loss', () => {
    expect(lossLevel(0)).toBe('ok')
    expect(lossLevel(5)).toBe('warn')
    expect(lossLevel(20)).toBe('bad')
  })
})

describe('ICMP rate limiting', () => {
  it('flags a lossy hop followed by clean ones', () => {
    const hops = [hop(1, 0), hop(2, 60), hop(3, 0), hop(4, 0)]
    expect(isIcmpRateLimited(hops, 1)).toBe(true)
  })

  it('does not flag loss that continues to the destination', () => {
    const hops = [hop(1, 0), hop(2, 40), hop(3, 35), hop(4, 38)]
    expect(isIcmpRateLimited(hops, 1)).toBe(false)
  })

  it('does not flag the last hop or a clean hop', () => {
    const hops = [hop(1, 0), hop(2, 50)]
    expect(isIcmpRateLimited(hops, 1)).toBe(false)
    expect(isIcmpRateLimited(hops, 0)).toBe(false)
  })

  it('ignores later hops that never answered', () => {
    const hops = [hop(1, 50), hop(2, 100, 0), hop(3, 0)]
    expect(isIcmpRateLimited(hops, 0)).toBe(true)
  })
})

describe('port scope', () => {
  it('tells all-interfaces from local-only', () => {
    expect(portScope('0.0.0.0')).toBe('all')
    expect(portScope('::')).toBe('all')
    expect(portScope('127.0.0.1')).toBe('local')
    expect(portScope('::1')).toBe('local')
    expect(portScope('10.0.0.5')).toBe('specific')
  })
})

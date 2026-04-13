import { describe, it, expect } from 'vitest'
import { cn, formatNumber, formatDuration, timeAgo } from './utils'

describe('cn', () => {
  it('merges class names', () => {
    expect(cn('foo', 'bar')).toBe('foo bar')
  })

  it('handles conditional classes', () => {
    expect(cn('base', false && 'hidden', 'active')).toBe('base active')
  })

  it('deduplicates tailwind classes', () => {
    expect(cn('px-2', 'px-4')).toBe('px-4')
  })
})

describe('formatNumber', () => {
  it('formats millions', () => {
    expect(formatNumber(1_500_000)).toBe('1.5M')
  })

  it('formats thousands', () => {
    expect(formatNumber(2_500)).toBe('2.5K')
  })

  it('formats small numbers as-is', () => {
    expect(formatNumber(42)).toBe('42')
  })

  it('formats zero', () => {
    expect(formatNumber(0)).toBe('0')
  })

  it('formats exact million', () => {
    expect(formatNumber(1_000_000)).toBe('1.0M')
  })

  it('formats exact thousand', () => {
    expect(formatNumber(1_000)).toBe('1.0K')
  })
})

describe('formatDuration', () => {
  it('formats seconds', () => {
    expect(formatDuration(1_500_000)).toBe('1.5s')
  })

  it('formats milliseconds', () => {
    expect(formatDuration(2_500)).toBe('2.5ms')
  })

  it('formats microseconds', () => {
    expect(formatDuration(500)).toBe('500us')
  })

  it('formats zero', () => {
    expect(formatDuration(0)).toBe('0us')
  })
})

describe('timeAgo', () => {
  it('returns "just now" for recent timestamps', () => {
    const now = new Date().toISOString()
    expect(timeAgo(now)).toBe('just now')
  })

  it('returns seconds ago', () => {
    const ts = new Date(Date.now() - 30_000).toISOString()
    expect(timeAgo(ts)).toBe('30s ago')
  })

  it('returns minutes ago', () => {
    const ts = new Date(Date.now() - 180_000).toISOString()
    expect(timeAgo(ts)).toBe('3m ago')
  })

  it('returns hours ago', () => {
    const ts = new Date(Date.now() - 7_200_000).toISOString()
    expect(timeAgo(ts)).toBe('2h ago')
  })

  it('returns days ago', () => {
    const ts = new Date(Date.now() - 172_800_000).toISOString()
    expect(timeAgo(ts)).toBe('2d ago')
  })
})

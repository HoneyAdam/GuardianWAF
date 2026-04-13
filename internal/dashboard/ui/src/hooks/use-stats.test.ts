import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useStats } from './use-stats'

describe('useStats', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  const mockStats = {
    total_requests: 100,
    blocked_requests: 10,
    challenged_requests: 5,
    logged_requests: 20,
    passed_requests: 65,
    avg_latency_us: 500,
  }

  it('starts with loading=true', () => {
    vi.mocked(fetch).mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useStats())
    expect(result.current.loading).toBe(true)
  })

  it('fetches stats and sets loading=false', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockStats),
    } as Response)

    const { result } = renderHook(() => useStats())

    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })

    expect(result.current.loading).toBe(false)
    expect(result.current.stats).toEqual(mockStats)
  })

  it('polls every 5 seconds', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockStats),
    } as Response)

    renderHook(() => useStats())

    // Wait for initial fetch to resolve
    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })
    const afterInitial = vi.mocked(fetch).mock.calls.length
    expect(afterInitial).toBeGreaterThanOrEqual(1)

    // Advance past 5s — should trigger another fetch
    await act(async () => {
      vi.advanceTimersByTime(5_000)
      await vi.runOnlyPendingTimersAsync()
    })
    expect(vi.mocked(fetch).mock.calls.length).toBeGreaterThan(afterInitial)

    // Advance another 5s — yet another fetch
    const afterFirst = vi.mocked(fetch).mock.calls.length
    await act(async () => {
      vi.advanceTimersByTime(5_000)
      await vi.runOnlyPendingTimersAsync()
    })
    expect(vi.mocked(fetch).mock.calls.length).toBeGreaterThan(afterFirst)
  })

  it('keeps previous stats on fetch error', async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockStats),
      } as Response)
      .mockRejectedValueOnce(new Error('network error'))

    const { result } = renderHook(() => useStats())

    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })
    expect(result.current.stats).toEqual(mockStats)

    await act(async () => {
      vi.advanceTimersByTime(5_000)
      await vi.runOnlyPendingTimersAsync()
    })

    // Stats should still be the old data
    expect(result.current.stats).toEqual(mockStats)
    expect(result.current.loading).toBe(false)
  })

  it('cleans up interval on unmount', () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockStats),
    } as Response)

    const { unmount } = renderHook(() => useStats())
    unmount()

    const count = vi.mocked(fetch).mock.calls.length
    vi.advanceTimersByTime(10_000)

    // No more fetches after unmount
    expect(vi.mocked(fetch).mock.calls.length).toBe(count)
  })
})

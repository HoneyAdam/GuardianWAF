import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useTheme } from './use-theme'

describe('useTheme', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('defaults to dark theme', () => {
    const { result } = renderHook(() => useTheme())
    expect(result.current.theme).toBe('dark')
  })

  it('reads saved theme from localStorage', () => {
    localStorage.setItem('gwaf-theme', 'light')
    const { result } = renderHook(() => useTheme())
    expect(result.current.theme).toBe('light')
  })

  it('toggles from dark to light', () => {
    const { result } = renderHook(() => useTheme())
    expect(result.current.theme).toBe('dark')

    act(() => {
      result.current.toggle()
    })

    expect(result.current.theme).toBe('light')
    expect(localStorage.getItem('gwaf-theme')).toBe('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('toggles from light to dark', () => {
    localStorage.setItem('gwaf-theme', 'light')
    const { result } = renderHook(() => useTheme())

    act(() => {
      result.current.toggle()
    })

    expect(result.current.theme).toBe('dark')
    expect(localStorage.getItem('gwaf-theme')).toBe('dark')
  })
})

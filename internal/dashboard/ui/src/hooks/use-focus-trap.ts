import { useEffect, useRef } from 'react'

/**
 * Traps keyboard focus within a container element (Tab / Shift+Tab cycle).
 * Pressing Escape calls `onEscape`.
 */
export function useFocusTrap(onEscape?: () => void) {
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    const focusableSelector =
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

    // Move focus into the container on mount
    const initiallyFocused = container.querySelector<HTMLElement>(focusableSelector)
    if (initiallyFocused) {
      initiallyFocused.focus()
    } else {
      container.focus()
    }

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault()
        onEscape?.()
        return
      }

      if (e.key !== 'Tab') return

      const el = containerRef.current
      if (!el) return

      const focusables = el.querySelectorAll<HTMLElement>(focusableSelector)
      if (focusables.length === 0) {
        e.preventDefault()
        return
      }

      const first = focusables[0]
      const last = focusables[focusables.length - 1]

      if (e.shiftKey) {
        if (document.activeElement === first || !el.contains(document.activeElement)) {
          e.preventDefault()
          last.focus()
        }
      } else {
        if (document.activeElement === last || !el.contains(document.activeElement)) {
          e.preventDefault()
          first.focus()
        }
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [onEscape])

  return containerRef
}

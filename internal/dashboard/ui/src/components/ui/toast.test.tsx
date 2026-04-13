import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider, useToast } from './toast'

function ToastConsumer({ title, description, variant }: {
  title?: string
  description?: string
  variant?: 'default' | 'success' | 'warning' | 'destructive'
}) {
  const { toast } = useToast()
  return (
    <button
      onClick={() => toast({ title, description, variant })}
    >
      Show Toast
    </button>
  )
}

describe('Toast', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('shows toast on toast() call', async () => {
    render(
      <ToastProvider>
        <ToastConsumer title="Test Toast" description="Hello world" />
      </ToastProvider>,
    )

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    await user.click(screen.getByText('Show Toast'))

    expect(screen.getByText('Test Toast')).toBeInTheDocument()
    expect(screen.getByText('Hello world')).toBeInTheDocument()
  })

  it('dismisses toast on close button click', async () => {
    render(
      <ToastProvider>
        <ToastConsumer title="Dismissible" />
      </ToastProvider>,
    )

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    await user.click(screen.getByText('Show Toast'))

    expect(screen.getByText('Dismissible')).toBeInTheDocument()

    // Click the dismiss button (X svg button)
    const dismissBtn = screen.getByRole('alert').querySelector('button')!
    await user.click(dismissBtn)

    expect(screen.queryByText('Dismissible')).not.toBeInTheDocument()
  })

  it('auto-dismisses after duration', async () => {
    render(
      <ToastProvider>
        <ToastConsumer title="Auto-dismiss" />
      </ToastProvider>,
    )

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    await user.click(screen.getByText('Show Toast'))

    expect(screen.getByText('Auto-dismiss')).toBeInTheDocument()

    act(() => {
      vi.advanceTimersByTime(5_000)
    })

    expect(screen.queryByText('Auto-dismiss')).not.toBeInTheDocument()
  })

  it('throws when useToast is used outside provider', () => {
    // Suppress console.error for expected error
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})

    expect(() => render(<ToastConsumer title="Oops" />)).toThrow(
      'useToast must be used within a ToastProvider',
    )

    spy.mockRestore()
  })

  it('renders with success variant', async () => {
    render(
      <ToastProvider>
        <ToastConsumer title="Success!" variant="success" />
      </ToastProvider>,
    )

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    await user.click(screen.getByText('Show Toast'))

    const alert = screen.getByRole('alert')
    expect(alert.className).toContain('text-success')
  })

  it('renders with destructive variant', async () => {
    render(
      <ToastProvider>
        <ToastConsumer title="Error!" variant="destructive" />
      </ToastProvider>,
    )

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    await user.click(screen.getByText('Show Toast'))

    const alert = screen.getByRole('alert')
    expect(alert.className).toContain('text-destructive')
  })
})

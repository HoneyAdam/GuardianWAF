import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Switch } from './switch'

describe('Switch', () => {
  it('renders with role="switch"', () => {
    render(<Switch />)
    expect(screen.getByRole('switch')).toBeInTheDocument()
  })

  it('defaults to unchecked', () => {
    render(<Switch />)
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'false')
  })

  it('renders checked state', () => {
    render(<Switch checked />)
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'true')
  })

  it('toggles on click', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<Switch checked={false} onCheckedChange={onChange} />)

    await user.click(screen.getByRole('switch'))
    expect(onChange).toHaveBeenCalledWith(true)
  })

  it('toggles from checked to unchecked', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<Switch checked onCheckedChange={onChange} />)

    await user.click(screen.getByRole('switch'))
    expect(onChange).toHaveBeenCalledWith(false)
  })

  it('is disabled when disabled prop is set', () => {
    render(<Switch disabled />)
    expect(screen.getByRole('switch')).toBeDisabled()
  })

  it('has displayName', () => {
    expect(Switch.displayName).toBe('Switch')
  })
})

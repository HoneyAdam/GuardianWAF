import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Input } from './input'

describe('Input', () => {
  it('renders an input element', () => {
    render(<Input placeholder="Enter text" />)
    expect(screen.getByPlaceholderText('Enter text')).toBeInTheDocument()
  })

  it('accepts text input', async () => {
    const user = userEvent.setup()
    render(<Input placeholder="Type here" />)

    const input = screen.getByPlaceholderText('Type here')
    await user.type(input, 'hello')
    expect(input).toHaveValue('hello')
  })

  it('is disabled when disabled prop is set', () => {
    render(<Input disabled placeholder="Disabled input" />)
    expect(screen.getByPlaceholderText('Disabled input')).toBeDisabled()
  })

  it('applies custom className', () => {
    render(<Input className="my-input" placeholder="Test" />)
    expect(screen.getByPlaceholderText('Test').className).toContain('my-input')
  })

  it('renders with type attribute', () => {
    render(<Input type="password" placeholder="Password" />)
    expect(screen.getByPlaceholderText('Password')).toHaveAttribute('type', 'password')
  })

  it('has displayName', () => {
    expect(Input.displayName).toBe('Input')
  })
})

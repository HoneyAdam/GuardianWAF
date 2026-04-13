import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Select, SelectOption } from './select'

describe('Select', () => {
  const options = (
    <>
      <SelectOption value="a">Option A</SelectOption>
      <SelectOption value="b">Option B</SelectOption>
    </>
  )

  it('renders a select with options', () => {
    render(<Select>{options}</Select>)
    const select = screen.getByRole('combobox')
    expect(select).toBeInTheDocument()
    expect(screen.getByText('Option A')).toBeInTheDocument()
    expect(screen.getByText('Option B')).toBeInTheDocument()
  })

  it('selects an option', async () => {
    const user = userEvent.setup()
    render(<Select>{options}</Select>)

    await user.selectOptions(screen.getByRole('combobox'), 'b')
    expect(screen.getByRole('combobox')).toHaveValue('b')
  })

  it('is disabled when disabled prop is set', () => {
    render(<Select disabled>{options}</Select>)
    expect(screen.getByRole('combobox')).toBeDisabled()
  })

  it('applies custom className', () => {
    render(<Select className="custom-select">{options}</Select>)
    expect(screen.getByRole('combobox').className).toContain('custom-select')
  })

  it('Select has displayName', () => {
    expect(Select.displayName).toBe('Select')
  })
})

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Badge } from './badge'

describe('Badge', () => {
  it('renders children', () => {
    render(<Badge>Status</Badge>)
    expect(screen.getByText('Status')).toBeInTheDocument()
  })

  it('renders with default variant', () => {
    render(<Badge>Default</Badge>)
    const el = screen.getByText('Default')
    expect(el.className).toContain('bg-accent')
  })

  it('renders with success variant', () => {
    render(<Badge variant="success">OK</Badge>)
    expect(screen.getByText('OK').className).toContain('text-success')
  })

  it('renders with warning variant', () => {
    render(<Badge variant="warning">Warn</Badge>)
    expect(screen.getByText('Warn').className).toContain('text-warning')
  })

  it('renders with destructive variant', () => {
    render(<Badge variant="destructive">Error</Badge>)
    expect(screen.getByText('Error').className).toContain('text-destructive')
  })

  it('renders with outline variant', () => {
    render(<Badge variant="outline">Outlined</Badge>)
    expect(screen.getByText('Outlined').className).toContain('border-border')
  })

  it('applies custom className', () => {
    render(<Badge className="extra">Custom</Badge>)
    expect(screen.getByText('Custom').className).toContain('extra')
  })

  it('has displayName', () => {
    expect(Badge.displayName).toBe('Badge')
  })
})

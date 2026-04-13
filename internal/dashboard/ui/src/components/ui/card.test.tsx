import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from './card'

describe('Card', () => {
  it('renders children', () => {
    render(<Card>Card content</Card>)
    expect(screen.getByText('Card content')).toBeInTheDocument()
  })

  it('applies custom className', () => {
    render(<Card className="test-class">Content</Card>)
    expect(screen.getByText('Content').className).toContain('test-class')
  })

  it('composes header + title + description + content + footer', () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Title</CardTitle>
          <CardDescription>Description</CardDescription>
        </CardHeader>
        <CardContent>Body</CardContent>
        <CardFooter>Footer</CardFooter>
      </Card>,
    )

    expect(screen.getByText('Title')).toBeInTheDocument()
    expect(screen.getByText('Description')).toBeInTheDocument()
    expect(screen.getByText('Body')).toBeInTheDocument()
    expect(screen.getByText('Footer')).toBeInTheDocument()
  })

  it('has displayName for all sub-components', () => {
    expect(Card.displayName).toBe('Card')
    expect(CardHeader.displayName).toBe('CardHeader')
    expect(CardTitle.displayName).toBe('CardTitle')
    expect(CardDescription.displayName).toBe('CardDescription')
    expect(CardContent.displayName).toBe('CardContent')
    expect(CardFooter.displayName).toBe('CardFooter')
  })

  it('forwards ref', () => {
    const ref = vi.fn()
    render(<Card ref={ref}>Ref test</Card>)
    expect(ref).toHaveBeenCalled()
  })
})

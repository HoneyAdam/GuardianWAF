import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from './table'

describe('Table', () => {
  it('renders a table with headers and cells', () => {
    render(
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Value</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow>
            <TableCell>Test</TableCell>
            <TableCell>42</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    )

    expect(screen.getByText('Name')).toBeInTheDocument()
    expect(screen.getByText('Value')).toBeInTheDocument()
    expect(screen.getByText('Test')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('renders the table element', () => {
    render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell>Data</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    )

    expect(screen.getByRole('table')).toBeInTheDocument()
  })

  it('has displayName for all sub-components', () => {
    expect(Table.displayName).toBe('Table')
    expect(TableHeader.displayName).toBe('TableHeader')
    expect(TableBody.displayName).toBe('TableBody')
    expect(TableRow.displayName).toBe('TableRow')
    expect(TableHead.displayName).toBe('TableHead')
    expect(TableCell.displayName).toBe('TableCell')
  })
})

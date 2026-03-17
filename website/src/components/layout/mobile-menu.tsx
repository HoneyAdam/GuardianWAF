import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Menu, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ThemeToggle } from './theme-toggle'

const links = [
  { href: '/#features', label: 'Features' },
  { href: '/#architecture', label: 'Architecture' },
  { href: '/#quick-start', label: 'Quick Start' },
  { href: '/docs', label: 'Docs' },
]

export function MobileMenu() {
  const [open, setOpen] = useState(false)

  return (
    <div className="md:hidden">
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setOpen(!open)}
        aria-label={open ? 'Close menu' : 'Open menu'}
        aria-expanded={open}
      >
        {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
      </Button>

      {open && (
        <div className="absolute top-full left-0 right-0 bg-background border-b border-border z-50">
          <nav className="flex flex-col p-4 gap-1" aria-label="Mobile navigation">
            {links.map((link) => (
              <Link
                key={link.href}
                to={link.href}
                className="px-4 py-3 text-sm font-medium text-muted hover:text-foreground hover:bg-card rounded-lg transition-colors"
                onClick={() => setOpen(false)}
              >
                {link.label}
              </Link>
            ))}
            <div className="flex items-center justify-between px-4 py-3 border-t border-border mt-2 pt-4">
              <span className="text-sm text-muted">Theme</span>
              <ThemeToggle />
            </div>
            <a
              href="https://github.com/GuardianWAF/GuardianWAF"
              target="_blank"
              rel="noopener noreferrer"
              className="px-4 py-3 text-sm font-medium text-accent hover:text-accent/80 transition-colors"
              onClick={() => setOpen(false)}
            >
              GitHub
            </a>
          </nav>
        </div>
      )}
    </div>
  )
}

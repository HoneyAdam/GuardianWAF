import { Link, useLocation } from 'react-router-dom'
import { Shield, Github } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ThemeToggle } from './theme-toggle'
import { MobileMenu } from './mobile-menu'
import { cn } from '@/lib/utils'

const links = [
  { href: '/#features', label: 'Features' },
  { href: '/#architecture', label: 'Architecture' },
  { href: '/#quick-start', label: 'Quick Start' },
  { href: '/docs', label: 'Docs' },
]

export function Navbar() {
  const location = useLocation()

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border bg-background/80 backdrop-blur-lg supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto max-w-7xl flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
        <Link
          to="/"
          className="flex items-center gap-2 font-semibold text-foreground hover:text-accent transition-colors"
          aria-label="GuardianWAF Home"
        >
          <Shield className="h-6 w-6 text-accent" />
          <span className="text-lg">GuardianWAF</span>
        </Link>

        <nav className="hidden md:flex items-center gap-1" aria-label="Main navigation">
          {links.map((link) => (
            <Link
              key={link.href}
              to={link.href}
              className={cn(
                'px-3 py-2 text-sm font-medium rounded-md transition-colors',
                location.pathname + location.hash === link.href
                  ? 'text-accent'
                  : 'text-muted hover:text-foreground'
              )}
            >
              {link.label}
            </Link>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <div className="hidden md:block">
            <ThemeToggle />
          </div>
          <a
            href="https://github.com/GuardianWAF/GuardianWAF"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden md:block"
          >
            <Button variant="outline" size="sm" className="gap-2">
              <Github className="h-4 w-4" />
              GitHub
            </Button>
          </a>
          <MobileMenu />
        </div>
      </div>
    </header>
  )
}

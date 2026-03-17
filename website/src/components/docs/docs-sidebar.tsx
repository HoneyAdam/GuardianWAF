import { cn } from '@/lib/utils'
import { docSections } from '@/content/docs'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { useState } from 'react'

interface DocsSidebarProps {
  activeSection: string
  onSectionClick: (id: string) => void
  className?: string
}

export function DocsSidebar({ activeSection, onSectionClick, className }: DocsSidebarProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {}
    docSections.forEach((s) => {
      initial[s.id] = true
    })
    return initial
  })

  const toggleSection = (id: string) => {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  return (
    <nav className={cn('space-y-1', className)} aria-label="Documentation navigation">
      {docSections.map((section) => {
        const isActive = activeSection === section.id || section.subsections?.some((s) => activeSection === s.id)
        const isExpanded = expanded[section.id]

        return (
          <div key={section.id}>
            <button
              className={cn(
                'w-full flex items-center justify-between px-3 py-2 text-sm font-medium rounded-lg transition-colors cursor-pointer',
                isActive
                  ? 'text-accent bg-accent/10'
                  : 'text-muted hover:text-foreground hover:bg-card'
              )}
              onClick={() => {
                onSectionClick(section.id)
                if (section.subsections) {
                  toggleSection(section.id)
                }
              }}
            >
              <span>{section.title}</span>
              {section.subsections && (
                isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />
              )}
            </button>

            {section.subsections && isExpanded && (
              <div className="ml-3 mt-1 space-y-0.5 border-l border-border pl-3">
                {section.subsections.map((sub) => (
                  <button
                    key={sub.id}
                    className={cn(
                      'w-full text-left px-3 py-1.5 text-sm rounded-md transition-colors cursor-pointer',
                      activeSection === sub.id
                        ? 'text-accent font-medium'
                        : 'text-muted hover:text-foreground'
                    )}
                    onClick={() => onSectionClick(sub.id)}
                  >
                    {sub.title}
                  </button>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </nav>
  )
}

import { useState } from 'react'
import { Menu, X } from 'lucide-react'
import { DocsSidebar } from './docs-sidebar'
import { DocsContent } from './docs-content'
import { docSections, docContents } from '@/content/docs'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

export function DocsLayout() {
  const [activeSection, setActiveSection] = useState(() => {
    if (typeof window !== 'undefined') {
      const hash = window.location.hash.slice(1)
      if (hash) return hash
    }
    return 'getting-started'
  })
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const handleSectionClick = (id: string) => {
    // Find which main section this belongs to
    let mainSectionId = id
    for (const section of docSections) {
      if (section.id === id) {
        mainSectionId = id
        break
      }
      if (section.subsections?.some((s) => s.id === id)) {
        mainSectionId = section.id
        // Scroll to the subsection anchor
        setTimeout(() => {
          document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' })
        }, 50)
        break
      }
    }
    setActiveSection(mainSectionId)
    window.history.replaceState(null, '', `#${id}`)
    setSidebarOpen(false)
  }

  const currentContent = docContents.find((d) => d.id === activeSection) || docContents[0]

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex gap-8">
        {/* Mobile sidebar toggle */}
        <div className="lg:hidden fixed bottom-4 right-4 z-50">
          <Button
            size="icon"
            className="h-12 w-12 rounded-full shadow-lg"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
          >
            {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>
        </div>

        {/* Sidebar overlay (mobile) */}
        {sidebarOpen && (
          <div
            className="lg:hidden fixed inset-0 bg-background/80 backdrop-blur-sm z-40"
            onClick={() => setSidebarOpen(false)}
            aria-hidden="true"
          />
        )}

        {/* Sidebar */}
        <aside
          className={cn(
            'shrink-0 lg:w-64 lg:sticky lg:top-20 lg:h-[calc(100vh-5rem)] lg:overflow-y-auto',
            'fixed inset-y-0 left-0 z-50 w-72 bg-background border-r border-border p-6 transform transition-transform duration-200 lg:relative lg:translate-x-0 lg:border-0 lg:p-0',
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          )}
          aria-label="Documentation sidebar"
        >
          <div className="lg:hidden flex items-center justify-between mb-6">
            <h3 className="font-semibold text-foreground">Documentation</h3>
            <button onClick={() => setSidebarOpen(false)} className="text-muted cursor-pointer" aria-label="Close sidebar">
              <X className="h-5 w-5" />
            </button>
          </div>
          <DocsSidebar
            activeSection={activeSection}
            onSectionClick={handleSectionClick}
          />
        </aside>

        {/* Content */}
        <main className="flex-1 min-w-0 max-w-3xl">
          <DocsContent content={currentContent} />
        </main>
      </div>
    </div>
  )
}

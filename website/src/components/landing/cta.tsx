import { ArrowRight, Github } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

export function CTA() {
  return (
    <section className="py-20 sm:py-28" aria-labelledby="cta-heading">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="relative overflow-hidden rounded-2xl border border-border bg-gradient-to-br from-accent/10 via-card to-card p-8 sm:p-12 md:p-16 text-center">
          {/* Background decorative elements */}
          <div className="absolute top-0 left-0 w-64 h-64 bg-accent/5 rounded-full -translate-x-1/2 -translate-y-1/2 blur-3xl" />
          <div className="absolute bottom-0 right-0 w-96 h-96 bg-accent/5 rounded-full translate-x-1/3 translate-y-1/3 blur-3xl" />

          <div className="relative">
            <h2 id="cta-heading" className="text-3xl sm:text-4xl md:text-5xl font-bold text-foreground">
              Ready to secure your application?
            </h2>
            <p className="mt-4 text-lg text-muted max-w-2xl mx-auto">
              Get started with GuardianWAF in under 5 minutes. One binary, zero configuration headaches.
            </p>

            <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link to="/docs#getting-started">
                <Button size="lg" className="gap-2 text-base">
                  Get Started
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
              <a href="https://github.com/GuardianWAF/GuardianWAF" target="_blank" rel="noopener noreferrer">
                <Button variant="secondary" size="lg" className="gap-2 text-base">
                  <Github className="h-5 w-5" />
                  Star on GitHub
                </Button>
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

import { Hero } from '@/components/landing/hero'
import { Features } from '@/components/landing/features'
import { Architecture } from '@/components/landing/architecture'
import { ScoringDemo } from '@/components/landing/scoring-demo'
import { QuickStart } from '@/components/landing/quick-start'
import { Comparison } from '@/components/landing/comparison'
import { Performance } from '@/components/landing/performance'
import { CTA } from '@/components/landing/cta'

export function HomePage() {
  return (
    <main>
      <Hero />
      <Features />
      <Architecture />
      <ScoringDemo />
      <QuickStart />
      <Comparison />
      <Performance />
      <CTA />
    </main>
  )
}

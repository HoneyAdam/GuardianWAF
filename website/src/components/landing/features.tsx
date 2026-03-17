import {
  Shield,
  Package,
  Rocket,
  BarChart3,
  Bot,
  Zap,
  Lock,
  Gauge,
  Search,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'

const features = [
  {
    icon: Shield,
    title: 'Multi-Layer Detection',
    description: 'SQL injection, XSS, path traversal, command injection, protocol anomaly, and bot detection with tokenizer-based analysis.',
  },
  {
    icon: Package,
    title: 'Zero Dependencies',
    description: 'Built entirely in Go\'s standard library. No external modules, no supply chain risk, no dependency hell.',
  },
  {
    icon: Rocket,
    title: 'Three Deploy Modes',
    description: 'Run as a standalone reverse proxy, embed as a Go library, or deploy as a sidecar. Your infrastructure, your choice.',
  },
  {
    icon: BarChart3,
    title: 'Scoring Engine',
    description: 'Intelligent threat scoring aggregates signals from all detectors. Configurable thresholds with per-rule weighting.',
  },
  {
    icon: Bot,
    title: 'MCP Integration',
    description: 'Built-in Model Context Protocol server for AI-powered analysis, automated tuning, and intelligent response.',
  },
  {
    icon: Zap,
    title: 'Sub-Millisecond Latency',
    description: 'Optimized detection pipeline processes requests in under 1ms at p99. Zero-allocation hot path.',
  },
  {
    icon: Lock,
    title: 'Auto TLS',
    description: 'Built-in ACME client for automatic certificate management. Let\'s Encrypt integration with zero configuration.',
  },
  {
    icon: Gauge,
    title: 'Real-Time Dashboard',
    description: 'Built-in web dashboard with live traffic metrics, threat visualization, and rule management. No external tools needed.',
  },
  {
    icon: Search,
    title: 'Deep Inspection',
    description: 'Custom tokenizer breaks down payloads into semantic tokens. Pattern matching beyond simple regex for fewer false positives.',
  },
]

export function Features() {
  return (
    <section id="features" className="py-20 sm:py-28" aria-labelledby="features-heading">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12 sm:mb-16">
          <h2 id="features-heading" className="text-3xl sm:text-4xl font-bold text-foreground">
            Everything you need. Nothing you don't.
          </h2>
          <p className="mt-4 text-lg text-muted max-w-2xl mx-auto">
            A complete WAF solution built from the ground up in Go, designed for modern cloud-native applications.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
          {features.map((feature) => {
            const Icon = feature.icon
            return (
              <Card
                key={feature.title}
                className="group hover:border-accent/50 transition-all duration-300 hover:shadow-lg hover:shadow-accent/5"
              >
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-accent/10 text-accent group-hover:bg-accent/20 transition-colors duration-300">
                      <Icon className="h-5 w-5" />
                    </div>
                    <CardTitle>{feature.title}</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-sm leading-relaxed">
                    {feature.description}
                  </CardDescription>
                </CardContent>
              </Card>
            )
          })}
        </div>
      </div>
    </section>
  )
}

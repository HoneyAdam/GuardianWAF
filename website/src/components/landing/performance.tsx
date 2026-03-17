import { Card, CardContent } from '@/components/ui/card'

const metrics = [
  { value: '<1ms', label: 'p99 Latency', detail: 'Detection pipeline' },
  { value: '50K+', label: 'Requests/sec', detail: 'Single core throughput' },
  { value: '0', label: 'Allocations', detail: 'Hot path zero-alloc' },
  { value: '7.2MB', label: 'Binary Size', detail: 'Statically linked' },
  { value: '<16MB', label: 'Memory', detail: 'Idle footprint' },
  { value: '~2s', label: 'Cold Start', detail: 'Ready to serve' },
]

export function Performance() {
  return (
    <section id="performance" className="py-20 sm:py-28 bg-card/30" aria-labelledby="performance-heading">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12 sm:mb-16">
          <h2 id="performance-heading" className="text-3xl sm:text-4xl font-bold text-foreground">
            Built for performance
          </h2>
          <p className="mt-4 text-lg text-muted max-w-2xl mx-auto">
            Security shouldn't slow you down. GuardianWAF is optimized from the ground up
            with zero-allocation hot paths and a tiny memory footprint.
          </p>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 sm:gap-6 max-w-4xl mx-auto">
          {metrics.map((metric) => (
            <Card
              key={metric.label}
              className="text-center hover:border-accent/50 transition-all duration-300"
            >
              <CardContent className="pt-6 pb-6">
                <div className="text-3xl sm:text-4xl font-bold text-accent font-mono">
                  {metric.value}
                </div>
                <div className="mt-2 text-sm font-medium text-foreground">
                  {metric.label}
                </div>
                <div className="mt-1 text-xs text-muted">
                  {metric.detail}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  )
}

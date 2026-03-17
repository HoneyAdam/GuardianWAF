import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'

interface ScoringExample {
  title: string
  input: string
  tokens: { text: string; type: string }[]
  scores: { detector: string; score: number }[]
  totalScore: number
  action: 'ALLOW' | 'BLOCK' | 'LOG'
}

const examples: ScoringExample[] = [
  {
    title: 'Legitimate Request',
    input: 'GET /api/users?page=2&limit=10',
    tokens: [
      { text: 'GET', type: 'method' },
      { text: '/api/users', type: 'path' },
      { text: 'page=2', type: 'param' },
      { text: 'limit=10', type: 'param' },
    ],
    scores: [
      { detector: 'SQLi', score: 0 },
      { detector: 'XSS', score: 0 },
      { detector: 'Path', score: 0 },
      { detector: 'Bot', score: 5 },
    ],
    totalScore: 5,
    action: 'ALLOW',
  },
  {
    title: 'Suspicious Request',
    input: "GET /search?q=<script>alert('xss')",
    tokens: [
      { text: 'GET', type: 'method' },
      { text: '/search', type: 'path' },
      { text: '<script>', type: 'xss-tag' },
      { text: "alert('xss')", type: 'xss-payload' },
    ],
    scores: [
      { detector: 'SQLi', score: 0 },
      { detector: 'XSS', score: 85 },
      { detector: 'Path', score: 0 },
      { detector: 'Bot', score: 10 },
    ],
    totalScore: 85,
    action: 'BLOCK',
  },
  {
    title: 'SQL Injection Attempt',
    input: "POST /login body: admin' OR 1=1--",
    tokens: [
      { text: 'POST', type: 'method' },
      { text: '/login', type: 'path' },
      { text: "admin'", type: 'sqli-escape' },
      { text: 'OR 1=1--', type: 'sqli-tautology' },
    ],
    scores: [
      { detector: 'SQLi', score: 95 },
      { detector: 'XSS', score: 0 },
      { detector: 'Path', score: 0 },
      { detector: 'Bot', score: 15 },
    ],
    totalScore: 95,
    action: 'BLOCK',
  },
]

function getActionColor(action: string) {
  switch (action) {
    case 'ALLOW': return 'success' as const
    case 'BLOCK': return 'destructive' as const
    case 'LOG': return 'warning' as const
    default: return 'secondary' as const
  }
}

function getScoreColor(score: number) {
  if (score >= 80) return 'text-destructive'
  if (score >= 40) return 'text-warning'
  if (score > 0) return 'text-muted'
  return 'text-muted-foreground'
}

function getTokenColor(type: string) {
  if (type.startsWith('sqli')) return 'bg-destructive/10 text-destructive border-destructive/30'
  if (type.startsWith('xss')) return 'bg-destructive/10 text-destructive border-destructive/30'
  if (type === 'method') return 'bg-accent/10 text-accent border-accent/30'
  if (type === 'path') return 'bg-purple-500/10 text-purple-400 border-purple-500/30'
  return 'bg-card text-muted border-border'
}

export function ScoringDemo() {
  return (
    <section id="scoring" className="py-20 sm:py-28" aria-labelledby="scoring-heading">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12 sm:mb-16">
          <h2 id="scoring-heading" className="text-3xl sm:text-4xl font-bold text-foreground">
            Intelligent Scoring Engine
          </h2>
          <p className="mt-4 text-lg text-muted max-w-2xl mx-auto">
            Every request is tokenized, analyzed by multiple detectors, and scored.
            The composite score determines the action. No binary rules -- just intelligent analysis.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {examples.map((example) => (
            <Card key={example.title} className="overflow-hidden">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">{example.title}</CardTitle>
                  <Badge variant={getActionColor(example.action)}>
                    {example.action}
                  </Badge>
                </div>
                <div className="mt-2 p-2 rounded-md bg-background font-mono text-xs text-muted overflow-x-auto">
                  {example.input}
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Tokens */}
                <div>
                  <p className="text-xs font-medium text-muted mb-2 uppercase tracking-wider">Tokens</p>
                  <div className="flex flex-wrap gap-1.5">
                    {example.tokens.map((token, i) => (
                      <span
                        key={i}
                        className={cn(
                          'inline-flex px-2 py-0.5 rounded text-xs font-mono border',
                          getTokenColor(token.type)
                        )}
                      >
                        {token.text}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Scores */}
                <div>
                  <p className="text-xs font-medium text-muted mb-2 uppercase tracking-wider">Detector Scores</p>
                  <div className="space-y-1.5">
                    {example.scores.map((s) => (
                      <div key={s.detector} className="flex items-center justify-between text-xs">
                        <span className="text-muted">{s.detector}</span>
                        <div className="flex items-center gap-2">
                          <div className="w-20 h-1.5 rounded-full bg-border overflow-hidden">
                            <div
                              className={cn(
                                'h-full rounded-full transition-all duration-500',
                                s.score >= 80 ? 'bg-destructive' :
                                s.score >= 40 ? 'bg-warning' :
                                s.score > 0 ? 'bg-muted' : 'bg-transparent'
                              )}
                              style={{ width: `${s.score}%` }}
                            />
                          </div>
                          <span className={cn('font-mono w-6 text-right', getScoreColor(s.score))}>
                            {s.score}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Total */}
                <div className="pt-3 border-t border-border flex items-center justify-between">
                  <span className="text-sm font-medium text-foreground">Total Score</span>
                  <span className={cn('text-2xl font-bold font-mono', getScoreColor(example.totalScore))}>
                    {example.totalScore}
                  </span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  )
}

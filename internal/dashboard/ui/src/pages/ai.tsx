import { useState, useEffect, useCallback } from 'react'
import { Section } from '@/components/config/section'
import { Input } from '@/components/ui/input'
import { Select, SelectOption } from '@/components/ui/select'
import { Button } from '@/components/ui/button'
import {
  Brain, Loader2, CheckCircle2, XCircle, Zap, DollarSign,
  Shield, Eye, Ban, Clock, Sparkles,
  ChevronDown, Lock, Activity,
} from 'lucide-react'
import { cn } from '@/lib/utils'

// --- Types ---

interface ProviderSummary {
  id: string; name: string; api: string; doc: string; model_count: number
  models: ModelSummary[]
}

interface ModelSummary {
  id: string; name: string; family: string; reasoning: boolean; tool_call: boolean
  cost_input_per_m: number; cost_output_per_m: number; context_window: number; max_output: number
}

interface AIConfig {
  enabled: boolean; provider_id: string; provider_name: string; model_id: string
  model_name: string; base_url: string; api_key_set: boolean; api_key_mask: string
}

interface AIStats {
  enabled: boolean; tokens_used_hour: number; tokens_used_day: number
  requests_hour: number; requests_day: number; total_tokens_used: number
  total_requests: number; total_cost_usd: number; blocks_triggered: number; monitors_triggered: number
}

interface Verdict { ip: string; action: string; reason: string; confidence: number }

interface AnalysisResult {
  id: string; timestamp: string; event_count: number; verdicts: Verdict[]
  summary: string; threats_detected: string[]; tokens_used: number
  cost_usd: number; duration_ms: number; model: string; error?: string
}

// --- API extensions ---

const aiApi = {
  getProviders: () => fetch('/api/v1/ai/providers').then(r => r.json()),
  getConfig: () => fetch('/api/v1/ai/config').then(r => r.json()),
  setConfig: (data: Record<string, string>) =>
    fetch('/api/v1/ai/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }).then(r => r.json()),
  getHistory: (limit = 20) => fetch(`/api/v1/ai/history?limit=${limit}`).then(r => r.json()),
  getStats: () => fetch('/api/v1/ai/stats').then(r => r.json()),
  analyze: (limit = 20) => fetch(`/api/v1/ai/analyze?limit=${limit}`, { method: 'POST' }).then(r => r.json()),
  test: () => fetch('/api/v1/ai/test', { method: 'POST' }).then(r => r.json()),
}

// --- Page ---

export default function AIPage() {
  const [providers, setProviders] = useState<ProviderSummary[]>([])
  const [config, setConfig] = useState<AIConfig | null>(null)
  const [stats, setStats] = useState<AIStats | null>(null)
  const [history, setHistory] = useState<AnalysisResult[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Config form
  const [selectedProvider, setSelectedProvider] = useState('')
  const [selectedModel, setSelectedModel] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ status: string; message: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeResult, setAnalyzeResult] = useState<AnalysisResult | null>(null)

  const refresh = useCallback(() => {
    Promise.all([
      aiApi.getConfig().catch(() => null),
      aiApi.getStats().catch(() => null),
      aiApi.getHistory().catch(() => ({ history: [] })),
      aiApi.getProviders().catch(() => ({ providers: [] })),
    ]).then(([cfg, st, hist, prov]) => {
      if (cfg) setConfig(cfg)
      if (st) setStats(st)
      if (hist?.history) setHistory(hist.history)
      if (prov?.providers) setProviders(prov.providers)
      setLoading(false)
    })
  }, [])

  useEffect(() => { refresh() }, [refresh])

  const selectedProviderData = providers.find(p => p.id === selectedProvider)

  const handleSave = async () => {
    if (!selectedProvider || !selectedModel || !apiKey) {
      setError('Provider, model ve API key gerekli')
      return
    }
    const prov = providers.find(p => p.id === selectedProvider)
    const model = prov?.models.find(m => m.id === selectedModel)

    setSaving(true)
    setError(null)
    try {
      await aiApi.setConfig({
        provider_id: selectedProvider,
        provider_name: prov?.name || selectedProvider,
        model_id: selectedModel,
        model_name: model?.name || selectedModel,
        api_key: apiKey,
        base_url: prov?.api || '',
      })
      setSuccess('AI provider configured successfully')
      setApiKey('')
      refresh()
    } catch (e: any) {
      setError(e.message || 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await aiApi.test()
      setTestResult(res)
    } catch {
      setTestResult({ status: 'error', message: 'Connection failed' })
    } finally {
      setTesting(false)
    }
  }

  const handleAnalyze = async () => {
    setAnalyzing(true)
    setAnalyzeResult(null)
    setError(null)
    try {
      const res = await aiApi.analyze(20)
      if (res.error) {
        setError(res.error)
      } else {
        setAnalyzeResult(res)
        refresh()
      }
    } catch (e: any) {
      setError(e.message || 'Analysis failed')
    } finally {
      setAnalyzing(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-4 pb-20">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Brain className="h-5 w-5 text-accent" />
          <h1 className="text-lg font-semibold text-foreground">AI Threat Analysis</h1>
        </div>
        {config?.api_key_set && (
          <Button onClick={handleAnalyze} disabled={analyzing} size="sm">
            {analyzing ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Zap className="h-4 w-4 mr-1" />}
            Analyze Now
          </Button>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive flex items-center gap-2">
          <XCircle size={16} /> {error}
          <button onClick={() => setError(null)} className="ml-auto text-xs underline">dismiss</button>
        </div>
      )}
      {success && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400 flex items-center gap-2">
          <CheckCircle2 size={16} /> {success}
          <button onClick={() => setSuccess(null)} className="ml-auto text-xs underline">dismiss</button>
        </div>
      )}

      {/* === Stats Cards === */}
      {stats?.enabled && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard icon={Zap} label="Requests/Hour" value={stats.requests_hour} max="/ 30" />
          <StatCard icon={Activity} label="Tokens/Hour" value={stats.tokens_used_hour.toLocaleString()} max="/ 50K" />
          <StatCard icon={DollarSign} label="Total Cost" value={`$${stats.total_cost_usd.toFixed(4)}`} />
          <StatCard icon={Ban} label="AI Blocks" value={stats.blocks_triggered} sub={`${stats.monitors_triggered} monitors`} />
        </div>
      )}

      {/* === Analysis Result (if just triggered) === */}
      {analyzeResult && (
        <Section title="Analysis Result" defaultOpen>
          <div className="space-y-3">
            <div className="text-sm text-muted-foreground">{analyzeResult.summary}</div>
            {analyzeResult.threats_detected?.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {analyzeResult.threats_detected.map((t, i) => (
                  <span key={i} className="text-[10px] px-2 py-0.5 rounded-full bg-red-900/40 text-red-300 border border-red-700/30">{t}</span>
                ))}
              </div>
            )}
            {analyzeResult.verdicts?.length > 0 && (
              <div className="space-y-1.5">
                {analyzeResult.verdicts.map((v, i) => (
                  <VerdictRow key={i} verdict={v} />
                ))}
              </div>
            )}
            <div className="flex gap-4 text-[10px] text-muted-foreground">
              <span>{analyzeResult.tokens_used} tokens</span>
              <span>${analyzeResult.cost_usd.toFixed(4)}</span>
              <span>{analyzeResult.duration_ms}ms</span>
              <span>{analyzeResult.event_count} events</span>
            </div>
          </div>
        </Section>
      )}

      {/* === Provider Config === */}
      <Section title="AI Provider Configuration" defaultOpen>
        {config?.api_key_set && (
          <div className="rounded-lg border border-border bg-card/50 px-4 py-3 mb-4 flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-foreground flex items-center gap-1.5">
                <CheckCircle2 size={14} className="text-emerald-400" />
                {config.provider_name || config.provider_id} — {config.model_name || config.model_id}
              </div>
              <div className="text-xs text-muted-foreground mt-0.5 flex items-center gap-1">
                <Lock size={10} /> API Key: {config.api_key_mask}
              </div>
            </div>
            <Button size="sm" variant="outline" onClick={handleTest} disabled={testing}>
              {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : 'Test Connection'}
            </Button>
          </div>
        )}

        {testResult && (
          <div className={cn(
            'rounded-lg border px-4 py-2 mb-4 text-sm flex items-center gap-2',
            testResult.status === 'ok'
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
              : 'border-red-500/30 bg-red-500/10 text-red-400'
          )}>
            {testResult.status === 'ok' ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
            {testResult.message}
          </div>
        )}

        <div className="grid gap-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Provider</label>
              <Select value={selectedProvider} onChange={e => { setSelectedProvider(e.target.value); setSelectedModel('') }}>
                <SelectOption value="">Select provider...</SelectOption>
                {providers.map(p => (
                  <SelectOption key={p.id} value={p.id}>{p.name} ({p.model_count} models)</SelectOption>
                ))}
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Model</label>
              <Select value={selectedModel} onChange={e => setSelectedModel(e.target.value)} disabled={!selectedProvider}>
                <SelectOption value="">Select model...</SelectOption>
                {selectedProviderData?.models.map(m => (
                  <SelectOption key={m.id} value={m.id}>
                    {m.name} {m.reasoning ? '(reasoning)' : ''} — ctx:{(m.context_window/1000).toFixed(0)}K
                  </SelectOption>
                ))}
              </Select>
            </div>
          </div>

          {/* Selected model details */}
          {selectedModel && selectedProviderData && (() => {
            const model = selectedProviderData.models.find(m => m.id === selectedModel)
            if (!model) return null
            return (
              <div className="rounded-lg border border-border bg-card/30 px-4 py-2.5 grid grid-cols-4 gap-3 text-xs">
                <div>
                  <span className="text-muted-foreground">Family:</span>
                  <span className="ml-1 text-foreground">{model.family}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Context:</span>
                  <span className="ml-1 text-foreground">{(model.context_window/1000).toFixed(0)}K tokens</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Cost In:</span>
                  <span className="ml-1 text-foreground">${model.cost_input_per_m}/M</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Cost Out:</span>
                  <span className="ml-1 text-foreground">${model.cost_output_per_m}/M</span>
                </div>
              </div>
            )
          })()}

          <div>
            <label className="text-xs text-muted-foreground mb-1 block">API Key</label>
            <Input type="password" placeholder="sk-..." value={apiKey} onChange={e => setApiKey(e.target.value)} />
          </div>

          <Button onClick={handleSave} disabled={saving || !selectedProvider || !selectedModel || !apiKey}>
            {saving ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Sparkles className="h-4 w-4 mr-1" />}
            Save Provider
          </Button>
        </div>
      </Section>

      {/* === Analysis History === */}
      <Section title={`Analysis History (${history.length})`} defaultOpen={history.length > 0}>
        {history.length === 0 ? (
          <div className="text-sm text-muted-foreground py-4 text-center">
            No analysis results yet. Configure a provider and click "Analyze Now".
          </div>
        ) : (
          <div className="space-y-2">
            {history.map((r) => (
              <HistoryItem key={r.id} result={r} />
            ))}
          </div>
        )}
      </Section>
    </div>
  )
}

// --- Sub-components ---

function StatCard({ icon: Icon, label, value, max, sub }: {
  icon: any; label: string; value: any; max?: string; sub?: string
}) {
  return (
    <div className="rounded-lg border border-border bg-card/50 px-3 py-2.5">
      <div className="flex items-center gap-1.5 mb-1">
        <Icon size={13} className="text-muted-foreground" />
        <span className="text-[10px] text-muted-foreground">{label}</span>
      </div>
      <div className="text-lg font-semibold text-foreground leading-none">
        {value}
        {max && <span className="text-xs text-muted-foreground font-normal ml-1">{max}</span>}
      </div>
      {sub && <div className="text-[10px] text-muted-foreground mt-0.5">{sub}</div>}
    </div>
  )
}

function VerdictRow({ verdict }: { verdict: Verdict }) {
  const actionColor = verdict.action === 'block'
    ? 'text-red-400 bg-red-900/40 border-red-700/30'
    : verdict.action === 'monitor'
    ? 'text-yellow-400 bg-yellow-900/40 border-yellow-700/30'
    : 'text-emerald-400 bg-emerald-900/40 border-emerald-700/30'

  const ActionIcon = verdict.action === 'block' ? Ban : verdict.action === 'monitor' ? Eye : Shield

  return (
    <div className="flex items-center gap-2 rounded-lg border border-border bg-card/30 px-3 py-2">
      <span className={cn('text-[10px] px-1.5 py-0.5 rounded border flex items-center gap-1', actionColor)}>
        <ActionIcon size={10} /> {verdict.action}
      </span>
      <span className="text-xs font-mono text-foreground">{verdict.ip}</span>
      <span className="text-xs text-muted-foreground flex-1 truncate">{verdict.reason}</span>
      <span className="text-[10px] text-muted-foreground">{(verdict.confidence * 100).toFixed(0)}%</span>
    </div>
  )
}

function HistoryItem({ result }: { result: AnalysisResult }) {
  const [open, setOpen] = useState(false)
  const hasError = Boolean(result.error)
  const ts = new Date(result.timestamp).toLocaleString()
  const blockCount = result.verdicts?.filter(v => v.action === 'block').length || 0
  const monitorCount = result.verdicts?.filter(v => v.action === 'monitor').length || 0

  return (
    <div className="rounded-lg border border-border bg-card/30 overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-3 px-3 py-2 hover:bg-card/50 transition-colors text-left">
        <Clock size={12} className="text-muted-foreground shrink-0" />
        <span className="text-xs text-muted-foreground">{ts}</span>
        <span className="text-xs text-foreground">{result.event_count} events</span>
        {blockCount > 0 && <span className="text-[9px] px-1.5 rounded bg-red-900/40 text-red-300">{blockCount} blocks</span>}
        {monitorCount > 0 && <span className="text-[9px] px-1.5 rounded bg-yellow-900/40 text-yellow-300">{monitorCount} monitors</span>}
        {hasError && <span className="text-[9px] px-1.5 rounded bg-red-900/40 text-red-400">error</span>}
        <span className="text-[10px] text-muted-foreground ml-auto">{result.tokens_used} tok / ${result.cost_usd.toFixed(4)} / {result.duration_ms}ms</span>
        <ChevronDown size={14} className={cn('text-muted-foreground transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="border-t border-border px-3 py-2 space-y-2">
          {result.summary && <p className="text-xs text-muted-foreground">{result.summary}</p>}
          {result.error && <p className="text-xs text-red-400">{result.error}</p>}
          {result.threats_detected?.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {result.threats_detected.map((t, i) => (
                <span key={i} className="text-[9px] px-1.5 py-0.5 rounded-full bg-red-900/30 text-red-300">{t}</span>
              ))}
            </div>
          )}
          {result.verdicts?.map((v, i) => <VerdictRow key={i} verdict={v} />)}
          <div className="text-[10px] text-muted-foreground">Model: {result.model}</div>
        </div>
      )}
    </div>
  )
}

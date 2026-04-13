import { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Brain,
  Play,
  Trash2,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Loader2,
  FileText,
} from 'lucide-react'
import { clsx } from 'clsx'
import { ollamaApi } from '@/api/ollama'
import type { OllamaAnalysis } from '@/types/ollama'

// ── Source options ────────────────────────────────────────────────────────

const SOURCES = ['static', 'owasp', 'cve', 'fuzzing', 'tls', 'jwt', 'frida', 'strix', 'manual'] as const
type Source = typeof SOURCES[number]

const SOURCE_LABELS: Record<Source, string> = {
  static:  'Static',
  owasp:   'OWASP',
  cve:     'CVE',
  fuzzing: 'Fuzzing',
  tls:     'TLS',
  jwt:     'JWT',
  frida:   'Frida',
  strix:   'Strix',
  manual:  'Manual',
}

// ── AI response renderer ──────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH:     'bg-orange-500 text-white',
  MEDIUM:   'bg-yellow-500 text-black',
  LOW:      'bg-blue-500 text-white',
}

function highlightSeverities(text: string) {
  // Replace CRITICAL/HIGH/MEDIUM/LOW with colored spans
  const parts = text.split(/(CRITICAL|HIGH|MEDIUM|LOW)/g)
  return parts.map((part, i) => {
    if (part === 'CRITICAL') return <span key={i} className="text-red-400 font-semibold">{part}</span>
    if (part === 'HIGH')     return <span key={i} className="text-orange-400 font-semibold">{part}</span>
    if (part === 'MEDIUM')   return <span key={i} className="text-yellow-400 font-semibold">{part}</span>
    if (part === 'LOW')      return <span key={i} className="text-blue-400 font-semibold">{part}</span>
    return part
  })
}

function AiResponseView({ text }: { text: string }) {
  // Parse sections: FINDINGS:, OVERALL RISK: X, SUMMARY:
  const overallRiskMatch = text.match(/OVERALL RISK:\s*(CRITICAL|HIGH|MEDIUM|LOW)/i)
  const overallRisk = overallRiskMatch?.[1]?.toUpperCase()

  const findingsMatch  = text.match(/FINDINGS:\s*([\s\S]*?)(?=OVERALL RISK:|SUMMARY:|$)/i)
  const summaryMatch   = text.match(/SUMMARY:\s*([\s\S]*?)$/i)

  const findingsText = findingsMatch?.[1]?.trim()
  const summaryText  = summaryMatch?.[1]?.trim()

  const hasSections = overallRisk || findingsText || summaryText

  if (!hasSections) {
    return (
      <pre className="text-xs text-zinc-300 font-mono whitespace-pre-wrap break-words leading-relaxed bg-bg-elevated rounded-lg p-4 overflow-auto max-h-[500px]">
        {text}
      </pre>
    )
  }

  return (
    <div className="space-y-3">
      {/* Overall risk */}
      {overallRisk && (
        <div className="flex items-center gap-3 px-4 py-3 bg-bg-surface rounded-lg border border-bg-border">
          <span className="text-xs text-zinc-500 font-medium">OVERALL RISK</span>
          <span className={clsx('text-sm px-3 py-1 rounded font-bold', RISK_COLORS[overallRisk] ?? 'bg-zinc-700 text-zinc-200')}>
            {overallRisk}
          </span>
        </div>
      )}

      {/* Findings */}
      {findingsText && (
        <div className="bg-bg-elevated rounded-lg border border-bg-border p-4">
          <p className="text-xs text-zinc-500 font-medium mb-3 flex items-center gap-1.5">
            <FileText size={11} />
            FINDINGS
          </p>
          <div className="text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap">
            {highlightSeverities(findingsText)}
          </div>
        </div>
      )}

      {/* Summary */}
      {summaryText && (
        <div className="border-l-2 border-accent/50 bg-bg-surface rounded-r-lg pl-4 pr-4 py-3">
          <p className="text-xs text-zinc-500 font-medium mb-1">SUMMARY</p>
          <p className="text-sm text-zinc-300 leading-relaxed">{summaryText}</p>
        </div>
      )}
    </div>
  )
}

// ── History row ───────────────────────────────────────────────────────────

function HistoryRow({ record, onDelete }: { record: OllamaAnalysis; onDelete: () => void }) {
  const [open, setOpen] = useState(false)

  const STATUS_COLOR: Record<string, string> = {
    complete: 'text-green-400',
    error:    'text-red-400',
    running:  'text-blue-400',
    pending:  'text-zinc-400',
  }

  return (
    <div className="border border-bg-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-2.5 bg-bg-surface">
        <button onClick={() => setOpen((v) => !v)} className="text-zinc-500 hover:text-zinc-200 shrink-0">
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </button>
        <span className="text-xs px-2 py-0.5 bg-bg-elevated rounded text-zinc-300 font-medium shrink-0">
          {record.source}
        </span>
        {record.session_id != null && (
          <span className="text-xs text-zinc-500 shrink-0">session {record.session_id}</span>
        )}
        <span className={clsx('text-xs font-medium shrink-0', STATUS_COLOR[record.status])}>
          {record.status}
        </span>
        <span className="text-xs text-zinc-500 font-mono shrink-0">{record.model_used}</span>
        <span className="text-xs text-zinc-600 flex-1">{new Date(record.created_at).toLocaleString()}</span>
        {record.duration_ms != null && (
          <span className="text-xs text-zinc-600 shrink-0">{(record.duration_ms / 1000).toFixed(1)}s</span>
        )}
        <button
          onClick={onDelete}
          className="text-zinc-600 hover:text-red-400 p-1 shrink-0"
        >
          <Trash2 size={12} />
        </button>
      </div>
      {open && (
        <div className="bg-bg-elevated px-4 py-3">
          {record.error && (
            <p className="text-xs text-red-400 font-mono mb-2">{record.error}</p>
          )}
          {record.ai_response && <AiResponseView text={record.ai_response} />}
        </div>
      )}
    </div>
  )
}

// ── Tabs ──────────────────────────────────────────────────────────────────

type Tab = 'analyze' | 'session' | 'history'

// ── Main page ─────────────────────────────────────────────────────────────

export default function AiTriagePage() {
  const qc = useQueryClient()
  const resultsRef = useRef<HTMLDivElement>(null)

  const [tab, setTab]               = useState<Tab>('analyze')

  // Analyze tab
  const [source,       setSource]       = useState<Source>('manual')
  const [scanData,     setScanData]     = useState('')
  const [extraContext, setExtraContext]  = useState('')
  const [analyzeSession, setAnalyzeSession] = useState('')
  const [analyzeResult, setAnalyzeResult]   = useState<string | null>(null)

  // Session tab
  const [sessionId,    setSessionId]    = useState('')
  const [sessionSources, setSessionSources] = useState<Set<Source>>(new Set())
  const [sessionResult,  setSessionResult]  = useState<{ text: string; sources: string[] } | null>(null)

  // History tab
  const [historyFilter, setHistoryFilter] = useState('')

  // Ollama status
  const { data: ollamaStatus } = useQuery({
    queryKey: ['ollama-status'],
    queryFn: () => ollamaApi.status(),
    refetchInterval: 10_000,
  })

  // History
  const { data: history = [], refetch: refetchHistory } = useQuery({
    queryKey: ['ollama-history'],
    queryFn: () => ollamaApi.history({ limit: 100 }),
    enabled: tab === 'history',
  })

  // Scroll to results
  useEffect(() => {
    if ((analyzeResult || sessionResult) && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }, [analyzeResult, sessionResult])

  const analyze = useMutation({
    mutationFn: () =>
      ollamaApi.analyze({
        scan_data: scanData,
        source,
        session_id: analyzeSession ? Number(analyzeSession) : undefined,
        extra_context: extraContext || undefined,
      }),
    onSuccess: (data) => {
      setAnalyzeResult(data.ai_response)
    },
  })

  const sessionReport = useMutation({
    mutationFn: () =>
      ollamaApi.analyzeSession({
        session_id: Number(sessionId),
        sources: sessionSources.size > 0 ? Array.from(sessionSources) : undefined,
      }),
    onSuccess: (data) => {
      setSessionResult({ text: data.ai_response ?? '', sources: data.sources_included ?? [] })
    },
  })

  const deleteAnalysis = useMutation({
    mutationFn: (id: number) => ollamaApi.deleteAnalysis(id),
    onSuccess: () => refetchHistory(),
  })

  function toggleSessionSource(s: Source) {
    setSessionSources((prev) => {
      const next = new Set(prev)
      next.has(s) ? next.delete(s) : next.add(s)
      return next
    })
  }

  const filteredHistory = historyFilter
    ? history.filter((r) => String(r.session_id) === historyFilter.trim())
    : history

  const TABS: { id: Tab; label: string }[] = [
    { id: 'analyze', label: 'Analyze' },
    { id: 'session', label: 'Session Report' },
    { id: 'history', label: 'History' },
  ]

  return (
    <div className="flex flex-col h-full p-6 gap-4 overflow-auto">

      {/* Header */}
      <div className="flex items-center gap-3">
        <Brain size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-zinc-100">AI Triage</h1>
        <div className="flex-1" />

        {/* Ollama status pill */}
        {ollamaStatus ? (
          <span className={clsx(
            'text-xs flex items-center gap-1.5 px-2.5 py-1 rounded border',
            !ollamaStatus.ollama_running
              ? 'border-red-700 text-red-400 bg-red-900/20'
              : !ollamaStatus.model_available
              ? 'border-yellow-700 text-yellow-400 bg-yellow-900/20'
              : 'border-green-700 text-green-400 bg-green-900/20',
          )}>
            {!ollamaStatus.ollama_running ? (
              <><XCircle size={11} /> Ollama offline</>
            ) : !ollamaStatus.model_available ? (
              <><AlertCircle size={11} /> Model missing</>
            ) : (
              <><CheckCircle2 size={11} /> metatron-qwen ready</>
            )}
          </span>
        ) : (
          <span className="text-xs text-zinc-600">Checking Ollama…</span>
        )}
      </div>

      {/* Hint banner */}
      {ollamaStatus?.hint && (
        <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-lg px-4 py-2 text-xs text-yellow-300 flex items-center gap-2">
          <AlertCircle size={11} className="shrink-0" />
          {ollamaStatus.hint}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-bg-border pb-0">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx(
              'px-4 py-2 text-sm border-b-2 -mb-px transition-colors',
              tab === t.id
                ? 'border-accent text-zinc-100'
                : 'border-transparent text-zinc-500 hover:text-zinc-300',
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Analyze tab ── */}
      {tab === 'analyze' && (
        <div className="flex flex-col gap-4">
          <div className="bg-bg-surface rounded-lg border border-bg-border p-4 flex flex-col gap-4">

            {/* Source selector */}
            <div>
              <label className="text-xs text-zinc-500 mb-2 block">Source</label>
              <div className="flex flex-wrap gap-1.5">
                {SOURCES.map((s) => (
                  <button
                    key={s}
                    onClick={() => setSource(s)}
                    className={clsx(
                      'text-xs px-3 py-1 rounded-full border transition-colors',
                      source === s
                        ? 'border-accent bg-accent/10 text-accent'
                        : 'border-bg-border text-zinc-500 hover:text-zinc-300 hover:border-zinc-500',
                    )}
                  >
                    {SOURCE_LABELS[s]}
                  </button>
                ))}
              </div>
            </div>

            {/* Scan data */}
            <div>
              <label className="text-xs text-zinc-500 mb-1 block">Scan Data</label>
              <textarea
                className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent font-mono resize-none"
                rows={10}
                placeholder="Paste raw scan output, JSON findings, or any security data to analyze…"
                value={scanData}
                onChange={(e) => setScanData(e.target.value)}
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-zinc-500 mb-1 block">Session ID</label>
                <input
                  className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
                  placeholder="Optional — link to a session"
                  value={analyzeSession}
                  onChange={(e) => setAnalyzeSession(e.target.value)}
                />
              </div>
              <div>
                <label className="text-xs text-zinc-500 mb-1 block">Extra Context</label>
                <input
                  className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
                  placeholder="Additional instructions for the model…"
                  value={extraContext}
                  onChange={(e) => setExtraContext(e.target.value)}
                />
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={() => { setAnalyzeResult(null); analyze.mutate() }}
                disabled={analyze.isPending || !scanData.trim() || !ollamaStatus?.ollama_running}
                className="flex items-center gap-2 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-sm text-white transition-colors"
              >
                {analyze.isPending
                  ? <><Loader2 size={13} className="animate-spin" />Analyzing…</>
                  : <><Play size={13} />Run Analysis</>
                }
              </button>
              {analyze.isError && (
                <span className="text-xs text-red-400">{(analyze.error as Error).message}</span>
              )}
            </div>
          </div>

          {/* Results */}
          {analyzeResult && (
            <div ref={resultsRef} className="flex flex-col gap-3">
              <p className="text-xs text-zinc-500 font-medium">Analysis Result</p>
              <AiResponseView text={analyzeResult} />
            </div>
          )}
        </div>
      )}

      {/* ── Session Report tab ── */}
      {tab === 'session' && (
        <div className="flex flex-col gap-4">
          <div className="bg-bg-surface rounded-lg border border-bg-border p-4 flex flex-col gap-4">
            <p className="text-xs text-zinc-400 leading-relaxed">
              Pulls all completed analyses for a session and runs a consolidated risk assessment —
              correlating findings across modules, identifying attack chains, and ranking top issues.
            </p>

            <div>
              <label className="text-xs text-zinc-500 mb-1 block">Session ID</label>
              <input
                className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
                placeholder="BluJay session ID"
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
              />
            </div>

            <div>
              <label className="text-xs text-zinc-500 mb-2 block">Filter sources (leave empty for all)</label>
              <div className="flex flex-wrap gap-1.5">
                {SOURCES.map((s) => (
                  <button
                    key={s}
                    onClick={() => toggleSessionSource(s)}
                    className={clsx(
                      'text-xs px-3 py-1 rounded-full border transition-colors',
                      sessionSources.has(s)
                        ? 'border-accent bg-accent/10 text-accent'
                        : 'border-bg-border text-zinc-500 hover:text-zinc-300 hover:border-zinc-500',
                    )}
                  >
                    {SOURCE_LABELS[s]}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={() => { setSessionResult(null); sessionReport.mutate() }}
                disabled={sessionReport.isPending || !sessionId.trim() || !ollamaStatus?.ollama_running}
                className="flex items-center gap-2 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-sm text-white transition-colors"
              >
                {sessionReport.isPending
                  ? <><Loader2 size={13} className="animate-spin" />Generating…</>
                  : <><FileText size={13} />Generate Report</>
                }
              </button>
              {sessionReport.isError && (
                <span className="text-xs text-red-400">{(sessionReport.error as Error).message}</span>
              )}
            </div>
          </div>

          {sessionResult && (
            <div ref={resultsRef} className="flex flex-col gap-3">
              <div className="flex items-center gap-2">
                <p className="text-xs text-zinc-500 font-medium">Consolidated Report</p>
                <span className="text-xs text-zinc-600">
                  Sources: {sessionResult.sources.join(', ') || 'all'}
                </span>
              </div>
              <AiResponseView text={sessionResult.text} />
            </div>
          )}
        </div>
      )}

      {/* ── History tab ── */}
      {tab === 'history' && (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <input
              className="bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent w-48"
              placeholder="Filter by session ID"
              value={historyFilter}
              onChange={(e) => setHistoryFilter(e.target.value)}
            />
            <span className="text-xs text-zinc-500">{filteredHistory.length} records</span>
          </div>

          <div className="flex flex-col gap-1.5">
            {filteredHistory.map((r) => (
              <HistoryRow
                key={r.id}
                record={r}
                onDelete={() => deleteAnalysis.mutate(r.id)}
              />
            ))}
            {filteredHistory.length === 0 && (
              <p className="text-zinc-500 text-sm py-4 text-center border border-dashed border-bg-border rounded-lg">
                No analyses yet. Run an analysis in the Analyze tab first.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

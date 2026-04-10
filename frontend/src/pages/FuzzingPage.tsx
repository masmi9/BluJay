import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Crosshair, Play, Trash2, ChevronDown, ChevronRight, AlertTriangle } from 'lucide-react'
import { clsx } from 'clsx'
import { fuzzingApi } from '@/api/fuzzing'
import type { FuzzJob, FuzzResult } from '@/types/fuzzing'
import { useWebSocket } from '@/hooks/useWebSocket'

const ALL_ATTACKS = ['idor', 'verb_tampering', 'auth_bypass', 'rate_limit'] as const
type AttackType = typeof ALL_ATTACKS[number]

const ATTACK_LABELS: Record<AttackType, string> = {
  idor: 'IDOR',
  verb_tampering: 'Verb Tampering',
  auth_bypass: 'Auth Bypass Headers',
  rate_limit: 'Rate Limit Detection',
}

const STATUS_COLORS: Record<string, string> = {
  pending: 'text-zinc-400',
  running: 'text-blue-400',
  complete: 'text-green-400',
  error: 'text-red-400',
}

function ResultRow({ r }: { r: FuzzResult }) {
  const [open, setOpen] = useState(false)
  return (
    <div className={clsx('border-b border-bg-border', r.is_interesting && 'bg-yellow-900/10')}>
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-3 px-4 py-2 hover:bg-bg-elevated text-left"
      >
        {open ? <ChevronDown size={12} className="text-zinc-500 shrink-0" /> : <ChevronRight size={12} className="text-zinc-500 shrink-0" />}
        {r.is_interesting && <AlertTriangle size={12} className="text-yellow-400 shrink-0" />}
        <span className="text-xs font-mono text-zinc-400 w-16 shrink-0">{r.method}</span>
        <span className="text-xs font-mono text-zinc-300 flex-1 truncate">{r.url}</span>
        <span className="text-xs px-2 py-0.5 bg-bg-elevated rounded text-zinc-400 shrink-0">{r.attack_type}</span>
        <span className={clsx('text-xs w-10 text-right shrink-0',
          r.response_status && r.response_status >= 500 ? 'text-red-400' :
          r.response_status && r.response_status >= 400 ? 'text-orange-400' : 'text-zinc-400'
        )}>
          {r.response_status ?? '—'}
        </span>
      </button>
      {open && (
        <div className="px-8 pb-3 text-xs text-zinc-400 space-y-1">
          {r.notes && <p className="text-yellow-300">{r.notes}</p>}
          {r.response_body && (
            <pre className="bg-bg-elevated rounded p-2 text-zinc-400 overflow-auto max-h-24 whitespace-pre-wrap break-all">
              {r.response_body}
            </pre>
          )}
          <p className="text-zinc-600">{r.duration_ms?.toFixed(0)}ms</p>
        </div>
      )}
    </div>
  )
}

function JobRow({ job }: { job: FuzzJob }) {
  const [open, setOpen] = useState(false)
  const qc = useQueryClient()

  const { data: detail } = useQuery({
    queryKey: ['fuzz-job', job.id],
    queryFn: () => fuzzingApi.getJob(job.id),
    enabled: open,
  })

  const del = useMutation({
    mutationFn: () => fuzzingApi.deleteJob(job.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fuzz-jobs'] }),
  })

  // Live progress via WS
  const wsUrl = job.status === 'running' ? `/ws/fuzzing/${job.id}` : null
  const { lastMessage } = useWebSocket(wsUrl)
  useEffect(() => {
    if (lastMessage) qc.invalidateQueries({ queryKey: ['fuzz-job', job.id] })
  }, [lastMessage])

  const interesting = detail?.results.filter(r => r.is_interesting).length ?? 0

  return (
    <div className="border border-bg-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 bg-bg-surface">
        <button onClick={() => setOpen(v => !v)} className="text-zinc-500 hover:text-zinc-200">
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </button>
        <span className={clsx('text-xs font-medium capitalize', STATUS_COLORS[job.status])}>{job.status}</span>
        <span className="text-xs text-zinc-400">{job.endpoint_count} endpoints</span>
        <span className="text-xs text-zinc-500">{new Date(job.created_at).toLocaleString()}</span>
        {interesting > 0 && (
          <span className="text-xs px-2 py-0.5 bg-yellow-900/40 text-yellow-400 rounded">
            {interesting} interesting
          </span>
        )}
        <div className="flex-1" />
        <button onClick={() => del.mutate()} className="text-zinc-600 hover:text-red-400">
          <Trash2 size={13} />
        </button>
      </div>
      {open && detail && (
        <div className="bg-bg-elevated">
          {detail.results.length === 0 ? (
            <p className="px-4 py-3 text-xs text-zinc-500">No results yet…</p>
          ) : (
            detail.results.map(r => <ResultRow key={r.id} r={r} />)
          )}
        </div>
      )}
    </div>
  )
}

export default function FuzzingPage() {
  const qc = useQueryClient()
  const [sessionId, setSessionId] = useState('')
  const [analysisId, setAnalysisId] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [filter, setFilter] = useState('')
  const [attacks, setAttacks] = useState<Set<AttackType>>(new Set(ALL_ATTACKS))

  const { data: jobs = [] } = useQuery({
    queryKey: ['fuzz-jobs'],
    queryFn: () => fuzzingApi.listJobs(),
    refetchInterval: (query) =>
      (query.state.data as FuzzJob[] | undefined)?.some(j => j.status === 'running') ? 3000 : false,
  })

  const create = useMutation({
    mutationFn: () => fuzzingApi.createJob({
      session_id: sessionId ? Number(sessionId) : undefined,
      analysis_id: analysisId ? Number(analysisId) : undefined,
      attacks: Array.from(attacks),
      endpoint_filter: filter || undefined,
      base_url: baseUrl || undefined,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fuzz-jobs'] }),
  })

  function toggleAttack(a: AttackType) {
    setAttacks(prev => {
      const next = new Set(prev)
      next.has(a) ? next.delete(a) : next.add(a)
      return next
    })
  }

  return (
    <div className="flex flex-col h-full p-6 gap-4 overflow-auto">
      <div className="flex items-center gap-3">
        <Crosshair size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-zinc-100">API Fuzzing</h1>
      </div>

      {/* Job creator */}
      <div className="bg-bg-surface rounded-lg border border-bg-border p-4 flex flex-col gap-4">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Session ID</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
              placeholder="Session ID for proxy endpoints"
              value={sessionId}
              onChange={e => setSessionId(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Analysis ID</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
              placeholder="Analysis ID for static endpoints"
              value={analysisId}
              onChange={e => setAnalysisId(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Base URL (for static)</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
              placeholder="https://api.example.com"
              value={baseUrl}
              onChange={e => setBaseUrl(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">URL Filter (regex)</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
              placeholder="/api/v1/.*"
              value={filter}
              onChange={e => setFilter(e.target.value)}
            />
          </div>
        </div>

        {/* Attack type checkboxes */}
        <div>
          <label className="text-xs text-zinc-500 mb-2 block">Attack Types</label>
          <div className="flex gap-3 flex-wrap">
            {ALL_ATTACKS.map(a => (
              <label key={a} className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={attacks.has(a)}
                  onChange={() => toggleAttack(a)}
                  className="accent-accent"
                />
                <span className="text-xs text-zinc-300">{ATTACK_LABELS[a]}</span>
              </label>
            ))}
          </div>
        </div>

        <button
          onClick={() => create.mutate()}
          disabled={create.isPending || (!sessionId && !analysisId)}
          className="self-start flex items-center gap-2 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-sm text-white transition-colors"
        >
          <Play size={13} />
          {create.isPending ? 'Starting…' : 'Start Fuzz Job'}
        </button>
        {create.isError && <p className="text-xs text-red-400">{(create.error as Error).message}</p>}
      </div>

      {/* Jobs list */}
      <div className="flex flex-col gap-2">
        {jobs.map(j => <JobRow key={j.id} job={j} />)}
        {jobs.length === 0 && <p className="text-zinc-500 text-sm">No fuzz jobs yet.</p>}
      </div>
    </div>
  )
}

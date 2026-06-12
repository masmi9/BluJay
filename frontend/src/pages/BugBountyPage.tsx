import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Target, Play, RefreshCw, CheckCircle2, XCircle, Loader2, Clock, ChevronDown, ChevronRight } from 'lucide-react'
import { clsx } from 'clsx'
import { analysisApi } from '@/api/analysis'

const BASE = '/api/v1/bugbounty'

const STEP_LABELS: Record<string, string> = {
  static_analysis: 'Static Analysis Summary',
  secret_scan: 'Secret / Credential Scan',
  firebase_probe: 'Firebase Database Probe',
  s3_bucket_enum: 'S3 Bucket Enumeration',
  idor_sweep: 'IDOR Sweep',
  api_surface_map: 'API Surface Map',
}

interface Step {
  name: string
  status: 'pending' | 'running' | 'complete' | 'error'
  result: Record<string, unknown> | null
  error: string | null
}

interface BugBountyJob {
  job_id: string
  app_name: string
  status: 'running' | 'complete' | 'error'
  started_at: string
  steps: Step[]
  error: string | null
}

async function fetchJob(jobId: string): Promise<BugBountyJob> {
  const r = await fetch(`${BASE}/${jobId}`)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

async function fetchJobs(): Promise<BugBountyJob[]> {
  const r = await fetch(`${BASE}`)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export default function BugBountyPage() {
  const queryClient = useQueryClient()
  const [analysisId, setAnalysisId] = useState<number | ''>('')
  const [appName, setAppName] = useState('')
  const [scopeNotes, setScopeNotes] = useState('')
  const [activeJobId, setActiveJobId] = useState<string | null>(null)

  const { data: analyses = [] } = useQuery({ queryKey: ['analyses'], queryFn: analysisApi.list })

  const { data: activeJob } = useQuery({
    queryKey: ['bugbounty-job', activeJobId],
    queryFn: () => fetchJob(activeJobId!),
    enabled: !!activeJobId,
    refetchInterval: (q) => {
      const status = q.state.data?.status
      return status === 'running' ? 1500 : false
    },
  })

  const { data: jobs = [] } = useQuery({
    queryKey: ['bugbounty-jobs'],
    queryFn: fetchJobs,
    refetchInterval: activeJob?.status === 'running' ? 3000 : false,
  })

  const run = useMutation({
    mutationFn: async () => {
      const r = await fetch(`${BASE}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analysis_id: Number(analysisId), app_name: appName, scope_notes: scopeNotes }),
      })
      if (!r.ok) {
        const body = await r.json().catch(() => ({ detail: r.statusText }))
        throw new Error(body.detail ?? r.statusText)
      }
      return r.json() as Promise<BugBountyJob>
    },
    onSuccess: (job) => {
      setActiveJobId(job.job_id)
      queryClient.invalidateQueries({ queryKey: ['bugbounty-jobs'] })
    },
  })

  const displayJob = activeJob ?? (activeJobId ? jobs.find((j) => j.job_id === activeJobId) : null)

  return (
    <div className="flex h-full overflow-hidden">
      {/* Left panel — launch + history */}
      <div className="w-72 shrink-0 border-r border-bg-border bg-bg-surface flex flex-col">
        <div className="p-4 border-b border-bg-border space-y-3">
          <div className="flex items-center gap-2">
            <Target size={14} className="text-orange-400" />
            <h1 className="text-sm font-semibold text-zinc-200">Bug Bounty Hunt</h1>
          </div>
          <p className="text-xs text-zinc-500">
            Structured recon sweep modeled after the TCM course hunt methodology.
            Runs static, secret, Firebase, S3, IDOR, and API checks in sequence.
          </p>

          <select
            value={analysisId}
            onChange={(e) => setAnalysisId(e.target.value ? Number(e.target.value) : '')}
            className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent"
          >
            <option value="">Select analysis…</option>
            {analyses.filter((a: any) => a.status === 'complete').map((a: any) => (
              <option key={a.id} value={a.id}>{a.apk_filename}</option>
            ))}
          </select>

          <input
            type="text"
            placeholder="App / target name (optional)"
            value={appName}
            onChange={(e) => setAppName(e.target.value)}
            className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
          />

          <textarea
            placeholder="Scope notes (optional)"
            value={scopeNotes}
            onChange={(e) => setScopeNotes(e.target.value)}
            rows={2}
            className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent resize-none"
          />

          {run.error && <p className="text-xs text-red-400">{(run.error as Error).message}</p>}

          <button
            onClick={() => run.mutate()}
            disabled={run.isPending || !analysisId}
            className="flex items-center gap-1.5 w-full justify-center px-3 py-2 rounded bg-orange-500/80 hover:bg-orange-500 text-white text-xs font-medium disabled:opacity-40 transition-colors"
          >
            {run.isPending ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
            {run.isPending ? 'Launching…' : 'Start Hunt'}
          </button>
        </div>

        {/* History */}
        <div className="flex-1 overflow-auto p-2 space-y-1">
          {jobs.map((j) => (
            <button
              key={j.job_id}
              onClick={() => setActiveJobId(j.job_id)}
              className={clsx(
                'w-full text-left px-3 py-2 rounded-lg text-xs transition-colors',
                activeJobId === j.job_id
                  ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30'
                  : 'text-zinc-400 hover:bg-bg-elevated'
              )}
            >
              <p className="truncate font-medium">{j.app_name}</p>
              <p className="text-zinc-600 mt-0.5">{j.job_id} · {j.status}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Right panel — results */}
      <div className="flex-1 overflow-auto p-6">
        {!displayJob && (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-zinc-600">
            <Target size={32} />
            <p className="text-sm">Select an analysis and click Start Hunt</p>
          </div>
        )}

        {displayJob && (
          <div className="max-w-2xl space-y-5">
            <div className="flex items-center gap-3">
              <div>
                <h2 className="text-sm font-semibold text-zinc-200">{displayJob.app_name}</h2>
                <p className="text-xs text-zinc-500 mt-0.5">Job {displayJob.job_id} · started {new Date(displayJob.started_at).toLocaleTimeString()}</p>
              </div>
              <div className="ml-auto">
                {displayJob.status === 'running' && <Loader2 size={16} className="animate-spin text-orange-400" />}
                {displayJob.status === 'complete' && <CheckCircle2 size={16} className="text-green-400" />}
                {displayJob.status === 'error' && <XCircle size={16} className="text-red-400" />}
              </div>
            </div>

            {displayJob.error && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400">{displayJob.error}</div>
            )}

            <div className="space-y-3">
              {displayJob.steps.map((step) => (
                <StepCard key={step.name} step={step} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function StepCard({ step }: { step: Step }) {
  const [open, setOpen] = useState(false)

  const statusIcon = {
    pending: <Clock size={13} className="text-zinc-600" />,
    running: <Loader2 size={13} className="animate-spin text-orange-400" />,
    complete: <CheckCircle2 size={13} className="text-green-400" />,
    error: <XCircle size={13} className="text-red-400" />,
  }[step.status]

  return (
    <div className={clsx(
      'rounded-lg border transition-colors',
      step.status === 'complete' ? 'border-green-500/20 bg-green-500/5' :
      step.status === 'error' ? 'border-red-500/20 bg-red-500/5' :
      step.status === 'running' ? 'border-orange-500/30 bg-orange-500/5' :
      'border-bg-border bg-bg-surface'
    )}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
        onClick={() => step.result && setOpen((o) => !o)}
      >
        {statusIcon}
        <span className="text-xs font-medium text-zinc-200 flex-1">{STEP_LABELS[step.name] ?? step.name}</span>
        {step.result && (open ? <ChevronDown size={12} className="text-zinc-500" /> : <ChevronRight size={12} className="text-zinc-500" />)}
      </button>

      {step.error && (
        <p className="px-4 pb-3 text-xs text-red-400">{step.error}</p>
      )}

      {open && step.result && (
        <div className="px-4 pb-3">
          <pre className="text-xs text-zinc-400 bg-bg-base rounded p-3 overflow-auto max-h-48 whitespace-pre-wrap">
            {JSON.stringify(step.result, null, 2)}
          </pre>
        </div>
      )}

      {/* Quick summary badges */}
      {step.status === 'complete' && step.result && !open && (
        <div className="px-4 pb-3 flex flex-wrap gap-2">
          {renderSummaryBadges(step.name, step.result)}
        </div>
      )}
    </div>
  )
}

function renderSummaryBadges(name: string, result: Record<string, unknown>) {
  const badges: JSX.Element[] = []

  if (name === 'static_analysis' && result.findings_by_severity) {
    const sev = result.findings_by_severity as Record<string, number>
    const colors: Record<string, string> = { critical: 'bg-red-600', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-blue-500' }
    Object.entries(sev).filter(([, v]) => v > 0).forEach(([k, v]) =>
      badges.push(
        <span key={k} className={`${colors[k] ?? 'bg-zinc-600'} text-white text-[10px] px-1.5 py-0.5 rounded`}>{v} {k}</span>
      )
    )
  }
  if (name === 'secret_scan') badges.push(<span key="s" className="text-xs text-zinc-400">{String(result.count)} secrets found</span>)
  if (name === 'firebase_probe') badges.push(<span key="f" className="text-xs text-zinc-400">{String(result.databases_found)} DBs found</span>)
  if (name === 's3_bucket_enum') badges.push(<span key="b" className="text-xs text-zinc-400">{String(result.buckets_found)} buckets found</span>)
  if (name === 'idor_sweep') badges.push(<span key="i" className="text-xs text-zinc-400">{String(result.idor_findings)} IDOR findings</span>)
  if (name === 'api_surface_map') badges.push(<span key="a" className="text-xs text-zinc-400">{String(result.endpoints_discovered)} endpoints mapped</span>)

  return badges
}

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { KeyRound, Scan, Play, Pause, RotateCcw, CheckCircle } from 'lucide-react'
import { clsx } from 'clsx'
import { bruteForceApi } from '@/api/brute_force'
import type { BruteForceJob, DetectedEndpoint } from '@/types/brute_force'
import { useWebSocket } from '@/hooks/useWebSocket'

const STATUS_COLORS: Record<string, string> = {
  pending: 'text-zinc-400',
  running: 'text-blue-400',
  paused:  'text-yellow-400',
  complete: 'text-green-400',
  error:   'text-red-400',
}

function ProgressBar({ job }: { job: BruteForceJob }) {
  const qc = useQueryClient()
  const wsUrl = job.status === 'running' ? `/ws/brute-force/${job.id}` : null
  const { lastMessage } = useWebSocket(wsUrl)

  useEffect(() => {
    if (lastMessage) {
      qc.invalidateQueries({ queryKey: ['bf-jobs'] })
    }
  }, [lastMessage])

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-bg-elevated rounded-full overflow-hidden">
        <div
          className="h-full bg-accent rounded-full transition-all duration-300"
          style={{ width: `${Math.min((job.attempts_made / 200) * 100, 100)}%` }}
        />
      </div>
      <span className="text-xs text-zinc-500 shrink-0">{job.attempts_made} attempts</span>
    </div>
  )
}

function JobCard({ job }: { job: BruteForceJob }) {
  const qc = useQueryClient()
  const [showAttempts, setShowAttempts] = useState(false)

  const { data: attempts = [] } = useQuery({
    queryKey: ['bf-attempts', job.id],
    queryFn: () => bruteForceApi.getAttempts(job.id),
    enabled: showAttempts,
  })

  const pause = useMutation({
    mutationFn: () => bruteForceApi.pause(job.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['bf-jobs'] }),
  })

  const resume = useMutation({
    mutationFn: () => bruteForceApi.resume(job.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['bf-jobs'] }),
  })

  const foundCreds: { username: string; password: string }[] = job.credentials_found
    ? JSON.parse(job.credentials_found)
    : []

  return (
    <div className="bg-bg-surface rounded-lg border border-bg-border overflow-hidden">
      <div className="flex items-start gap-3 p-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={clsx('text-xs font-medium capitalize', STATUS_COLORS[job.status])}>{job.status}</span>
            <span className="text-xs text-zinc-600">#{job.id}</span>
          </div>
          <p className="text-sm text-zinc-200 font-mono truncate">{job.target_url}</p>
          <p className="text-xs text-zinc-500 mt-1">
            user: <span className="text-zinc-300">{job.username}</span> ·
            auth: <span className="text-zinc-300">{job.auth_type}</span> ·
            concurrency: <span className="text-zinc-300">{job.concurrency}</span> ·
            {job.rate_limit_rps} req/s
          </p>
          <div className="mt-2">
            <ProgressBar job={job} />
          </div>
        </div>
        <div className="flex gap-2 shrink-0">
          {job.status === 'running' && (
            <button onClick={() => pause.mutate()} className="p-1.5 rounded bg-bg-elevated hover:bg-bg-border text-yellow-400" title="Pause">
              <Pause size={13} />
            </button>
          )}
          {job.status === 'paused' && (
            <button onClick={() => resume.mutate()} className="p-1.5 rounded bg-bg-elevated hover:bg-bg-border text-green-400" title="Resume">
              <RotateCcw size={13} />
            </button>
          )}
        </div>
      </div>

      {foundCreds.length > 0 && (
        <div className="px-4 pb-3">
          <div className="bg-green-900/30 border border-green-700/40 rounded p-3">
            <p className="text-xs font-medium text-green-400 mb-2 flex items-center gap-1">
              <CheckCircle size={12} /> Credentials Found
            </p>
            {foundCreds.map((c, i) => (
              <p key={i} className="text-xs font-mono text-green-300">
                {c.username} : <span className="text-green-200 font-bold">{c.password}</span>
              </p>
            ))}
          </div>
        </div>
      )}

      {job.error && (
        <p className="px-4 pb-3 text-xs text-red-400">{job.error}</p>
      )}

      <div className="border-t border-bg-border px-4 py-2">
        <button
          onClick={() => setShowAttempts(v => !v)}
          className="text-xs text-zinc-500 hover:text-zinc-300"
        >
          {showAttempts ? 'Hide' : 'Show'} attempts
        </button>
        {showAttempts && (
          <div className="mt-2 max-h-40 overflow-auto space-y-0.5">
            {attempts.map(a => (
              <div key={a.id} className={clsx('flex items-center gap-3 text-xs font-mono py-0.5', a.success && 'text-green-400')}>
                <span className="text-zinc-600 w-8 text-right">{a.status_code ?? '—'}</span>
                <span className="text-zinc-400 flex-1 truncate">{a.password}</span>
                {a.success && <CheckCircle size={10} className="text-green-400 shrink-0" />}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default function BruteForcePage() {
  const qc = useQueryClient()
  const [sessionId, setSessionId] = useState('')
  const [detected, setDetected] = useState<DetectedEndpoint[]>([])
  const [selectedEndpoint, setSelectedEndpoint] = useState<DetectedEndpoint | null>(null)
  const [username, setUsername] = useState('admin')
  const [concurrency, setConcurrency] = useState(5)
  const [rps, setRps] = useState(10)
  const [authType, setAuthType] = useState('form')

  const { data: jobs = [] } = useQuery({
    queryKey: ['bf-jobs'],
    queryFn: () => bruteForceApi.listJobs(),
    refetchInterval: (query) =>
      (query.state.data as BruteForceJob[] | undefined)?.some(j => j.status === 'running') ? 3000 : false,
  })

  const detectMut = useMutation({
    mutationFn: () => bruteForceApi.detect(Number(sessionId)),
    onSuccess: (data) => { setDetected(data); if (data.length) setSelectedEndpoint(data[0]) },
  })

  const createJob = useMutation({
    mutationFn: () => bruteForceApi.createJob({
      target_url: selectedEndpoint?.url ?? '',
      auth_type: authType,
      username_field: selectedEndpoint?.username_field ?? 'username',
      password_field: selectedEndpoint?.password_field ?? 'password',
      username,
      concurrency,
      rate_limit_rps: rps,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['bf-jobs'] }),
  })

  return (
    <div className="flex flex-col h-full p-6 gap-4 overflow-auto">
      <div className="flex items-center gap-3">
        <KeyRound size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-zinc-100">Credential Brute Force</h1>
      </div>

      {/* Detection panel */}
      <div className="bg-bg-surface rounded-lg border border-bg-border p-4 flex flex-col gap-3">
        <p className="text-xs font-medium text-zinc-400">Step 1 — Detect Login Endpoints</p>
        <div className="flex gap-2">
          <input
            className="w-40 bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
            placeholder="Session ID"
            value={sessionId}
            onChange={e => setSessionId(e.target.value)}
          />
          <button
            onClick={() => detectMut.mutate()}
            disabled={!sessionId || detectMut.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-bg-elevated hover:bg-bg-border disabled:opacity-50 rounded text-sm text-zinc-300 transition-colors"
          >
            <Scan size={13} /> {detectMut.isPending ? 'Scanning…' : 'Detect Endpoints'}
          </button>
        </div>
        {detected.length > 0 && (
          <div className="flex flex-col gap-1">
            {detected.map((ep, i) => (
              <button
                key={i}
                onClick={() => { setSelectedEndpoint(ep); setAuthType(ep.auth_type) }}
                className={clsx(
                  'text-left px-3 py-2 rounded text-xs font-mono border transition-colors',
                  selectedEndpoint?.url === ep.url
                    ? 'border-accent bg-accent/10 text-zinc-200'
                    : 'border-bg-border text-zinc-400 hover:border-zinc-600'
                )}
              >
                {ep.method ?? 'POST'} {ep.url} <span className="text-zinc-600">({ep.auth_type})</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Job config */}
      <div className="bg-bg-surface rounded-lg border border-bg-border p-4 flex flex-col gap-3">
        <p className="text-xs font-medium text-zinc-400">Step 2 — Configure & Launch</p>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Target URL</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 focus:outline-none focus:border-accent font-mono"
              value={selectedEndpoint?.url ?? ''}
              onChange={e => setSelectedEndpoint(prev => prev ? { ...prev, url: e.target.value } : null)}
              placeholder="https://api.example.com/login"
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Username</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 focus:outline-none focus:border-accent"
              value={username}
              onChange={e => setUsername(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Auth Type</label>
            <select
              className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200"
              value={authType}
              onChange={e => setAuthType(e.target.value)}
            >
              <option value="form">Form (urlencoded)</option>
              <option value="json">JSON body</option>
              <option value="basic">HTTP Basic</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Concurrency: {concurrency}</label>
            <input type="range" min={1} max={20} value={concurrency} onChange={e => setConcurrency(Number(e.target.value))} className="w-full accent-accent" />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Rate limit: {rps} req/s</label>
            <input type="range" min={1} max={50} value={rps} onChange={e => setRps(Number(e.target.value))} className="w-full accent-accent" />
          </div>
        </div>
        <button
          onClick={() => createJob.mutate()}
          disabled={createJob.isPending || !selectedEndpoint?.url}
          className="self-start flex items-center gap-2 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-sm text-white transition-colors"
        >
          <Play size={13} /> {createJob.isPending ? 'Starting…' : 'Launch Job'}
        </button>
      </div>

      {/* Active & past jobs */}
      <div className="flex flex-col gap-3">
        {jobs.map(j => <JobCard key={j.id} job={j} />)}
        {jobs.length === 0 && <p className="text-zinc-500 text-sm">No jobs yet.</p>}
      </div>
    </div>
  )
}

import React, { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import {
  ShieldAlert, Play, Trash2,
  RefreshCw, Zap, Eye, Globe, X, Plus,
} from 'lucide-react'
import { scannerApi } from '@/api/scanner'
import { proxyApi } from '@/api/proxy'
import { useProxyStore } from '@/store/proxyStore'
import type { ActiveScanJob, ScanFinding, SeverityLevel } from '@/types/scanner'
import { ACTIVE_CHECKS, SEVERITY_COLOR, SEVERITY_ORDER } from '@/types/scanner'

const CHECK_LABELS: Record<string, string> = {
  'xss-reflected':  'Reflected XSS',
  'sqli-error':     'SQL Injection (Error)',
  'open-redirect':  'Open Redirect',
  'path-traversal': 'Path Traversal',
  'ssrf-basic':     'SSRF (Basic)',
}

const PASSIVE_LABELS: Record<string, string> = {
  'missing-security-headers': 'Missing Security Headers',
  'insecure-cookie':          'Insecure Cookie',
  'reflected-input':          'Reflected Input',
  'sensitive-data-exposure':  'Sensitive Data Exposure',
  'info-disclosure':          'Info Disclosure',
  'cors-misconfiguration':    'CORS Misconfiguration',
}

function SeverityBadge({ severity }: { severity: SeverityLevel }) {
  return (
    <span className={clsx('px-1.5 py-0.5 text-xs rounded border font-medium capitalize', SEVERITY_COLOR[severity])}>
      {severity}
    </span>
  )
}

function FindingRow({ finding, onSelect, selected }: {
  finding: ScanFinding
  onSelect: (f: ScanFinding) => void
  selected: boolean
}) {
  return (
    <div
      onClick={() => onSelect(finding)}
      className={clsx(
        'flex items-center gap-3 px-3 py-2 text-xs cursor-pointer hover:bg-bg-elevated border-l-2 transition-colors',
        selected ? 'bg-accent/10 border-accent' : 'border-transparent',
      )}
    >
      <SeverityBadge severity={finding.severity} />
      <span className="text-zinc-300 flex-1 truncate">{finding.title}</span>
      <span className="text-zinc-600 font-mono truncate max-w-[200px]">{finding.host}</span>
      <span className={clsx('text-xs px-1.5 py-0.5 rounded',
        finding.scan_type === 'passive' ? 'text-blue-400 bg-blue-500/10' : 'text-purple-400 bg-purple-500/10')}>
        {finding.scan_type}
      </span>
    </div>
  )
}

function FindingDetail({ finding }: { finding: ScanFinding }) {
  return (
    <div className="flex flex-col h-full overflow-auto p-4 space-y-4">
      <div className="flex items-start gap-3">
        <SeverityBadge severity={finding.severity} />
        <h2 className="text-sm font-semibold text-zinc-100 flex-1">{finding.title}</h2>
      </div>

      <div className="space-y-3 text-xs">
        <div>
          <p className="text-zinc-600 uppercase tracking-wide mb-1">URL</p>
          <p className="font-mono text-zinc-300 break-all">{finding.url}</p>
        </div>

        <div>
          <p className="text-zinc-600 uppercase tracking-wide mb-1">Detail</p>
          <p className="text-zinc-300 leading-relaxed">{finding.detail}</p>
        </div>

        {finding.evidence && (
          <div>
            <p className="text-zinc-600 uppercase tracking-wide mb-1">Evidence</p>
            <pre className="bg-bg-elevated border border-bg-border rounded p-2 text-xs font-mono text-amber-300 whitespace-pre-wrap break-all overflow-auto max-h-40">
              {finding.evidence}
            </pre>
          </div>
        )}

        {finding.remediation && (
          <div>
            <p className="text-zinc-600 uppercase tracking-wide mb-1">Remediation</p>
            <p className="text-green-400 leading-relaxed">{finding.remediation}</p>
          </div>
        )}

        <div className="pt-1 border-t border-bg-border text-zinc-600">
          Check: <span className="text-zinc-400">{finding.check_name}</span>
          {' · '}Type: <span className="text-zinc-400">{finding.scan_type}</span>
          {' · '}{new Date(finding.timestamp).toLocaleString()}
        </div>
      </div>
    </div>
  )
}

// ── URL target manager ────────────────────────────────────────────────────────

function UrlTargetInput({ urls, onChange }: { urls: string[]; onChange: (u: string[]) => void }) {
  const [input, setInput] = useState('')

  const add = () => {
    const u = input.trim()
    if (!u || urls.includes(u)) return
    if (!u.startsWith('http://') && !u.startsWith('https://')) {
      onChange([...urls, `https://${u}`])
    } else {
      onChange([...urls, u])
    }
    setInput('')
  }

  return (
    <div className="space-y-1.5">
      <p className="text-xs text-zinc-600 uppercase tracking-wide flex items-center gap-1">
        <Globe size={10} /> Target URLs
      </p>
      <div className="flex gap-1">
        <input
          className="flex-1 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-300 placeholder-zinc-600 focus:outline-none focus:border-purple-500/50"
          placeholder="https://example.com/search?q=test"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && add()}
        />
        <button onClick={add} className="px-2 py-1 text-xs bg-bg-elevated border border-bg-border rounded text-zinc-400 hover:text-zinc-200">
          <Plus size={11} />
        </button>
      </div>
      {urls.map((u) => (
        <div key={u} className="flex items-center gap-1 bg-bg-elevated border border-bg-border rounded px-2 py-0.5">
          <span className="text-xs font-mono text-zinc-400 flex-1 truncate">{u}</span>
          <button onClick={() => onChange(urls.filter((x) => x !== u))} className="text-zinc-600 hover:text-red-400">
            <X size={10} />
          </button>
        </div>
      ))}
    </div>
  )
}

// ── Passive URL scan ──────────────────────────────────────────────────────────

function PassiveUrlScan({ sessionId, onFindings }: {
  sessionId: number
  onFindings: (findings: import('@/types/scanner').ScanFinding[]) => void
}) {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<string | null>(null)

  const scan = async () => {
    const u = url.trim()
    if (!u) return
    setScanning(true)
    setResult(null)
    try {
      const data = await scannerApi.scanUrl(
        u.startsWith('http') ? u : `https://${u}`,
        sessionId || undefined,
      )
      setResult(`${data.findings.length} findings`)
      onFindings(data.findings)
    } catch (e: any) {
      setResult(e?.response?.data?.detail ?? 'Failed')
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="p-3 space-y-2 border-b border-bg-border">
      <p className="text-xs font-semibold text-zinc-300 flex items-center gap-1.5">
        <Eye size={12} className="text-blue-400" /> Passive Scan URL
      </p>
      <div className="flex gap-1">
        <input
          className="flex-1 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-300 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
          placeholder="https://target.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && scan()}
        />
        <button
          onClick={scan}
          disabled={scanning || !url.trim()}
          className="flex items-center gap-1 px-2 py-1 text-xs bg-blue-500/20 text-blue-400 hover:bg-blue-500/30 rounded disabled:opacity-40 transition-colors"
        >
          {scanning ? <RefreshCw size={11} className="animate-spin" /> : <Eye size={11} />}
          {scanning ? 'Scanning…' : 'Scan'}
        </button>
      </div>
      {result && <p className="text-xs text-zinc-500">{result}</p>}
    </div>
  )
}

// ── Active scan launcher ──────────────────────────────────────────────────────

function ActiveScanPanel({ sessionId, onJobStarted }: {
  sessionId: number
  onJobStarted: (job: ActiveScanJob) => void
}) {
  const [selectedChecks, setSelectedChecks] = useState<Set<string>>(new Set(ACTIVE_CHECKS))
  const [flowCount, setFlowCount] = useState(0)
  const [targetUrls, setTargetUrls] = useState<string[]>([])
  const [launching, setLaunching] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const toggleCheck = (c: string) => setSelectedChecks((prev) => {
    const next = new Set(prev)
    if (next.has(c)) next.delete(c); else next.add(c)
    return next
  })

  const launch = async () => {
    setError(null)
    setLaunching(true)
    try {
      let ids: string[] = []

      // Load proxy flows if session is active
      if (sessionId && flowCount > 0) {
        const { data: flowsData } = await import('axios').then((ax) =>
          ax.default.get(`/api/v1/proxy/flows`, { params: { session_id: sessionId, limit: flowCount } })
        )
        ids = flowsData.items.map((f: { id: string }) => f.id)
      }

      if (!ids.length && !targetUrls.length) {
        setError('Add target URLs above, or set "Proxy flows" > 0 to scan captured traffic.')
        return
      }

      const job = await scannerApi.startScan(ids, [...selectedChecks], sessionId || undefined, targetUrls)
      onJobStarted(job)
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? e?.message ?? 'Failed to start scan')
    } finally {
      setLaunching(false)
    }
  }

  return (
    <div className="p-3 space-y-3 border-b border-bg-border">
      <p className="text-xs font-semibold text-zinc-300 flex items-center gap-1.5">
        <Zap size={13} className="text-purple-400" /> Active Scan
      </p>

      <UrlTargetInput urls={targetUrls} onChange={setTargetUrls} />

      <div className="space-y-1.5">
        <p className="text-xs text-zinc-600 uppercase tracking-wide">Checks</p>
        <div className="grid grid-cols-2 gap-1">
          {ACTIVE_CHECKS.map((c) => (
            <label key={c} className="flex items-center gap-1.5 text-xs text-zinc-400 cursor-pointer hover:text-zinc-200">
              <input type="checkbox" checked={selectedChecks.has(c)} onChange={() => toggleCheck(c)} className="accent-purple-500" />
              {CHECK_LABELS[c]}
            </label>
          ))}
        </div>
      </div>

      <div className="flex items-center gap-2">
        <label className="text-xs text-zinc-600">Proxy flows</label>
        <input
          type="number" min={0} max={500} value={flowCount}
          onChange={(e) => setFlowCount(Number(e.target.value))}
          className="w-16 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-300 focus:outline-none focus:border-purple-500/50"
        />
        <span className="text-xs text-zinc-600">(0 = target URLs only)</span>
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <button
        onClick={launch}
        disabled={launching || selectedChecks.size === 0}
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 rounded transition-colors disabled:opacity-40"
      >
        {launching ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />}
        {launching ? 'Launching…' : 'Run Active Scan'}
      </button>
    </div>
  )
}

// ── Job list ──────────────────────────────────────────────────────────────────

function JobCard({ job, active, onSelect, onCancel }: {
  job: ActiveScanJob
  active: boolean
  onSelect: () => void
  onCancel: () => void
}) {
  const statusColor = job.status === 'done' ? 'text-green-400'
    : job.status === 'error' ? 'text-red-400'
    : job.status === 'running' ? 'text-amber-400'
    : 'text-zinc-500'

  return (
    <div
      onClick={onSelect}
      className={clsx('px-3 py-2 cursor-pointer hover:bg-bg-elevated transition-colors border-l-2',
        active ? 'border-purple-500 bg-purple-500/5' : 'border-transparent')}
    >
      <div className="flex items-center gap-2 text-xs">
        <span className={clsx('font-medium capitalize', statusColor)}>{job.status}</span>
        {job.status === 'running' && <RefreshCw size={10} className="animate-spin text-amber-400" />}
        <span className="text-zinc-600 ml-auto">{job.finding_count} findings</span>
      </div>
      <div className="text-xs text-zinc-600 mt-0.5">
        {job.checks.length} checks · {job.flow_ids.length} flows · {job.requests_sent} requests
      </div>
      {job.status === 'running' && (
        <button
          onClick={(e) => { e.stopPropagation(); onCancel() }}
          className="mt-1 text-xs text-red-400 hover:text-red-300"
        >
          Cancel
        </button>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ScannerPage() {
  const { sessionId } = useProxyStore()
  const effectiveSession = sessionId ?? 0
  const queryClient = useQueryClient()

  const [selectedFinding, setSelectedFinding] = useState<ScanFinding | null>(null)
  const [selectedJobId, setSelectedJobId] = useState<number | null>(null)
  const [scanTypeFilter, setScanTypeFilter] = useState<'all' | 'passive' | 'active'>('all')
  const [severityFilter, setSeverityFilter] = useState<'all' | SeverityLevel>('all')
  const [liveFindings, setLiveFindings] = useState<ScanFinding[]>([])
  const wsRef = useRef<WebSocket | null>(null)

  const { data: findingsData, refetch: refetchFindings } = useQuery({
    queryKey: ['scanner-findings', effectiveSession, scanTypeFilter, severityFilter],
    queryFn: () => scannerApi.getFindings({
      session_id: effectiveSession || undefined,
      scan_type: scanTypeFilter !== 'all' ? scanTypeFilter : undefined,
      severity: severityFilter !== 'all' ? severityFilter : undefined,
      limit: 500,
    }),
    refetchInterval: 5000,
  })

  const { data: jobs = [], refetch: refetchJobs } = useQuery({
    queryKey: ['scanner-jobs', effectiveSession],
    queryFn: () => scannerApi.listJobs(effectiveSession || undefined),
    refetchInterval: 3000,
  })

  // WebSocket for active scan job live updates
  useEffect(() => {
    if (!selectedJobId) return
    const ws = new WebSocket(`ws://${window.location.host}/ws/scanner/${selectedJobId}`)
    wsRef.current = ws
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.type === 'finding' && msg.data) {
          setLiveFindings((prev) => [msg.data as ScanFinding, ...prev])
        }
        if (msg.type === 'done' || msg.type === 'progress') {
          refetchJobs()
          refetchFindings()
        }
      } catch {}
    }
    ws.onclose = () => {}
    return () => ws.close()
  }, [selectedJobId])

  const handleJobStarted = (job: ActiveScanJob) => {
    setSelectedJobId(job.id)
    setLiveFindings([])
    refetchJobs()
  }

  const cancelJob = async (id: number) => {
    await scannerApi.cancelJob(id)
    refetchJobs()
  }

  const clearAll = async () => {
    await scannerApi.clearFindings(effectiveSession || undefined)
    refetchFindings()
    setSelectedFinding(null)
  }

  const allFindings: ScanFinding[] = findingsData?.items ?? []

  // Severity counts for summary bar
  const counts = allFindings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  const runningJob = jobs.find((j) => j.status === 'running')

  return (
    <div className="flex h-full overflow-hidden">

      {/* Left: controls + job list */}
      <div className="w-64 shrink-0 flex flex-col border-r border-bg-border bg-bg-surface overflow-y-auto">
        <div className="px-3 py-3 border-b border-bg-border flex items-center gap-2">
          <ShieldAlert size={14} className="text-accent" />
          <span className="text-xs font-semibold text-zinc-200">Scanner</span>
          {effectiveSession > 0 && (
            <span className="ml-auto text-xs text-zinc-600">Session #{effectiveSession}</span>
          )}
        </div>

        {/* Passive scanner info */}
        <div className="px-3 py-2 border-b border-bg-border">
          <div className="flex items-center gap-1.5 text-xs text-blue-400">
            <Eye size={11} /> Passive scanner running
          </div>
          <p className="text-xs text-zinc-600 mt-0.5">Analyzes each proxied flow automatically.</p>
        </div>

        {/* Active scan panel */}
        <ActiveScanPanel sessionId={effectiveSession} onJobStarted={handleJobStarted} />

        {/* Job history */}
        {jobs.length > 0 && (
          <div className="flex flex-col">
            <p className="px-3 py-1.5 text-xs text-zinc-600 uppercase tracking-wide border-b border-bg-border">
              Scan Jobs
            </p>
            {jobs.map((job) => (
              <JobCard
                key={job.id}
                job={job}
                active={job.id === selectedJobId}
                onSelect={() => { setSelectedJobId(job.id); setLiveFindings([]) }}
                onCancel={() => cancelJob(job.id)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Center: findings list */}
      <div className="flex flex-col flex-1 min-w-0 border-r border-bg-border">

        {/* Summary + filters */}
        <div className="px-3 py-2 border-b border-bg-border bg-bg-surface flex items-center gap-3 shrink-0 flex-wrap">
          {(['critical', 'high', 'medium', 'low', 'info'] as SeverityLevel[]).map((s) =>
            counts[s] ? (
              <button
                key={s}
                onClick={() => setSeverityFilter(severityFilter === s ? 'all' : s)}
                className={clsx('flex items-center gap-1 px-2 py-0.5 rounded border text-xs transition-colors',
                  SEVERITY_COLOR[s],
                  severityFilter === s ? 'opacity-100' : 'opacity-60 hover:opacity-100')}
              >
                {counts[s]} {s}
              </button>
            ) : null
          )}

          <div className="ml-auto flex items-center gap-2">
            <select
              value={scanTypeFilter}
              onChange={(e) => setScanTypeFilter(e.target.value as typeof scanTypeFilter)}
              className="bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs text-zinc-300 focus:outline-none"
            >
              <option value="all">All types</option>
              <option value="passive">Passive</option>
              <option value="active">Active</option>
            </select>
            <span className="text-xs text-zinc-600">{allFindings.length} findings</span>
            <button onClick={clearAll} className="p-1 text-zinc-600 hover:text-zinc-200">
              <Trash2 size={13} />
            </button>
          </div>
        </div>

        {/* Running job progress */}
        {runningJob && (
          <div className="px-3 py-1.5 bg-amber-500/10 border-b border-amber-500/20 flex items-center gap-2 shrink-0">
            <RefreshCw size={11} className="animate-spin text-amber-400" />
            <span className="text-xs text-amber-400">
              Active scan running — {runningJob.requests_sent} requests sent, {runningJob.finding_count} findings so far
            </span>
          </div>
        )}

        {/* Findings */}
        <div className="flex-1 overflow-y-auto">
          {allFindings.length === 0 && liveFindings.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-zinc-600 gap-2">
              <ShieldAlert size={28} />
              <p className="text-sm">No findings yet</p>
              <p className="text-xs text-center max-w-xs">
                Passive findings appear automatically as traffic flows through the proxy.
                Run an active scan to test for XSS, SQLi, and more.
              </p>
            </div>
          ) : (
            <>
              {liveFindings.map((f) => (
                <FindingRow key={`live-${f.id}`} finding={f} onSelect={setSelectedFinding} selected={selectedFinding?.id === f.id} />
              ))}
              {allFindings
                .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
                .map((f) => (
                  <FindingRow key={f.id} finding={f} onSelect={setSelectedFinding} selected={selectedFinding?.id === f.id} />
                ))
              }
            </>
          )}
        </div>
      </div>

      {/* Right: finding detail */}
      <div className="w-[420px] shrink-0 bg-bg-surface overflow-hidden">
        {selectedFinding ? (
          <FindingDetail finding={selectedFinding} />
        ) : (
          <div className="flex items-center justify-center h-full text-zinc-600 text-sm">
            Select a finding
          </div>
        )}
      </div>
    </div>
  )
}

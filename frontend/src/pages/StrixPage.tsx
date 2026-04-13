import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Radar,
  Play,
  Square,
  Trash2,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Settings2,
  Loader2,
} from 'lucide-react'
import { clsx } from 'clsx'
import { strixApi } from '@/api/strix'
import type { StrixScan, StrixFinding, StrixScanResults } from '@/types/strix'

// ── Risk / severity helpers ───────────────────────────────────────────────

const RISK_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH:     'bg-orange-500 text-white',
  MEDIUM:   'bg-yellow-500 text-black',
  LOW:      'bg-blue-500 text-white',
  NONE:     'bg-zinc-700 text-zinc-300',
}

const STATUS_COLOR: Record<string, string> = {
  pending:   'text-zinc-400',
  running:   'text-blue-400',
  complete:  'text-green-400',
  error:     'text-red-400',
  cancelled: 'text-zinc-500',
}

function riskBadge(level: string | null) {
  if (!level) return null
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded font-medium', RISK_BADGE[level] ?? 'bg-zinc-700 text-zinc-300')}>
      {level}
    </span>
  )
}

function fmtDuration(s: number | null) {
  if (!s) return null
  if (s < 60) return `${s.toFixed(0)}s`
  return `${Math.floor(s / 60)}m ${(s % 60).toFixed(0)}s`
}

// ── Finding card ─────────────────────────────────────────────────────────

function FindingCard({ f }: { f: StrixFinding }) {
  const [open, setOpen] = useState(false)
  const title  = f.title ?? f.name ?? 'Unnamed Finding'
  const sev    = (f.severity ?? '').toUpperCase()
  const sevCls = RISK_BADGE[sev] ?? 'bg-zinc-700 text-zinc-300'

  return (
    <div className="border border-bg-border rounded overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-3 px-3 py-2 bg-bg-surface hover:bg-bg-elevated text-left transition-colors"
      >
        {open ? <ChevronDown size={12} className="text-zinc-500 shrink-0" /> : <ChevronRight size={12} className="text-zinc-500 shrink-0" />}
        {sev && <span className={clsx('text-xs px-1.5 py-0.5 rounded font-medium shrink-0', sevCls)}>{sev}</span>}
        <span className="text-xs text-zinc-200 flex-1 truncate">{title}</span>
      </button>
      {open && (
        <div className="px-4 py-3 bg-bg-elevated space-y-2 text-xs text-zinc-400">
          {f.description && <p>{f.description}</p>}
          {f.remediation && (
            <div className="border-l-2 border-green-600/50 pl-3 text-zinc-400">
              <span className="text-green-400 font-medium">Remediation: </span>
              {f.remediation}
            </div>
          )}
          {/* Extra fields beyond the known ones */}
          {Object.entries(f)
            .filter(([k]) => !['title', 'name', 'severity', 'description', 'remediation'].includes(k))
            .map(([k, v]) => (
              <div key={k} className="font-mono text-zinc-500">
                <span className="text-zinc-400">{k}: </span>
                {typeof v === 'string' ? v : JSON.stringify(v)}
              </div>
            ))}
        </div>
      )}
    </div>
  )
}

// ── Scan row ──────────────────────────────────────────────────────────────

function ScanRow({ scan }: { scan: StrixScan }) {
  const [open, setOpen] = useState(false)
  const qc = useQueryClient()

  const { data: results } = useQuery<StrixScanResults>({
    queryKey: ['strix-results', scan.id],
    queryFn: () => strixApi.scanResults(scan.id),
    enabled: open && scan.status === 'complete',
  })

  const cancel = useMutation({
    mutationFn: () => strixApi.cancelScan(scan.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['strix-scans'] }),
  })

  const del = useMutation({
    mutationFn: () => strixApi.deleteScan(scan.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['strix-scans'] }),
  })

  const isActive = scan.status === 'pending' || scan.status === 'running'

  return (
    <div className="border border-bg-border rounded-lg overflow-hidden">
      {/* Collapsed header */}
      <div className="flex items-center gap-3 px-4 py-3 bg-bg-surface">
        <button onClick={() => setOpen((v) => !v)} className="text-zinc-500 hover:text-zinc-200 shrink-0">
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </button>

        {/* Status */}
        <span className={clsx('text-xs font-medium capitalize shrink-0 flex items-center gap-1', STATUS_COLOR[scan.status])}>
          {scan.status === 'running' && <Loader2 size={10} className="animate-spin" />}
          {scan.status}
        </span>

        {/* Target */}
        <span className="text-xs text-zinc-300 font-mono flex-1 truncate" title={scan.target}>
          {scan.target}
        </span>

        {/* Mode */}
        <span className="text-xs text-zinc-500 shrink-0">{scan.scan_mode}</span>

        {/* Risk */}
        {riskBadge(scan.risk_level)}

        {/* Vuln count */}
        {scan.vuln_count != null && scan.vuln_count > 0 && (
          <span className="text-xs px-2 py-0.5 bg-red-900/40 text-red-400 rounded shrink-0">
            {scan.vuln_count} vuln{scan.vuln_count !== 1 ? 's' : ''}
          </span>
        )}

        {/* Duration */}
        {scan.duration_seconds != null && (
          <span className="text-xs text-zinc-600 shrink-0">{fmtDuration(scan.duration_seconds)}</span>
        )}

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0">
          {isActive && (
            <button
              onClick={() => cancel.mutate()}
              disabled={cancel.isPending}
              title="Cancel scan"
              className="text-zinc-500 hover:text-yellow-400 disabled:opacity-50 p-1"
            >
              <Square size={12} />
            </button>
          )}
          {!isActive && (
            <button
              onClick={() => del.mutate()}
              disabled={del.isPending}
              title="Delete"
              className="text-zinc-600 hover:text-red-400 disabled:opacity-50 p-1"
            >
              <Trash2 size={12} />
            </button>
          )}
        </div>
      </div>

      {/* Expanded content */}
      {open && (
        <div className="bg-bg-elevated px-4 py-3 space-y-3">
          {scan.error && (
            <div className="flex items-start gap-2 text-xs text-red-400">
              <XCircle size={12} className="mt-0.5 shrink-0" />
              <span className="font-mono">{scan.error}</span>
            </div>
          )}

          {scan.status === 'running' && (
            <p className="text-xs text-blue-400 flex items-center gap-2">
              <Loader2 size={11} className="animate-spin" />
              Scan in progress — findings will appear when complete
            </p>
          )}

          {scan.status === 'pending' && (
            <p className="text-xs text-zinc-500">Queued — scan has not started yet</p>
          )}

          {scan.status === 'complete' && results && (
            <>
              {/* Summary */}
              {results.summary && (
                <div className="text-xs text-zinc-400 border-l-2 border-accent/40 pl-3 whitespace-pre-wrap">
                  {results.summary}
                </div>
              )}

              {/* Findings */}
              {results.findings.length === 0 ? (
                <p className="text-xs text-zinc-500">No findings — target appears clean</p>
              ) : (
                <div className="space-y-1.5">
                  <p className="text-xs text-zinc-500 font-medium">{results.findings.length} finding{results.findings.length !== 1 ? 's' : ''}</p>
                  {results.findings.map((f, i) => <FindingCard key={i} f={f} />)}
                </div>
              )}

              {results.run_dir && (
                <p className="text-xs text-zinc-600 font-mono">Run dir: {results.run_dir}</p>
              )}
            </>
          )}

          {/* Metadata footer */}
          <div className="flex gap-4 text-xs text-zinc-600 pt-1 border-t border-bg-border">
            <span>ID: {scan.id}</span>
            {scan.session_id && <span>Session: {scan.session_id}</span>}
            <span>Model: {scan.llm_model}</span>
            {scan.run_name && <span>Run: {scan.run_name}</span>}
            <span>{new Date(scan.created_at).toLocaleString()}</span>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────

export default function StrixPage() {
  const qc = useQueryClient()

  // Form state
  const [target,      setTarget]      = useState('')
  const [scanMode,    setScanMode]     = useState<'quick' | 'standard' | 'deep'>('standard')
  const [sessionId,   setSessionId]    = useState('')
  const [instruction, setInstruction]  = useState('')
  const [llmModel,    setLlmModel]     = useState('ollama/metatron-qwen')
  const [autoTriage,  setAutoTriage]   = useState(true)
  const [advanced,    setAdvanced]     = useState(false)

  // Pre-flight status
  const { data: strixStatus } = useQuery({
    queryKey: ['strix-status'],
    queryFn: () => strixApi.status(),
    refetchInterval: 10_000,
  })

  // Scans list
  const { data: scans = [] } = useQuery({
    queryKey: ['strix-scans'],
    queryFn: () => strixApi.listScans({ limit: 50 }),
    refetchInterval: (query) => {
      const data = query.state.data as StrixScan[] | undefined
      return data?.some((s) => s.status === 'pending' || s.status === 'running') ? 3000 : false
    },
  })

  const launch = useMutation({
    mutationFn: () =>
      strixApi.startScan({
        target,
        scan_mode: scanMode,
        session_id: sessionId ? Number(sessionId) : undefined,
        instruction: instruction || undefined,
        llm_model: llmModel || undefined,
        auto_triage: autoTriage,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['strix-scans'] })
      setTarget('')
      setInstruction('')
    },
  })

  const MODES: { value: 'quick' | 'standard' | 'deep'; label: string; desc: string }[] = [
    { value: 'quick',    label: 'Quick',    desc: 'Surface-level recon' },
    { value: 'standard', label: 'Standard', desc: 'Full recon + exploit' },
    { value: 'deep',     label: 'Deep',     desc: 'Exhaustive + bruteforce' },
  ]

  return (
    <div className="flex flex-col h-full p-6 gap-4 overflow-auto">

      {/* Header */}
      <div className="flex items-center gap-3">
        <Radar size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-zinc-100">Strix Pentest Agent</h1>
        <div className="flex-1" />

        {/* Status chips */}
        {strixStatus ? (
          <div className="flex items-center gap-2">
            <span className={clsx('text-xs flex items-center gap-1.5 px-2 py-1 rounded border',
              strixStatus.strix_installed
                ? 'border-green-700 text-green-400 bg-green-900/20'
                : 'border-red-700 text-red-400 bg-red-900/20'
            )}>
              {strixStatus.strix_installed ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
              Strix
            </span>
            <span className={clsx('text-xs flex items-center gap-1.5 px-2 py-1 rounded border',
              strixStatus.docker_running
                ? 'border-green-700 text-green-400 bg-green-900/20'
                : 'border-red-700 text-red-400 bg-red-900/20'
            )}>
              {strixStatus.docker_running ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
              Docker
            </span>
          </div>
        ) : (
          <span className="text-xs text-zinc-600">Checking prerequisites…</span>
        )}
      </div>

      {/* Hints banner */}
      {strixStatus && strixStatus.hints.length > 0 && (
        <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-lg px-4 py-3 space-y-1">
          {strixStatus.hints.map((h, i) => (
            <p key={i} className="text-xs text-yellow-300 flex items-center gap-2">
              <AlertTriangle size={11} className="shrink-0" />
              {h}
            </p>
          ))}
        </div>
      )}

      {/* Launch form */}
      <div className="bg-bg-surface rounded-lg border border-bg-border p-4 flex flex-col gap-4">

        {/* Target */}
        <div>
          <label className="text-xs text-zinc-500 mb-1 block">Target</label>
          <input
            className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent font-mono"
            placeholder="https://api.target.com  or  192.168.1.1  or  ./app-source/"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </div>

        {/* Scan mode */}
        <div>
          <label className="text-xs text-zinc-500 mb-2 block">Scan Mode</label>
          <div className="flex gap-2">
            {MODES.map((m) => (
              <button
                key={m.value}
                onClick={() => setScanMode(m.value)}
                className={clsx(
                  'flex-1 flex flex-col items-center gap-0.5 py-2 rounded border text-xs transition-colors',
                  scanMode === m.value
                    ? 'border-accent bg-accent/10 text-accent'
                    : 'border-bg-border text-zinc-500 hover:text-zinc-300 hover:border-zinc-600',
                )}
              >
                <span className="font-medium">{m.label}</span>
                <span className={clsx('text-[10px]', scanMode === m.value ? 'text-accent/70' : 'text-zinc-600')}>
                  {m.desc}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Options row */}
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <label className="text-xs text-zinc-500 mb-1 block">Session ID</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
              placeholder="Link to BluJay session (optional)"
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-2 mt-5">
            <input
              id="auto-triage"
              type="checkbox"
              checked={autoTriage}
              onChange={(e) => setAutoTriage(e.target.checked)}
              className="accent-accent"
            />
            <label htmlFor="auto-triage" className="text-xs text-zinc-300 cursor-pointer whitespace-nowrap">
              Auto-triage with metatron-qwen
            </label>
          </div>
        </div>

        {/* Advanced toggle */}
        <button
          onClick={() => setAdvanced((v) => !v)}
          className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300 self-start"
        >
          <Settings2 size={12} />
          {advanced ? 'Hide' : 'Show'} advanced options
        </button>

        {advanced && (
          <div className="grid grid-cols-2 gap-3 border-t border-bg-border pt-3">
            <div>
              <label className="text-xs text-zinc-500 mb-1 block">LLM Model</label>
              <input
                className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent font-mono"
                value={llmModel}
                onChange={(e) => setLlmModel(e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-zinc-500 mb-1 block">Custom Instruction</label>
              <textarea
                className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent resize-none"
                rows={2}
                placeholder="Focus on IDOR and auth bypass…"
                value={instruction}
                onChange={(e) => setInstruction(e.target.value)}
              />
            </div>
          </div>
        )}

        <div className="flex items-center gap-3 pt-1">
          <button
            onClick={() => launch.mutate()}
            disabled={launch.isPending || !target.trim() || !strixStatus?.ready}
            className="flex items-center gap-2 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-sm text-white transition-colors"
          >
            <Play size={13} />
            {launch.isPending ? 'Launching…' : 'Launch Scan'}
          </button>
          {!strixStatus?.ready && strixStatus && (
            <span className="text-xs text-red-400">Prerequisites not met — check hints above</span>
          )}
          {launch.isError && (
            <span className="text-xs text-red-400">{(launch.error as Error).message}</span>
          )}
          {launch.isSuccess && (
            <span className="text-xs text-green-400">Scan queued — ID {(launch.data as { id: number }).id}</span>
          )}
        </div>
      </div>

      {/* Scans list */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <p className="text-xs text-zinc-500">
            {scans.length} scan{scans.length !== 1 ? 's' : ''}
            {scans.some((s) => s.status === 'running') && (
              <span className="text-blue-400 ml-2 flex items-center gap-1 inline-flex">
                <Loader2 size={10} className="animate-spin" />
                scanning…
              </span>
            )}
          </p>
        </div>
        {scans.map((s) => <ScanRow key={s.id} scan={s} />)}
        {scans.length === 0 && (
          <p className="text-zinc-500 text-sm py-4 text-center border border-dashed border-bg-border rounded-lg">
            No scans yet. Enter a target above to launch your first Strix scan.
          </p>
        )}
      </div>
    </div>
  )
}

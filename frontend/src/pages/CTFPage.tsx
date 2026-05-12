import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Flag, Play, Trash2, ChevronDown, ChevronRight, Loader2,
  AlertTriangle, CheckCircle2, XCircle, Target, Network,
  Brain, Radar, Trophy, Terminal, Wrench, Lightbulb, Settings2,
  History, Shield,
} from 'lucide-react'
import { clsx } from 'clsx'
import { ctfApi } from '@/api/ctf'
import type { CTFScan, ServiceScope } from '@/api/ctf'

// ── Severity helpers ───────────────────────────────────────────────────────

const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH:     'bg-orange-500 text-white',
  MEDIUM:   'bg-yellow-500 text-black',
  LOW:      'bg-blue-500 text-white',
}

const SEV_BORDER: Record<string, string> = {
  CRITICAL: 'border-red-600/40',
  HIGH:     'border-orange-500/40',
  MEDIUM:   'border-yellow-500/40',
  LOW:      'border-blue-500/40',
}

// ── Time helper ────────────────────────────────────────────────────────────

function timeAgo(iso: string | null): string {
  if (!iso) return ''
  const s = (Date.now() - new Date(iso).getTime()) / 1000
  if (s < 60)    return `${Math.floor(s)}s ago`
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

// ── Phase logic ────────────────────────────────────────────────────────────

// Maps backend phase string to a step index (0-3)
const PHASE_ORDER = ['queued', 'port_discovery', 'scope_analysis', 'strix_integration', 'complete']

type StepState = 'pending' | 'running' | 'done' | 'error'

function stepState(scan: CTFScan, stepPhase: string): StepState {
  const scanIdx  = PHASE_ORDER.indexOf(scan.phase)
  const stepIdx  = PHASE_ORDER.indexOf(stepPhase)
  if (scan.status === 'error') {
    if (scanIdx === stepIdx) return 'error'
    return scanIdx > stepIdx ? 'done' : 'pending'
  }
  if (scan.status === 'complete') return 'done'
  if (scanIdx === stepIdx) return 'running'
  if (scanIdx > stepIdx)  return 'done'
  return 'pending'
}

// ── Phase step component ───────────────────────────────────────────────────

interface PhaseStepProps {
  label: string
  sublabel: string
  icon: React.ElementType
  state: StepState
  isLast?: boolean
  children?: React.ReactNode
}

function PhaseStep({ label, sublabel, icon: Icon, state, isLast, children }: PhaseStepProps) {
  const [open, setOpen] = useState(true)

  const circleStyle = clsx(
    'w-8 h-8 rounded-full border-2 flex items-center justify-center shrink-0',
    state === 'done'    ? 'border-green-500 bg-green-500/15' :
    state === 'running' ? 'border-accent bg-accent/15' :
    state === 'error'   ? 'border-red-500 bg-red-500/15' :
                          'border-bg-border bg-bg-surface',
  )

  const labelStyle = clsx(
    'text-sm font-medium',
    state === 'done'    ? 'text-zinc-200' :
    state === 'running' ? 'text-accent' :
    state === 'error'   ? 'text-red-400' :
                          'text-zinc-600',
  )

  return (
    <div className="flex gap-4">
      {/* Connector */}
      <div className="flex flex-col items-center">
        <div className={circleStyle}>
          {state === 'done'    && <CheckCircle2 size={14} className="text-green-400" />}
          {state === 'running' && <Loader2 size={14} className="text-accent animate-spin" />}
          {state === 'error'   && <XCircle size={14} className="text-red-400" />}
          {state === 'pending' && <Icon size={14} className="text-zinc-600" />}
        </div>
        {!isLast && (
          <div className={clsx('w-0.5 flex-1 my-1 min-h-[1.5rem]', state === 'done' ? 'bg-green-500/25' : 'bg-bg-border')} />
        )}
      </div>

      {/* Content */}
      <div className={clsx('flex-1', !isLast && 'pb-5')}>
        <div className="flex items-center gap-2 mb-0.5">
          <span className={labelStyle}>{label}</span>
          {state === 'running' && (
            <span className="text-[10px] text-accent font-medium tracking-wide animate-pulse">RUNNING</span>
          )}
          {state === 'done' && (
            <span className="text-[10px] text-green-400 font-medium tracking-wide">DONE</span>
          )}
          {state === 'error' && (
            <span className="text-[10px] text-red-400 font-medium tracking-wide">ERROR</span>
          )}
        </div>
        <p className="text-[10px] text-zinc-600 mb-2">{sublabel}</p>

        {/* Phase content */}
        {(state === 'running' || state === 'done') && children && (
          <div>
            {state === 'done' && (
              <button
                onClick={() => setOpen((v) => !v)}
                className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300 mb-1.5"
              >
                {open ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
                {open ? 'Collapse' : 'Expand'}
              </button>
            )}
            {(state === 'running' || open) && children}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Port table ─────────────────────────────────────────────────────────────

function PortTable({ scan }: { scan: CTFScan }) {
  if (scan.open_ports.length === 0) {
    if (scan.status === 'running' && scan.phase === 'port_discovery') {
      return (
        <div className="flex items-center gap-2 text-xs text-zinc-500 py-2">
          <Loader2 size={11} className="animate-spin shrink-0" />
          Running nmap — scanning {scan.target}…
        </div>
      )
    }
    return <p className="text-xs text-zinc-600">No open ports found.</p>
  }

  return (
    <div className="rounded-lg border border-bg-border overflow-hidden">
      <div className="grid grid-cols-[4rem_5rem_1fr] text-[10px] text-zinc-500 uppercase tracking-wider px-3 py-1.5 bg-bg-elevated border-b border-bg-border">
        <span>Port</span>
        <span>Service</span>
        <span>Version</span>
      </div>
      <div className="divide-y divide-bg-border/60">
        {scan.open_ports.map((p) => (
          <div key={p.port} className="grid grid-cols-[4rem_5rem_1fr] px-3 py-1.5 text-xs bg-bg-surface hover:bg-bg-elevated transition-colors">
            <span className="font-mono text-accent">{p.port}<span className="text-zinc-600">/{p.protocol}</span></span>
            <span className="text-zinc-300">{p.service}</span>
            <span className="text-zinc-500 truncate">{p.version || '—'}</span>
          </div>
        ))}
      </div>
      {scan.os_guess && (
        <div className="px-3 py-1.5 bg-bg-elevated border-t border-bg-border text-[10px] text-zinc-500">
          OS: <span className="text-zinc-300">{scan.os_guess}</span>
        </div>
      )}
    </div>
  )
}

// ── AI analysis panel ──────────────────────────────────────────────────────

function AIAnalysis({ scan }: { scan: CTFScan }) {
  if (scan.phase === 'scope_analysis' && !scan.ai_analysis) {
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <Loader2 size={11} className="animate-spin shrink-0" />
          Building attack vectors from {scan.open_ports.length} service{scan.open_ports.length !== 1 ? 's' : ''}…
        </div>
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <Loader2 size={11} className="animate-spin shrink-0" />
          Consulting metatron-qwen for CTF analysis…
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {/* Scope count summary */}
      {scan.scope.length > 0 && (
        <div className="flex gap-3 text-xs">
          <span className="text-zinc-400">
            <span className="text-zinc-200 font-medium">{scan.scope.length}</span> services scoped
          </span>
          {scan.scope.filter((s) => s.severity === 'CRITICAL' || s.severity === 'HIGH').length > 0 && (
            <span className="text-red-400 font-medium">
              {scan.scope.filter((s) => s.severity === 'CRITICAL' || s.severity === 'HIGH').length} critical/high
            </span>
          )}
        </div>
      )}

      {/* AI output */}
      {scan.ai_analysis ? (
        <div className="rounded-lg border border-accent/20 bg-accent/5 p-3">
          <div className="flex items-center gap-1.5 text-[10px] font-semibold text-accent/80 uppercase tracking-wider mb-2">
            <Brain size={10} />
            metatron-qwen CTF Analysis
          </div>
          <pre className="text-xs text-zinc-300 whitespace-pre-wrap leading-relaxed font-sans">
            {scan.ai_analysis}
          </pre>
        </div>
      ) : (
        <div className="text-[10px] text-zinc-600 italic">
          metatron-qwen offline — rule-based scope used (start Ollama for AI analysis)
        </div>
      )}
    </div>
  )
}

// ── Strix panel ────────────────────────────────────────────────────────────

function StrixPanel({ scan }: { scan: CTFScan }) {
  if (scan.phase === 'strix_integration' && scan.strix_scan_ids.length === 0) {
    return (
      <div className="flex items-center gap-2 text-xs text-zinc-500">
        <Loader2 size={11} className="animate-spin shrink-0" />
        Launching Strix on discovered web services…
      </div>
    )
  }

  if (scan.strix_scan_ids.length === 0) {
    return (
      <p className="text-xs text-zinc-600">No HTTP/HTTPS services found — Strix not launched.</p>
    )
  }

  const targets = scan.strix_targets ?? []

  return (
    <div className="space-y-2">
      {scan.strix_scan_ids.map((sid, i) => (
        <div key={sid} className="flex items-center gap-3 px-3 py-2 bg-bg-surface border border-bg-border rounded-lg">
          <Radar size={13} className="text-accent shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-xs text-zinc-200 font-mono truncate">{targets[i] ?? `Target ${i + 1}`}</p>
            <p className="text-[10px] text-zinc-500">Strix scan #{sid} — deep mode</p>
          </div>
          <a
            href="/api-scanner"
            className="text-[10px] text-accent border border-accent/30 rounded px-2 py-0.5 hover:bg-accent/10 transition-colors shrink-0"
          >
            View →
          </a>
        </div>
      ))}
    </div>
  )
}

// ── Complete summary ───────────────────────────────────────────────────────

function CompleteSummary({ scan }: { scan: CTFScan }) {
  const duration = scan.started_at && scan.completed_at
    ? ((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
    : null
  const fmt = (s: number) => s < 60 ? `${s.toFixed(0)}s` : `${Math.floor(s / 60)}m ${(s % 60).toFixed(0)}s`

  return (
    <div className="flex items-center gap-4 text-xs">
      <span className="text-zinc-400">
        <span className="text-zinc-200 font-medium">{scan.open_ports.length}</span> ports ·{' '}
        <span className="text-zinc-200 font-medium">{scan.scope.length}</span> services ·{' '}
        <span className="text-zinc-200 font-medium">{scan.strix_scan_ids.length}</span> Strix scan{scan.strix_scan_ids.length !== 1 ? 's' : ''}
      </span>
      {duration && <span className="text-zinc-600">completed in {fmt(duration)}</span>}
    </div>
  )
}

// ── Service scope card ─────────────────────────────────────────────────────

function ScopeCard({ s, target }: { s: ServiceScope; target: string }) {
  const [open, setOpen] = useState(false)
  const attacks = s.attacks.map((a) => a.replace(/TARGET/g, target))

  return (
    <div className={clsx('border rounded-lg overflow-hidden', SEV_BORDER[s.severity] ?? 'border-bg-border')}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-3 px-4 py-2.5 bg-bg-surface hover:bg-bg-elevated text-left transition-colors"
      >
        {open ? <ChevronDown size={12} className="text-zinc-500 shrink-0" /> : <ChevronRight size={12} className="text-zinc-500 shrink-0" />}
        <span className={clsx('text-[10px] px-1.5 py-0.5 rounded font-medium shrink-0', SEV_BADGE[s.severity] ?? 'bg-zinc-700 text-zinc-300')}>
          {s.severity}
        </span>
        <span className="text-sm font-mono text-zinc-200 shrink-0 w-14">{s.port}</span>
        <span className="text-xs font-medium text-zinc-200 shrink-0">{s.service}</span>
        {s.version && <span className="text-xs text-zinc-500 truncate ml-1">{s.version}</span>}
        <div className="flex-1" />
        {s.strix_scan_id && (
          <span className="text-[10px] text-blue-400 border border-blue-400/30 rounded px-1.5 py-0.5 shrink-0">
            Strix #{s.strix_scan_id}
          </span>
        )}
      </button>

      {open && (
        <div className="bg-bg-elevated border-t border-bg-border divide-y divide-bg-border">
          <div className="px-4 py-3 space-y-2">
            <div className="flex items-center gap-1.5 text-[10px] font-semibold text-zinc-400 uppercase tracking-wider">
              <Terminal size={10} /> Attack Vectors
            </div>
            <ul className="space-y-1.5">
              {attacks.map((a, i) => (
                <li key={i} className="flex items-start gap-2 text-xs">
                  <span className="text-accent shrink-0 mt-0.5">▸</span>
                  <code className="text-zinc-300 font-mono text-[11px] leading-relaxed break-all">{a}</code>
                </li>
              ))}
            </ul>
          </div>
          <div className="px-4 py-3 space-y-1">
            <div className="flex items-center gap-1.5 text-[10px] font-semibold text-yellow-400/80 uppercase tracking-wider">
              <Flag size={10} /> Flag Locations
            </div>
            {s.flag_hints.map((h, i) => (
              <p key={i} className="text-xs text-yellow-300/80 flex items-start gap-2">
                <span className="shrink-0">🚩</span>
                <code className="font-mono text-[11px]">{h}</code>
              </p>
            ))}
          </div>
          <div className="px-4 py-2 flex items-center gap-2 flex-wrap">
            <Wrench size={10} className="text-zinc-500 shrink-0" />
            {s.tools.map((t, i) => (
              <span key={i} className="text-[10px] px-1.5 py-0.5 bg-bg-base border border-bg-border rounded text-zinc-400 font-mono">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Scan history row ───────────────────────────────────────────────────────

function ScanRow({ scan, isSelected, onSelect }: {
  scan: CTFScan; isSelected: boolean; onSelect: () => void
}) {
  const qc = useQueryClient()
  const del = useMutation({
    mutationFn: () => ctfApi.deleteScan(scan.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ctf-scans'] }),
  })

  const isRunning = scan.status === 'running'
  const isError   = scan.status === 'error'
  const strixCount = scan.strix_scan_ids?.length ?? 0
  const ports      = scan.ports_found ?? scan.open_ports?.length ?? 0

  return (
    <div
      className={clsx(
        'px-3 py-2.5 rounded-lg border cursor-pointer transition-colors',
        isSelected ? 'border-accent/50 bg-accent/5' : 'border-bg-border bg-bg-surface hover:bg-bg-elevated',
      )}
      onClick={onSelect}
    >
      {/* Row 1: status + target + delete */}
      <div className="flex items-center gap-2">
        <span className={clsx(
          'shrink-0',
          isRunning ? 'text-blue-400' : isError ? 'text-red-400' : 'text-green-400',
        )}>
          {isRunning
            ? <Loader2 size={10} className="animate-spin" />
            : isError
              ? <XCircle size={10} />
              : <CheckCircle2 size={10} />}
        </span>
        <span className="text-xs font-mono text-zinc-200 flex-1 truncate">{scan.target}</span>
        {!isRunning && (
          <button
            onClick={(e) => { e.stopPropagation(); del.mutate() }}
            disabled={del.isPending}
            aria-label={`Delete scan for ${scan.target}`}
            className="shrink-0 text-zinc-600 hover:text-red-400 disabled:opacity-40 transition-colors"
          >
            <Trash2 size={11} />
          </button>
        )}
      </div>

      {/* Row 2: metadata */}
      <div className="flex items-center gap-2 mt-1 pl-4">
        <span className="text-[10px] text-zinc-600">{ports} ports</span>
        {strixCount > 0 && (
          <>
            <span className="text-[10px] text-zinc-700">·</span>
            <span className="text-[10px] text-blue-400/80">{strixCount} Strix</span>
          </>
        )}
        {isRunning && (
          <>
            <span className="text-[10px] text-zinc-700">·</span>
            <span className="text-[10px] text-blue-400 animate-pulse capitalize">{scan.phase.replace(/_/g, ' ')}</span>
          </>
        )}
        {!isRunning && (scan.started_at || scan.completed_at) && (
          <>
            <span className="text-[10px] text-zinc-700">·</span>
            <span className="text-[10px] text-zinc-600">{timeAgo(scan.completed_at ?? scan.started_at)}</span>
          </>
        )}
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function CTFPage() {
  const qc = useQueryClient()
  const [target,      setTarget]      = useState('')
  const [ports,       setPorts]       = useState('common')
  const [speed,       setSpeed]       = useState(4)
  const [launchStrix, setLaunchStrix] = useState(true)
  const [strixMode,   setStrixMode]   = useState<'quick' | 'standard' | 'deep'>('deep')
  const [vulnScripts, setVulnScripts] = useState(false)
  const [advanced,    setAdvanced]    = useState(false)
  const [selectedId,  setSelectedId]  = useState<number | null>(null)
  const [showFull,    setShowFull]    = useState(false)

  const { data: nmapStatus } = useQuery({
    queryKey: ['ctf-nmap-status'],
    queryFn: ctfApi.nmapStatus,
    refetchInterval: 30_000,
  })

  const { data: scans = [] } = useQuery({
    queryKey: ['ctf-scans'],
    queryFn: ctfApi.listScans,
    refetchInterval: (q) => {
      const data = q.state.data as CTFScan[] | undefined
      return data?.some((s) => s.status === 'running') ? 2500 : false
    },
  })

  const { data: selected } = useQuery({
    queryKey: ['ctf-scan', selectedId],
    queryFn: () => ctfApi.getScan(selectedId!),
    enabled: selectedId !== null,
    refetchInterval: (q) => {
      const d = q.state.data as CTFScan | undefined
      return d?.status === 'running' ? 2000 : false
    },
  })

  const launch = useMutation({
    mutationFn: () =>
      ctfApi.startScan({ target: target.trim(), ports, scan_speed: speed, launch_strix: launchStrix, strix_mode: strixMode, run_vuln_scripts: vulnScripts }),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['ctf-scans'] })
      setSelectedId(data.id)
      setShowFull(false)
    },
  })

  const clearAll = useMutation({
    mutationFn: () => ctfApi.clearAll(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ctf-scans'] })
      setSelectedId(null)
    },
  })

  const PORT_PRESETS = [
    { value: 'common', label: 'Top 1000' },
    { value: 'full',   label: '1–65535'  },
    { value: '1-1000', label: '1–1000'   },
  ]

  return (
    <div className="flex h-full overflow-hidden">

      {/* ── Left: launch + history ──────────────────────────────────────── */}
      <div className="w-72 shrink-0 border-r border-bg-border flex flex-col bg-bg-surface overflow-auto">

        <div className="p-4 border-b border-bg-border">
          <div className="flex items-center gap-2 mb-1">
            <Flag size={15} className="text-accent" />
            <h2 className="text-sm font-semibold text-zinc-200">CTF Mode</h2>
          </div>
          <p className="text-[10px] text-zinc-600 leading-relaxed">
            Enter a target IP — full port scan, AI-assisted scope, and automated Strix exploitation.
          </p>
        </div>

        {/* nmap indicator */}
        {nmapStatus && (
          <div className={clsx(
            'mx-4 mt-3 flex items-center gap-2 text-xs px-2.5 py-1.5 rounded border',
            nmapStatus.available
              ? 'bg-green-500/10 border-green-500/30 text-green-400'
              : 'bg-red-500/10 border-red-500/30 text-red-400',
          )}>
            {nmapStatus.available ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
            {nmapStatus.available ? 'nmap ready' : 'nmap not found'}
          </div>
        )}

        {/* Launch form */}
        <div className="p-4 border-b border-bg-border space-y-3">
          <div>
            <label className="block text-[10px] text-zinc-500 mb-1">Target IP / Hostname</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-2.5 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent font-mono"
              placeholder="10.10.10.1 or target.htb"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && target.trim() && launch.mutate()}
            />
          </div>

          <div>
            <label className="block text-[10px] text-zinc-500 mb-1.5">Port Range</label>
            <div className="flex gap-1">
              {PORT_PRESETS.map((p) => (
                <button key={p.value} onClick={() => setPorts(p.value)}
                  className={clsx(
                    'flex-1 py-1 text-[10px] rounded border transition-colors',
                    ports === p.value ? 'border-accent bg-accent/10 text-accent' : 'border-bg-border text-zinc-500 hover:text-zinc-300',
                  )}>
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <label className="flex items-center gap-2 text-[10px] text-zinc-400 cursor-pointer">
            <input type="checkbox" checked={launchStrix} onChange={(e) => setLaunchStrix(e.target.checked)} className="accent-accent" />
            Auto-launch Strix on web services
          </label>

          <button onClick={() => setAdvanced((v) => !v)} className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300">
            <Settings2 size={10} />
            {advanced ? 'Hide' : 'Show'} advanced
          </button>

          {advanced && (
            <div className="space-y-2 border-t border-bg-border pt-2">
              <div>
                <label htmlFor="nmap-speed" className="block text-[10px] text-zinc-500 mb-1">Nmap Speed (-T{speed})</label>
                <input id="nmap-speed" type="range" min={1} max={5} step={1} value={speed}
                  onChange={(e) => setSpeed(Number(e.target.value))}
                  className="w-full accent-accent" />
                <div className="flex justify-between text-[9px] text-zinc-600 mt-0.5">
                  <span>Sneaky</span><span>Normal</span><span>Insane</span>
                </div>
              </div>
              {launchStrix && (
                <div>
                  <label className="block text-[10px] text-zinc-500 mb-1.5">Strix Mode</label>
                  <div className="flex gap-1">
                    {(['quick', 'standard', 'deep'] as const).map((m) => (
                      <button key={m} onClick={() => setStrixMode(m)}
                        className={clsx('flex-1 py-1 text-[10px] rounded border transition-colors capitalize',
                          strixMode === m ? 'border-accent bg-accent/10 text-accent' : 'border-bg-border text-zinc-500 hover:text-zinc-300')}>
                        {m}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              <label className="flex items-center gap-2 text-[10px] text-zinc-400 cursor-pointer">
                <input type="checkbox" checked={vulnScripts} onChange={(e) => setVulnScripts(e.target.checked)} className="accent-accent" />
                Run nmap vuln scripts (slower)
              </label>
            </div>
          )}

          <button
            onClick={() => launch.mutate()}
            disabled={launch.isPending || !target.trim() || !nmapStatus?.available}
            className="w-full flex items-center justify-center gap-2 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors"
          >
            {launch.isPending ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
            {launch.isPending ? 'Launching…' : 'Launch CTF Scan'}
          </button>

          {!nmapStatus?.available && nmapStatus && (
            <p className="text-[10px] text-red-400 text-center">{nmapStatus.hint}</p>
          )}
          {launch.isError && (
            <p className="text-[10px] text-red-400">{(launch.error as Error).message}</p>
          )}
        </div>

        {/* History header */}
        <div className="px-3 pt-3 pb-1.5 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-1.5 text-[10px] font-semibold text-zinc-500 uppercase tracking-wider">
            <History size={10} />
            Scan History
            {scans.length > 0 && (
              <span className="font-normal text-zinc-600 lowercase">({scans.length})</span>
            )}
          </div>
          {scans.length > 0 && !scans.some((s) => s.status === 'running') && (
            <button
              onClick={() => clearAll.mutate()}
              disabled={clearAll.isPending}
              className="text-[10px] text-zinc-600 hover:text-red-400 disabled:opacity-40 transition-colors"
            >
              {clearAll.isPending ? 'Clearing…' : 'Clear all'}
            </button>
          )}
        </div>

        {/* History list */}
        <div className="flex-1 overflow-auto px-3 pb-3 space-y-1.5">
          {scans.length === 0 && (
            <div className="flex flex-col items-center gap-2 pt-6 text-zinc-700">
              <Shield size={22} strokeWidth={1} />
              <p className="text-[10px] text-center leading-relaxed">
                No scans yet.<br />Enter a target above to start.
              </p>
            </div>
          )}
          {scans.map((s) => (
            <ScanRow key={s.id} scan={s} isSelected={selectedId === s.id}
              onSelect={() => { setSelectedId(s.id); setShowFull(false) }} />
          ))}
        </div>
      </div>

      {/* ── Right: phase timeline + results ─────────────────────────────── */}
      <div className="flex-1 overflow-auto p-6">
        {!selectedId ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 text-zinc-600">
            <Flag size={40} strokeWidth={1} />
            <div className="text-center">
              <p className="text-sm text-zinc-400 mb-1">Enter a target IP to begin</p>
              <p className="text-xs text-zinc-600 max-w-xs leading-relaxed">
                BluJay runs nmap, builds an AI-assisted attack scope, and launches Strix on any web services found.
              </p>
            </div>
          </div>
        ) : !selected ? (
          <div className="flex items-center justify-center h-full">
            <Loader2 size={24} className="animate-spin text-accent" />
          </div>
        ) : (
          <div className="max-w-3xl space-y-6">

            {/* Header */}
            <div className="flex items-center gap-3">
              <Target size={18} className="text-accent shrink-0" />
              <h1 className="text-base font-semibold text-zinc-100 font-mono">{selected.target}</h1>
              <span className={clsx('ml-auto text-[10px] px-2.5 py-1 rounded-full border font-medium',
                selected.status === 'running'  ? 'border-blue-500/40 bg-blue-500/10 text-blue-400' :
                selected.status === 'complete' ? 'border-green-500/40 bg-green-500/10 text-green-400' :
                selected.status === 'error'    ? 'border-red-500/40 bg-red-500/10 text-red-400' :
                                                 'border-bg-border text-zinc-500'
              )}>
                {selected.status.toUpperCase()}
              </span>
            </div>

            {/* Error banner */}
            {selected.error && (
              <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400">
                <AlertTriangle size={13} className="mt-0.5 shrink-0" />
                {selected.error}
              </div>
            )}

            {/* ── Phase timeline ────────────────────────────────────────── */}
            <div className="bg-bg-surface border border-bg-border rounded-xl p-5">
              <PhaseStep
                label="Port Discovery"
                sublabel="nmap -sV — discovering open ports and services"
                icon={Network}
                state={stepState(selected, 'port_discovery')}
              >
                <PortTable scan={selected} />
              </PhaseStep>

              <PhaseStep
                label="Build Scope"
                sublabel="Rule-based attack vectors + metatron-qwen AI analysis"
                icon={Brain}
                state={stepState(selected, 'scope_analysis')}
              >
                <AIAnalysis scan={selected} />
              </PhaseStep>

              <PhaseStep
                label="Strix Integration"
                sublabel="Automated web exploitation agent launched on HTTP/HTTPS services"
                icon={Radar}
                state={stepState(selected, 'strix_integration')}
              >
                <StrixPanel scan={selected} />
              </PhaseStep>

              <PhaseStep
                label="Complete"
                sublabel="Full attack surface map ready"
                icon={Trophy}
                state={stepState(selected, 'complete')}
                isLast
              >
                <CompleteSummary scan={selected} />
              </PhaseStep>
            </div>

            {/* ── Full attack surface (complete only) ───────────────────── */}
            {selected.status === 'complete' && selected.scope.length > 0 && (
              <div className="space-y-3">
                <button
                  onClick={() => setShowFull((v) => !v)}
                  className="w-full flex items-center justify-between px-4 py-2.5 bg-bg-surface border border-bg-border rounded-lg hover:bg-bg-elevated transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <Lightbulb size={14} className="text-yellow-400" />
                    <span className="text-sm font-medium text-zinc-200">Full Attack Surface</span>
                    <span className="text-[10px] text-zinc-500">{selected.scope.length} services</span>
                  </div>
                  {showFull ? <ChevronDown size={14} className="text-zinc-500" /> : <ChevronRight size={14} className="text-zinc-500" />}
                </button>

                {showFull && (
                  <div className="space-y-4">
                    {/* Strategy */}
                    {selected.overall_strategy.length > 0 && (
                      <div className="rounded-lg border border-bg-border overflow-hidden">
                        <div className="px-4 py-2 bg-bg-elevated border-b border-bg-border text-[10px] font-semibold text-zinc-400 uppercase tracking-wider">
                          Attack Strategy
                        </div>
                        <ol className="divide-y divide-bg-border/50 bg-bg-surface">
                          {selected.overall_strategy.map((step, i) => (
                            <li key={i} className="flex items-start gap-3 px-4 py-2">
                              <span className="text-[10px] text-zinc-600 shrink-0 mt-0.5 w-4 text-right">{i + 1}.</span>
                              <code className="text-xs text-zinc-300 font-mono leading-relaxed break-all">{step}</code>
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}

                    {/* Service cards */}
                    <div className="space-y-1.5">
                      {[
                        ...selected.scope.filter((s) => s.severity === 'CRITICAL' || s.severity === 'HIGH'),
                        ...selected.scope.filter((s) => s.severity !== 'CRITICAL' && s.severity !== 'HIGH'),
                      ].map((s) => (
                        <ScopeCard key={s.port} s={s} target={selected.target} />
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

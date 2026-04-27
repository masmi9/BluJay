import { useCallback, useEffect, useRef, useState } from 'react'
import { clsx } from 'clsx'
import type { LucideIcon } from 'lucide-react'
import {
  Activity, AlertTriangle, BarChart2, Check, ChevronRight,
  CreditCard, Download, FileCode, FileText, Globe, Layers,
  Lock, Network, Play, RefreshCw, Server, Shield, Terminal, Trash2, X,
} from 'lucide-react'
import { pciApi } from '@/api/pci'
import type { ScopeValidation } from '@/api/pci'
import type { PciFinding, PciScanJob, PciSeverity, PaymentFlowResult } from '@/types/pci'
import {
  EXAMPLE_SCOPE_YAML, PCI_CATEGORY_LABEL, PCI_SEVERITY_COLOR,
  PCI_SEVERITY_ORDER, SCAN_PHASES, TIKTOK_PRESETS,
} from '@/types/pci'

// ── Types / constants ─────────────────────────────────────────────────────────

type PageTab = 'scope' | 'dashboard' | 'findings' | 'flows' | 'reports'
type ScanMode = 'web_only' | 'external_pci' | 'full_cde'

const SCAN_MODES: { id: ScanMode; label: string; desc: string; Icon: LucideIcon }[] = [
  {
    id: 'web_only',
    label: 'Web Only',
    desc: 'TLS, headers, cookies, card data, processor fingerprinting. Fastest — no port scanning.',
    Icon: Globe,
  },
  {
    id: 'external_pci',
    label: 'External PCI',
    desc: 'Full external PCI DSS v4.0 — host discovery, port scan, vulns, web checks, malware.',
    Icon: Shield,
  },
  {
    id: 'full_cde',
    label: 'Full CDE',
    desc: 'Comprehensive CDE sweep including internal IP ranges. Most thorough assessment.',
    Icon: Network,
  },
]

const SEV_ORDER: PciSeverity[] = ['critical', 'high', 'medium', 'low', 'info']

// ── Shared micro-components ───────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: PciSeverity }) {
  return (
    <span className={clsx('px-1.5 py-0.5 text-[10px] rounded border font-medium capitalize shrink-0', PCI_SEVERITY_COLOR[severity])}>
      {severity}
    </span>
  )
}

function CategoryTag({ category }: { category: string }) {
  return (
    <span className="px-1.5 py-0.5 text-[10px] rounded bg-bg-elevated text-zinc-400 font-mono shrink-0">
      {PCI_CATEGORY_LABEL[category] ?? category}
    </span>
  )
}

function PciReqBadge({ req }: { req: string | null }) {
  if (!req) return null
  return (
    <span className="px-1.5 py-0.5 text-[10px] rounded bg-accent/10 text-accent border border-accent/20 font-mono shrink-0">
      PCI {req}
    </span>
  )
}

// ── Finding detail panel ──────────────────────────────────────────────────────

function FindingDetail({ finding, onClose }: { finding: PciFinding; onClose: () => void }) {
  let cveIds: string[] = []
  try { if (finding.cve_ids) cveIds = JSON.parse(finding.cve_ids) } catch { /* */ }

  return (
    <div className="flex flex-col h-full bg-bg-surface border-l border-bg-border overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 border-b border-bg-border shrink-0">
        <p className="text-[11px] font-semibold text-zinc-300">Finding Detail</p>
        <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300 transition-colors">
          <X size={14} />
        </button>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-4 text-xs">
        <div className="flex flex-wrap items-start gap-2">
          <SeverityBadge severity={finding.severity} />
          <CategoryTag category={finding.category} />
          <PciReqBadge req={finding.pci_req} />
          {finding.phase && (
            <span className="px-1.5 py-0.5 text-[10px] rounded bg-zinc-800 text-zinc-400 font-mono shrink-0">
              {finding.phase}
            </span>
          )}
        </div>

        <h2 className="text-sm font-semibold text-zinc-100 leading-snug">{finding.title}</h2>

        <div className="space-y-3">
          <DetailRow label="URL" value={finding.url} mono />
          <DetailRow label="Host" value={finding.host} mono />
          {finding.port != null && (
            <DetailRow
              label="Port / Service"
              value={`${finding.port}${finding.service ? ` (${finding.service})` : ''}`}
              mono
            />
          )}
          {finding.cvss_score != null && (
            <DetailRow label="CVSS Score" value={finding.cvss_score.toFixed(1)} />
          )}
          {cveIds.length > 0 && (
            <div>
              <p className="text-zinc-600 uppercase tracking-wide mb-1">CVE IDs</p>
              <div className="flex flex-wrap gap-1">
                {cveIds.map((cve) => (
                  <span key={cve} className="px-1.5 py-0.5 text-[10px] rounded bg-red-500/10 text-red-400 border border-red-500/20 font-mono">
                    {cve}
                  </span>
                ))}
              </div>
            </div>
          )}
          {finding.plugin_id && <DetailRow label="Plugin ID" value={finding.plugin_id} mono />}
          <DetailRow label="Detail" value={finding.detail} />
          {finding.evidence && (
            <div>
              <p className="text-zinc-600 uppercase tracking-wide mb-1">Evidence</p>
              <pre className="bg-bg-elevated rounded p-2 text-zinc-300 whitespace-pre-wrap break-all font-mono text-[11px] max-h-40 overflow-auto">
                {finding.evidence}
              </pre>
            </div>
          )}
          {finding.remediation && <DetailRow label="Remediation" value={finding.remediation} />}
        </div>
      </div>
    </div>
  )
}

function DetailRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-zinc-600 uppercase tracking-wide mb-0.5 text-[10px]">{label}</p>
      <p className={clsx('text-zinc-300 leading-relaxed break-all text-xs', mono && 'font-mono')}>{value}</p>
    </div>
  )
}

// ── Scope tab ─────────────────────────────────────────────────────────────────

interface ScopeTabProps {
  scanMode: ScanMode
  setScanMode: (m: ScanMode) => void
  urlInput: string
  setUrlInput: (v: string) => void
  scopeYaml: string
  setScopeYaml: (v: string) => void
  validation: ScopeValidation | null
  validating: boolean
  onValidate: () => void
  onStart: () => void
  onCancel: () => void
  loading: boolean
  isRunning: boolean
  error: string | null
  jobs: PciScanJob[]
  onLoadJob: (job: PciScanJob) => void
  onDeleteJob: (job: PciScanJob) => void
  activeJobId: number | undefined
}

function ScopeTab({
  scanMode, setScanMode, urlInput, setUrlInput,
  scopeYaml, setScopeYaml, validation, validating,
  onValidate, onStart, onCancel, loading, isRunning,
  error, jobs, onLoadJob, onDeleteJob, activeJobId,
}: ScopeTabProps) {
  const addPreset = (url: string) => {
    const existing = urlInput.split('\n').map((u) => u.trim()).filter(Boolean)
    if (!existing.includes(url)) {
      setUrlInput(urlInput.trim() ? `${urlInput.trim()}\n${url}` : url)
    }
  }

  return (
    <div className="flex flex-1 overflow-hidden">
      {/* Config area */}
      <div className="flex-1 flex flex-col overflow-auto p-4 space-y-4 min-w-0">

        {/* Scan profile selector */}
        <div>
          <p className="text-[10px] text-zinc-500 uppercase tracking-wide mb-2">Scan Profile</p>
          <div className="grid grid-cols-3 gap-2">
            {SCAN_MODES.map(({ id, label, desc, Icon }) => (
              <button
                key={id}
                onClick={() => setScanMode(id)}
                className={clsx(
                  'text-left p-3 rounded border transition-colors',
                  scanMode === id
                    ? 'border-accent bg-accent/10 text-zinc-100'
                    : 'border-bg-border bg-bg-elevated text-zinc-400 hover:border-zinc-600 hover:text-zinc-200',
                )}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Icon size={13} className={scanMode === id ? 'text-accent' : 'text-zinc-500'} />
                  <span className="text-xs font-semibold">{label}</span>
                </div>
                <p className="text-[10px] leading-snug">{desc}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Input: simple URL list or YAML editor */}
        {scanMode === 'web_only' ? (
          <div className="space-y-2">
            <p className="text-[10px] text-zinc-500 uppercase tracking-wide">Target URLs (one per line)</p>
            <textarea
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder={'https://ads.tiktok.com\nhttps://checkout.example.com'}
              rows={6}
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs font-mono text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-accent resize-none"
            />
            <div>
              <p className="text-[10px] text-zinc-600 uppercase tracking-wide mb-1.5">Quick Add</p>
              <div className="flex flex-wrap gap-1">
                {TIKTOK_PRESETS.map(({ label, url }) => (
                  <button
                    key={url}
                    onClick={() => addPreset(url)}
                    className="px-2 py-0.5 text-[10px] rounded border border-zinc-700 text-zinc-400 hover:border-accent hover:text-accent transition-colors"
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <p className="text-[10px] text-zinc-500 uppercase tracking-wide">Scope Config (YAML or JSON)</p>
              <button
                onClick={() => setScopeYaml(EXAMPLE_SCOPE_YAML)}
                className="text-[10px] text-accent hover:text-accent/80 transition-colors"
              >
                Load TikTok Example
              </button>
            </div>
            <textarea
              value={scopeYaml}
              onChange={(e) => setScopeYaml(e.target.value)}
              rows={14}
              spellCheck={false}
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs font-mono text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-accent resize-y"
            />
            <div className="flex items-center gap-3 flex-wrap">
              <button
                onClick={onValidate}
                disabled={validating}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-zinc-600 text-zinc-300 hover:border-zinc-400 hover:text-zinc-100 text-xs transition-colors disabled:opacity-50"
              >
                {validating
                  ? <RefreshCw size={11} className="animate-spin" />
                  : <Check size={11} />}
                {validating ? 'Validating…' : 'Validate Scope'}
              </button>
              {validation && (
                validation.valid ? (
                  <span className="text-[11px] text-green-400 flex items-center gap-1">
                    <Check size={12} />
                    {validation.name} — {validation.target_count} target{validation.target_count === 1 ? '' : 's'}
                  </span>
                ) : (
                  <span className="text-[11px] text-red-400 flex items-center gap-1">
                    <X size={12} />
                    {validation.error}
                  </span>
                )
              )}
            </div>
          </div>
        )}

        {error && <p className="text-[11px] text-red-400">{error}</p>}

        <div className="flex gap-2">
          <button
            onClick={onStart}
            disabled={loading || isRunning}
            className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors"
          >
            <Play size={12} />
            {loading ? 'Starting…' : isRunning ? 'Scanning…' : 'Start Scan'}
          </button>
          {isRunning && (
            <button
              onClick={onCancel}
              className="flex items-center gap-1.5 px-3 py-2 rounded border border-red-500/40 text-red-400 hover:bg-red-500/10 text-xs transition-colors"
            >
              <X size={12} />
              Cancel
            </button>
          )}
        </div>
      </div>

      {/* Recent scans sidebar */}
      <div className="w-60 border-l border-bg-border flex flex-col overflow-hidden shrink-0">
        <div className="px-3 py-2 border-b border-bg-border shrink-0">
          <p className="text-[10px] text-zinc-500 uppercase tracking-wide">Recent Scans</p>
        </div>
        <div className="flex-1 overflow-auto">
          {jobs.length === 0 ? (
            <div className="flex items-center justify-center h-16 text-[11px] text-zinc-600">No scans yet</div>
          ) : (
            jobs.slice(0, 20).map((job) => (
              <div
                key={job.id}
                className={clsx(
                  'group flex items-stretch border-b border-bg-border/50 transition-colors',
                  activeJobId === job.id
                    ? 'bg-accent/10'
                    : 'hover:bg-bg-elevated',
                )}
              >
                <button
                  onClick={() => onLoadJob(job)}
                  className={clsx(
                    'flex-1 text-left px-3 py-2 min-w-0',
                    activeJobId === job.id ? 'text-zinc-200' : 'text-zinc-400 hover:text-zinc-200',
                  )}
                >
                  <div className="flex items-center justify-between gap-1 mb-0.5">
                    <span className="truncate font-mono text-[10px]">{job.target_urls[0]}</span>
                    <span className={clsx('text-[10px] shrink-0',
                      job.status === 'done'  ? 'text-green-400' :
                      job.status === 'error' ? 'text-red-400' : 'text-accent'
                    )}>
                      {job.status}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 text-zinc-600 text-[10px]">
                    <span>{job.scan_profile}</span>
                    <span>·</span>
                    <span>{job.finding_count} findings</span>
                  </div>
                </button>
                <button
                  onClick={(e) => { e.stopPropagation(); onDeleteJob(job) }}
                  title="Delete scan"
                  className="px-2 opacity-0 group-hover:opacity-100 text-zinc-600 hover:text-red-400 transition-all shrink-0"
                >
                  <Trash2 size={11} />
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

// ── Dashboard tab ─────────────────────────────────────────────────────────────

function DashboardTab({ job, findings }: { job: PciScanJob | null; findings: PciFinding[] }) {
  if (!job) {
    return (
      <div className="flex flex-col items-center justify-center flex-1 gap-3 text-zinc-600">
        <Activity size={32} strokeWidth={1} />
        <p className="text-sm">Start a scan from the Scope tab</p>
      </div>
    )
  }

  const currentPhaseIdx = SCAN_PHASES.findIndex((p) => p.id === job.phase)

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">

      {/* Status banner */}
      <div className={clsx('flex items-center gap-3 px-4 py-3 rounded border text-sm',
        job.status === 'done'  ? 'bg-green-500/10 border-green-500/20 text-green-400' :
        job.status === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-400' :
        'bg-accent/10 border-accent/20 text-accent'
      )}>
        {(job.status === 'pending' || job.status === 'running') && (
          <RefreshCw size={14} className="animate-spin shrink-0" />
        )}
        {job.status === 'done'  && <Check size={14} className="shrink-0" />}
        {job.status === 'error' && <X size={14} className="shrink-0" />}
        <span className="font-medium">
          {job.status === 'pending' && 'Queued — waiting to start'}
          {job.status === 'running' && `Running — ${job.phase ?? 'initializing'}…`}
          {job.status === 'done'    && `Completed — ${job.finding_count} findings`}
          {job.status === 'error'   && (job.error ?? 'Scan error')}
        </span>
        <span className="ml-auto text-[11px] opacity-60 font-mono shrink-0">{job.scan_profile}</span>
      </div>

      {/* Phase stepper */}
      <div>
        <p className="text-[10px] text-zinc-500 uppercase tracking-wide mb-3">Scan Phases</p>
        <div className="flex items-center overflow-x-auto pb-2">
          {SCAN_PHASES.map((phase, idx) => {
            const isDone   = job.status === 'done' || (currentPhaseIdx > idx && currentPhaseIdx !== -1)
            const isActive = job.phase === phase.id
            return (
              <div key={phase.id} className="flex items-center shrink-0">
                <div className="flex flex-col items-center gap-1 px-1.5">
                  <div className={clsx(
                    'w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold border-2 transition-colors',
                    isDone   ? 'bg-green-500/20 border-green-500 text-green-400' :
                    isActive ? 'bg-accent/20 border-accent text-accent' :
                    'bg-bg-elevated border-zinc-700 text-zinc-600',
                  )}>
                    {isDone ? <Check size={10} /> : idx + 1}
                  </div>
                  <span className={clsx('text-[9px] whitespace-nowrap',
                    isDone   ? 'text-green-400' :
                    isActive ? 'text-accent' : 'text-zinc-600',
                  )}>
                    {phase.label}
                  </span>
                </div>
                {idx < SCAN_PHASES.length - 1 && (
                  <div className={clsx('w-4 h-0.5 shrink-0 mb-3.5',
                    isDone ? 'bg-green-500/30' : 'bg-zinc-800',
                  )} />
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Findings',     value: job.finding_count, Icon: AlertTriangle, color: 'text-yellow-400' },
          { label: 'Hosts Found',  value: job.hosts_found,   Icon: Server,        color: 'text-blue-400'   },
          { label: 'Ports Open',   value: job.ports_open,    Icon: Network,       color: 'text-purple-400' },
          { label: 'Pages Crawled',value: job.pages_crawled, Icon: Globe,         color: 'text-green-400'  },
        ].map(({ label, value, Icon, color }) => (
          <div key={label} className="bg-bg-elevated border border-bg-border rounded p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <Icon size={12} className={color} />
              <span className="text-[10px] text-zinc-500 uppercase tracking-wide">{label}</span>
            </div>
            <span className="text-2xl font-bold text-zinc-100">{value}</span>
          </div>
        ))}
      </div>

      {/* Severity breakdown */}
      {findings.length > 0 && (
        <div>
          <p className="text-[10px] text-zinc-500 uppercase tracking-wide mb-2">Severity Breakdown</p>
          <div className="space-y-2">
            {SEV_ORDER.map((sev) => {
              const count = findings.filter((f) => f.severity === sev).length
              if (!count) return null
              const pct = Math.round((count / findings.length) * 100)
              return (
                <div key={sev} className="flex items-center gap-3 text-xs">
                  <span className={clsx('capitalize w-14 font-medium shrink-0', PCI_SEVERITY_COLOR[sev].split(' ')[0])}>
                    {sev}
                  </span>
                  <div className="flex-1 bg-bg-elevated rounded-full h-1.5">
                    <div
                      className={clsx('h-1.5 rounded-full transition-all', {
                        'bg-red-500':    sev === 'critical',
                        'bg-orange-500': sev === 'high',
                        'bg-yellow-500': sev === 'medium',
                        'bg-blue-500':   sev === 'low',
                        'bg-zinc-500':   sev === 'info',
                      })}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-zinc-400 font-mono w-5 text-right shrink-0">{count}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Payment processors */}
      {job.processors_detected.length > 0 && (
        <div>
          <p className="text-[10px] text-zinc-500 uppercase tracking-wide mb-2">Payment Processors Detected</p>
          <div className="flex flex-wrap gap-2">
            {job.processors_detected.map((p) => (
              <span key={p} className="px-2.5 py-1 text-xs rounded bg-accent/10 text-accent border border-accent/20 font-medium">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Findings tab ──────────────────────────────────────────────────────────────

interface FindingsTabProps {
  findings: PciFinding[]
  selectedFinding: PciFinding | null
  setSelectedFinding: (f: PciFinding | null) => void
  categoryFilter: string
  setCategoryFilter: (c: string) => void
  severityFilter: PciSeverity | 'all'
  setSeverityFilter: (s: PciSeverity | 'all') => void
}

function FindingsTab({
  findings, selectedFinding, setSelectedFinding,
  categoryFilter, setCategoryFilter,
  severityFilter, setSeverityFilter,
}: FindingsTabProps) {
  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center flex-1 gap-3 text-zinc-600">
        <Shield size={32} strokeWidth={1} />
        <p className="text-sm">No findings yet — run a scan from the Scope tab</p>
        <div className="flex flex-wrap justify-center gap-2 mt-1">
          {[
            { Icon: Lock,     text: 'TLS & Certificate'       },
            { Icon: Globe,    text: 'Security Headers'         },
            { Icon: Terminal, text: 'Card Data Exposure'       },
            { Icon: CreditCard, text: 'Processor Fingerprint' },
          ].map(({ Icon, text }) => (
            <div key={text} className="flex items-center gap-1.5 text-[11px] px-2 py-1 rounded border border-bg-border text-zinc-500">
              <Icon size={11} />
              {text}
            </div>
          ))}
        </div>
      </div>
    )
  }

  const categories = ['all', ...Array.from(new Set(findings.map((f) => f.category)))]
  const displayed = findings.filter((f) => {
    if (categoryFilter !== 'all' && f.category !== categoryFilter) return false
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false
    return true
  })

  return (
    <div className="flex flex-1 overflow-hidden">
      <div className="flex flex-col flex-1 overflow-hidden min-w-0">

        {/* Filter bar */}
        <div className="flex items-center gap-2 px-3 py-2 border-b border-bg-border shrink-0 overflow-x-auto">
          {/* Severity chips */}
          <div className="flex gap-1 shrink-0">
            <button
              onClick={() => setSeverityFilter('all')}
              className={clsx(
                'px-2 py-0.5 text-[10px] rounded border transition-colors',
                severityFilter === 'all'
                  ? 'border-zinc-500 text-zinc-200 bg-zinc-700/30'
                  : 'border-transparent text-zinc-500 hover:text-zinc-300',
              )}
            >
              All ({findings.length})
            </button>
            {SEV_ORDER.filter((s) => findings.some((f) => f.severity === s)).map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={clsx(
                  'px-2 py-0.5 text-[10px] rounded border transition-colors capitalize',
                  severityFilter === s ? PCI_SEVERITY_COLOR[s] : 'border-transparent text-zinc-500 hover:text-zinc-300',
                )}
              >
                {s} ({findings.filter((f) => f.severity === s).length})
              </button>
            ))}
          </div>

          <div className="w-px h-4 bg-bg-border shrink-0" />

          {/* Category tabs */}
          <div className="flex overflow-x-auto">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => { setCategoryFilter(cat); setSelectedFinding(null) }}
                className={clsx(
                  'px-3 py-1 text-[10px] font-medium border-b-2 whitespace-nowrap transition-colors shrink-0',
                  categoryFilter === cat
                    ? 'border-accent text-zinc-100'
                    : 'border-transparent text-zinc-500 hover:text-zinc-300',
                )}
              >
                {cat === 'all'
                  ? 'All Categories'
                  : `${PCI_CATEGORY_LABEL[cat] ?? cat} (${findings.filter((f) => f.category === cat).length})`}
              </button>
            ))}
          </div>
        </div>

        {/* Findings list */}
        <div className="flex-1 overflow-auto">
          {displayed.length === 0 ? (
            <div className="flex items-center justify-center h-16 text-[11px] text-zinc-600">
              No findings match current filters
            </div>
          ) : (
            displayed.map((finding) => (
              <div
                key={finding.id}
                onClick={() => setSelectedFinding(finding)}
                className={clsx(
                  'flex items-center gap-2 px-3 py-2 text-xs cursor-pointer hover:bg-bg-elevated border-l-2 transition-colors',
                  selectedFinding?.id === finding.id
                    ? 'bg-accent/10 border-accent'
                    : 'border-transparent',
                )}
              >
                <SeverityBadge severity={finding.severity} />
                <CategoryTag category={finding.category} />
                <span className="text-zinc-200 flex-1 truncate min-w-0">{finding.title}</span>
                <span className="text-zinc-600 font-mono truncate max-w-[140px] shrink-0 text-[10px]">{finding.host}</span>
                {finding.port != null && (
                  <span className="text-zinc-500 font-mono text-[10px] shrink-0">:{finding.port}</span>
                )}
                {finding.cvss_score != null && (
                  <span className={clsx('text-[10px] font-mono shrink-0',
                    finding.cvss_score >= 9   ? 'text-red-400' :
                    finding.cvss_score >= 7   ? 'text-orange-400' :
                    finding.cvss_score >= 4   ? 'text-yellow-400' : 'text-zinc-400',
                  )}>
                    {finding.cvss_score.toFixed(1)}
                  </span>
                )}
                {finding.pci_req && (
                  <span className="text-[10px] text-accent font-mono shrink-0">{finding.pci_req}</span>
                )}
                <ChevronRight size={12} className="text-zinc-700 shrink-0" />
              </div>
            ))
          )}
        </div>
      </div>

      {/* Detail panel */}
      {selectedFinding && (
        <div className="w-80 shrink-0 overflow-hidden">
          <FindingDetail finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
        </div>
      )}
    </div>
  )
}

// ── Reports tab ───────────────────────────────────────────────────────────────

function ReportsTab({ job }: { job: PciScanJob | null }) {
  const [downloading, setDownloading] = useState<string | null>(null)

  const download = async (type: 'json' | 'executive' | 'technical') => {
    if (!job) return
    setDownloading(type)
    try {
      const blob = await pciApi.downloadReport(job.id, type)
      const ext  = type === 'json' ? 'json' : 'html'
      const name = `pci_${type}_${job.id}.${ext}`
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url
      a.download = name
      a.click()
      URL.revokeObjectURL(url)
    } catch { /* ignore */ } finally {
      setDownloading(null)
    }
  }

  if (!job || job.status !== 'done') {
    return (
      <div className="flex flex-col items-center justify-center flex-1 gap-3 text-zinc-600">
        <FileText size={32} strokeWidth={1} />
        <p className="text-sm">Reports are generated when a scan completes</p>
      </div>
    )
  }

  const REPORT_CARDS = [
    {
      type:  'json' as const,
      label: 'JSON Report',
      Icon:  FileCode,
      ext:   '.json',
      desc:  'Machine-readable findings with full evidence, CVE references, CVSS scores, and remediation data. Suitable for import into other tools or SIEM systems.',
    },
    {
      type:  'executive' as const,
      label: 'Executive Summary',
      Icon:  BarChart2,
      ext:   '.html',
      desc:  'Management-facing HTML report: severity overview, processor exposure, PCI DSS 12-requirement coverage matrix, top critical findings, and remediation priorities.',
    },
    {
      type:  'technical' as const,
      label: 'Technical Report',
      Icon:  Layers,
      ext:   '.html',
      desc:  'Full technical PCI report: all findings with raw evidence, CVE links, CVSS detail, port/service context, and per-finding remediation steps.',
    },
  ]

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="max-w-2xl space-y-4">
        <div className="mb-1">
          <p className="text-sm text-zinc-100 font-semibold">Scan Reports — Job #{job.id}</p>
          <p className="text-[11px] text-zinc-500 mt-0.5">
            {job.finding_count} findings · {job.target_urls[0]} · {job.scan_profile}
          </p>
        </div>

        {REPORT_CARDS.map(({ type, label, Icon, ext, desc }) => (
          <div key={type} className="flex items-start gap-4 p-4 rounded border border-bg-border bg-bg-elevated">
            <div className="p-2.5 rounded bg-bg-surface border border-bg-border shrink-0">
              <Icon size={20} className="text-accent" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-zinc-100">{label}</p>
              <p className="text-[11px] text-zinc-500 mt-1 leading-relaxed">{desc}</p>
              <p className="text-[10px] text-zinc-600 mt-1.5 font-mono">pci_{type}_{job.id}{ext}</p>
            </div>
            <button
              onClick={() => download(type)}
              disabled={!!downloading}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors shrink-0"
            >
              {downloading === type
                ? <RefreshCw size={12} className="animate-spin" />
                : <Download size={12} />}
              Download
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Payment Flows tab ─────────────────────────────────────────────────────────

interface PaymentFlowsTabProps {
  job: PciScanJob | null
  flows: PaymentFlowResult[]
  loading: boolean
  onLoad: () => void
}

function PaymentFlowsTab({ job, flows, loading, onLoad }: PaymentFlowsTabProps) {
  const [expandedStep, setExpandedStep] = useState<string | null>(null)

  if (!job) {
    return (
      <div className="flex flex-col items-center justify-center flex-1 gap-3 text-zinc-600">
        <CreditCard size={32} strokeWidth={1} />
        <p className="text-sm">Run a scan to test payment flows</p>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center flex-1 gap-2 text-zinc-500 text-sm">
        <RefreshCw size={14} className="animate-spin" />
        Loading flow data…
      </div>
    )
  }

  if (job.status !== 'done' && job.status !== 'error') {
    return (
      <div className="flex flex-col items-center justify-center flex-1 gap-3 text-zinc-600">
        <Activity size={32} strokeWidth={1} />
        <p className="text-sm">Payment flow results will appear when the scan completes</p>
      </div>
    )
  }

  if (flows.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center flex-1 gap-3 text-zinc-600">
        <CreditCard size={32} strokeWidth={1} />
        <p className="text-sm">No flow data available</p>
        <button onClick={onLoad} className="text-xs text-accent hover:text-accent/80 transition-colors">
          Load flow data
        </button>
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-auto p-4 space-y-5">
      {flows.map((flow, fi) => (
        <div key={fi} className="rounded border border-bg-border overflow-hidden">

          {/* Flow header */}
          <div className="flex items-center gap-3 px-4 py-2.5 bg-bg-elevated border-b border-bg-border">
            <div className={clsx(
              'w-2 h-2 rounded-full shrink-0',
              flow.reached_payment_form ? 'bg-green-500' :
              flow.error ? 'bg-red-500' : 'bg-zinc-600',
            )} />
            <span className="font-mono text-xs text-zinc-300 flex-1 truncate min-w-0">{flow.url}</span>
            {flow.processor && (
              <span className="px-2 py-0.5 text-[10px] rounded bg-accent/10 text-accent border border-accent/20 font-medium shrink-0">
                {flow.processor}
              </span>
            )}
            <span className={clsx(
              'text-[10px] font-medium shrink-0',
              flow.reached_payment_form ? 'text-green-400' :
              flow.error ? 'text-red-400' : 'text-zinc-500',
            )}>
              {flow.reached_payment_form ? 'Form reached' : flow.error ? 'Error' : 'Form not reached'}
            </span>
          </div>

          {/* Test card info */}
          {flow.test_card && (
            <div className="flex items-center gap-3 px-4 py-1.5 border-b border-bg-border text-[10px] text-zinc-500 bg-bg-surface/40">
              <CreditCard size={10} className="shrink-0 text-zinc-600" />
              <span className="font-mono">
                {flow.test_card.number.replace(/\d(?=\d{4})/g, '•').replace(/(.{4})/g, '$1 ').trim()}
              </span>
              <span className="text-zinc-700">|</span>
              <span className="font-mono">Exp {flow.test_card.exp}</span>
              <span className="text-zinc-700">|</span>
              <span className="font-mono">CVV {flow.test_card.cvv}</span>
              <span className="text-zinc-600 ml-1 italic">not submitted</span>
            </div>
          )}

          {/* Steps */}
          <div className="divide-y divide-bg-border/40">
            {flow.steps.map((step) => {
              const key = `${fi}-${step.step}`
              const expanded = expandedStep === key
              return (
                <div key={step.step}>
                  <button
                    onClick={() => setExpandedStep(expanded ? null : key)}
                    className="w-full flex items-center gap-3 px-4 py-2 hover:bg-bg-elevated/60 transition-colors text-left"
                  >
                    <span className="w-5 h-5 rounded-full bg-bg-elevated border border-bg-border text-[9px] font-bold text-zinc-500 flex items-center justify-center shrink-0">
                      {step.step}
                    </span>
                    <span className={clsx(
                      'text-[10px] px-1.5 py-0.5 rounded font-mono shrink-0',
                      step.action === 'test-card-filled'    ? 'bg-green-500/10 text-green-400 border border-green-500/20' :
                      step.action === 'payment-form-detected' ? 'bg-accent/10 text-accent border border-accent/20' :
                      step.action === 'flow-not-reached'    ? 'bg-zinc-800 text-zinc-500' :
                      step.action === 'click-checkout'      ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                      'bg-bg-elevated text-zinc-500 border border-bg-border',
                    )}>
                      {step.action}
                    </span>
                    <span className="text-xs text-zinc-300 flex-1 truncate min-w-0">{step.description}</span>
                    {step.screenshot_b64 && (
                      <span className="text-[10px] text-zinc-600 shrink-0">screenshot</span>
                    )}
                    <ChevronRight size={11} className={clsx(
                      'text-zinc-700 shrink-0 transition-transform',
                      expanded && 'rotate-90',
                    )} />
                  </button>

                  {expanded && (
                    <div className="px-12 pb-4 space-y-3 bg-bg-elevated/20">
                      {step.notes && (
                        <pre className="text-[11px] text-zinc-400 font-mono whitespace-pre-wrap leading-relaxed">
                          {step.notes}
                        </pre>
                      )}
                      {step.elements_found.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {step.elements_found.map((el) => (
                            <span key={el} className="px-1.5 py-0.5 text-[10px] rounded bg-green-500/10 text-green-400 border border-green-500/20 font-mono">
                              {el}
                            </span>
                          ))}
                        </div>
                      )}
                      {step.screenshot_b64 && (
                        <img
                          src={`data:image/jpeg;base64,${step.screenshot_b64}`}
                          alt={`Step ${step.step}`}
                          className="rounded border border-bg-border max-w-2xl w-full"
                        />
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* Network captures */}
          {flow.network_captures.length > 0 && (
            <div className="border-t border-bg-border p-4">
              <p className="text-[10px] text-zinc-500 uppercase tracking-wide mb-2">
                Network Requests ({flow.network_captures.length} captured)
              </p>
              <div className="space-y-0.5 max-h-36 overflow-auto">
                {flow.network_captures.slice(0, 40).map((nc, i) => (
                  <div key={i} className="flex items-center gap-2 text-[10px] font-mono py-0.5">
                    <span className={clsx(
                      'w-8 text-center shrink-0 font-medium',
                      nc.method === 'POST' ? 'text-orange-400' :
                      nc.method === 'PUT'  ? 'text-yellow-400' : 'text-zinc-600',
                    )}>
                      {nc.method}
                    </span>
                    <span className={nc.is_https ? 'text-green-500 shrink-0' : 'text-red-400 shrink-0'}>
                      {nc.is_https ? '🔒' : '🔓'}
                    </span>
                    <span className="text-zinc-400 truncate flex-1 min-w-0">{nc.url}</span>
                    {nc.has_card_pattern && (
                      <span className="text-red-400 shrink-0 font-semibold">⚠ CHD</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {flow.error && (
            <div className="border-t border-bg-border px-4 py-2 text-[11px] text-red-400 bg-red-500/5">
              Error: {flow.error}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function PciTestPage() {
  const [tab, setTab]               = useState<PageTab>('scope')
  const [scanMode, setScanMode]     = useState<ScanMode>('web_only')
  const [urlInput, setUrlInput]     = useState('')
  const [scopeYaml, setScopeYaml]   = useState(EXAMPLE_SCOPE_YAML)
  const [validation, setValidation] = useState<ScopeValidation | null>(null)
  const [validating, setValidating] = useState(false)
  const [activeJob, setActiveJob]   = useState<PciScanJob | null>(null)
  const [findings, setFindings]     = useState<PciFinding[]>([])
  const [jobs, setJobs]             = useState<PciScanJob[]>([])
  const [selectedFinding, setSelectedFinding] = useState<PciFinding | null>(null)
  const [categoryFilter, setCategoryFilter]   = useState('all')
  const [severityFilter, setSeverityFilter]   = useState<PciSeverity | 'all'>('all')
  const [flows, setFlows]             = useState<PaymentFlowResult[]>([])
  const [flowsLoading, setFlowsLoading] = useState(false)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState<string | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    pciApi.listJobs().then(setJobs).catch(() => {})
  }, [])

  // Poll active job until terminal state
  useEffect(() => {
    if (!activeJob || activeJob.status === 'done' || activeJob.status === 'error') {
      if (pollRef.current) clearInterval(pollRef.current)
      return
    }
    pollRef.current = setInterval(async () => {
      try {
        const updated = await pciApi.getJob(activeJob.id)
        setActiveJob(updated)
        if (updated.status === 'done' || updated.status === 'error') {
          clearInterval(pollRef.current!)
          const f = await pciApi.getFindings(updated.id)
          setFindings(f.sort((a, b) => PCI_SEVERITY_ORDER[a.severity] - PCI_SEVERITY_ORDER[b.severity]))
          pciApi.listJobs().then(setJobs).catch(() => {})
          if (updated.status === 'done') {
            setTab('findings')
            // Pre-load flow steps in background
            pciApi.getFlowSteps(updated.id).then(setFlows).catch(() => {})
          }
        }
      } catch { /* ignore */ }
    }, 2000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [activeJob?.id, activeJob?.status])

  const handleValidate = async () => {
    setValidating(true)
    setValidation(null)
    try {
      setValidation(await pciApi.validateScope(scopeYaml))
    } catch {
      setValidation({ valid: false, error: 'Request failed' })
    } finally {
      setValidating(false)
    }
  }

  const loadFlows = useCallback(async (jobId: number) => {
    setFlowsLoading(true)
    try {
      const data = await pciApi.getFlowSteps(jobId)
      setFlows(data)
    } catch { /* ignore */ } finally {
      setFlowsLoading(false)
    }
  }, [])

  const handleStart = async () => {
    setError(null)
    setLoading(true)
    setFindings([])
    setFlows([])
    setSelectedFinding(null)
    setCategoryFilter('all')
    setSeverityFilter('all')
    try {
      let job: PciScanJob
      if (scanMode === 'web_only') {
        const urls = urlInput.split('\n').map((u) => u.trim()).filter(Boolean)
        if (!urls.length) { setError('Enter at least one URL.'); return }
        job = await pciApi.startScan(urls)
      } else {
        if (!scopeYaml.trim()) { setError('Provide a scope config.'); return }
        job = await pciApi.startFullScan(scopeYaml, scanMode)
      }
      setActiveJob(job)
      setTab('dashboard')
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Scan failed')
    } finally {
      setLoading(false)
    }
  }

  const handleCancel = async () => {
    if (!activeJob) return
    await pciApi.cancelJob(activeJob.id).catch(() => {})
    setActiveJob((j) => j ? { ...j, status: 'error', error: 'Cancelled' } : j)
    if (pollRef.current) clearInterval(pollRef.current)
  }

  const handleDeleteJob = useCallback(async (job: PciScanJob) => {
    await pciApi.deleteJob(job.id).catch(() => {})
    setJobs((prev) => prev.filter((j) => j.id !== job.id))
    if (activeJob?.id === job.id) {
      setActiveJob(null)
      setFindings([])
      setFlows([])
    }
  }, [activeJob?.id])

  const loadJob = useCallback(async (job: PciScanJob) => {
    setActiveJob(job)
    setSelectedFinding(null)
    setFlows([])
    setCategoryFilter('all')
    setSeverityFilter('all')
    const f = await pciApi.getFindings(job.id).catch(() => [] as PciFinding[])
    setFindings(f.sort((a, b) => PCI_SEVERITY_ORDER[a.severity] - PCI_SEVERITY_ORDER[b.severity]))
    if (job.status === 'done' || job.status === 'error') {
      pciApi.getFlowSteps(job.id).then(setFlows).catch(() => {})
    }
    setTab(job.status === 'done' || job.status === 'error' ? 'findings' : 'dashboard')
  }, [])

  const isRunning = activeJob?.status === 'pending' || activeJob?.status === 'running'

  const PAGE_TABS = [
    { id: 'scope'     as PageTab, label: 'Scope'     },
    { id: 'dashboard' as PageTab, label: 'Dashboard' },
    { id: 'findings'  as PageTab, label: findings.length ? `Findings (${findings.length})` : 'Findings' },
    { id: 'flows'     as PageTab, label: activeJob?.flow_steps_count ? `Payment Flows (${activeJob.flow_steps_count})` : 'Payment Flows' },
    { id: 'reports'   as PageTab, label: 'Reports'   },
  ]

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-bg-border bg-bg-surface shrink-0">
        <CreditCard size={15} className="text-accent shrink-0" />
        <div className="flex-1 min-w-0">
          <h1 className="text-sm font-semibold text-zinc-100">PCI DSS Compliance Scanner</h1>
          <p className="text-[11px] text-zinc-500">
            Tenable-style PCI DSS v4.0 — host discovery, port scan, vulnerability assessment, web checks, malware / skimmer detection
          </p>
        </div>
        {isRunning && (
          <div className="flex items-center gap-1.5 text-[11px] text-accent shrink-0">
            <RefreshCw size={11} className="animate-spin" />
            <span className="font-medium capitalize">{activeJob?.phase ?? 'running'}…</span>
          </div>
        )}
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-bg-border bg-bg-surface shrink-0">
        {PAGE_TABS.map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={clsx(
              'px-4 py-2 text-xs font-medium border-b-2 transition-colors',
              tab === id
                ? 'border-accent text-zinc-100'
                : 'border-transparent text-zinc-500 hover:text-zinc-300',
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex flex-1 overflow-hidden">
        {tab === 'scope' && (
          <ScopeTab
            scanMode={scanMode}   setScanMode={setScanMode}
            urlInput={urlInput}   setUrlInput={setUrlInput}
            scopeYaml={scopeYaml} setScopeYaml={setScopeYaml}
            validation={validation} validating={validating}
            onValidate={handleValidate}
            onStart={handleStart}   onCancel={handleCancel}
            loading={loading}       isRunning={isRunning}
            error={error}
            jobs={jobs}             onLoadJob={loadJob}
            onDeleteJob={handleDeleteJob}
            activeJobId={activeJob?.id}
          />
        )}
        {tab === 'dashboard' && <DashboardTab job={activeJob} findings={findings} />}
        {tab === 'findings'  && (
          <FindingsTab
            findings={findings}
            selectedFinding={selectedFinding}   setSelectedFinding={setSelectedFinding}
            categoryFilter={categoryFilter}     setCategoryFilter={setCategoryFilter}
            severityFilter={severityFilter}     setSeverityFilter={setSeverityFilter}
          />
        )}
        {tab === 'flows' && (
          <PaymentFlowsTab
            job={activeJob}
            flows={flows}
            loading={flowsLoading}
            onLoad={() => activeJob && loadFlows(activeJob.id)}
          />
        )}
        {tab === 'reports' && <ReportsTab job={activeJob} />}
      </div>

      {/* Disclaimer */}
      <div className="flex items-center gap-3 px-4 py-1.5 border-t border-bg-border bg-bg-surface text-[10px] text-zinc-600 shrink-0">
        <AlertTriangle size={10} />
        <span>PCI DSS v4.0 reference only. Does not replace a qualified PCI DSS assessor (QSA) audit.</span>
      </div>
    </div>
  )
}

import React, { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { Bot, Play, Square, Trash2, ChevronRight, AlertTriangle } from 'lucide-react'
import { aiAgentApi } from '@/api/aiAgent'
import type { AIAgentScan, AIAgentFinding, AIAgentScanWithFindings, ProtocolType, ProbeCategory, Severity } from '@/types/aiAgent'

// ── Severity styling ────────────────────────────────────────────────────────

const SEV_COLOR: Record<Severity, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  low:      'text-blue-400 bg-blue-500/10 border-blue-500/30',
  info:     'text-zinc-400 bg-zinc-500/10 border-zinc-500/30',
}

const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={clsx('px-1.5 py-0.5 text-[10px] rounded border font-semibold capitalize', SEV_COLOR[severity])}>
      {severity}
    </span>
  )
}

// ── Protocol + probe config ─────────────────────────────────────────────────

const PROTOCOLS: { value: ProtocolType; label: string; description: string }[] = [
  { value: 'openai_compat', label: 'OpenAI-compatible', description: 'POST /v1/chat/completions' },
  { value: 'mcp',           label: 'MCP (JSON-RPC)',    description: 'JSON-RPC 2.0 tool calls'  },
  { value: 'a2a',           label: 'A2A',               description: 'Agent-to-Agent protocol'  },
  { value: 'rest',          label: 'Generic REST',      description: 'Arbitrary REST endpoint'  },
]

const PROBE_CATEGORIES: { value: ProbeCategory; label: string; description: string }[] = [
  { value: 'infra',            label: 'Infrastructure Checks', description: '8 checks: agent.json, auth gaps, CORS, rate limiting, debug endpoints' },
  { value: 'prompt_injection', label: 'Prompt Injection',      description: '11 payloads: direct override, roleplay, TAO injection, encoding tricks' },
]

// ── Status badge ────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const cls = {
    pending:   'text-zinc-400 bg-zinc-500/10',
    running:   'text-blue-400 bg-blue-500/10 animate-pulse',
    complete:  'text-green-400 bg-green-500/10',
    error:     'text-red-400 bg-red-500/10',
    cancelled: 'text-zinc-500 bg-zinc-700/10',
  }[status] ?? 'text-zinc-400 bg-zinc-500/10'
  return <span className={clsx('px-1.5 py-0.5 text-[10px] rounded font-medium capitalize', cls)}>{status}</span>
}

// ── Config panel ────────────────────────────────────────────────────────────

function ConfigPanel({
  onScanStarted,
  activeScans,
  onSelectScan,
  selectedScanId,
}: {
  onScanStarted: (id: number) => void
  activeScans: AIAgentScan[]
  onSelectScan: (id: number) => void
  selectedScanId: number | null
}) {
  const [targetUrl, setTargetUrl] = useState(() => localStorage.getItem('ai-agent-target') ?? '')
  const [protocol, setProtocol] = useState<ProtocolType>('openai_compat')
  const [probes, setProbes] = useState<ProbeCategory[]>(['infra', 'prompt_injection'])
  const [launching, setLaunching] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const qc = useQueryClient()

  const toggleProbe = (cat: ProbeCategory) => {
    setProbes((prev) => prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat])
  }

  const startScan = async () => {
    if (!targetUrl.trim() || probes.length === 0) return
    setError(null)
    setLaunching(true)
    try {
      localStorage.setItem('ai-agent-target', targetUrl.trim())
      const result = await aiAgentApi.startScan({
        target_url: targetUrl.trim(),
        protocol_type: protocol,
        probe_categories: probes,
      })
      onScanStarted(result.id)
      qc.invalidateQueries({ queryKey: ['ai-agent-scans'] })
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } }; message?: string }
      setError(err?.response?.data?.detail ?? err?.message ?? 'Failed to start scan')
    } finally {
      setLaunching(false)
    }
  }

  const isRunning = (id: number) => activeScans.find((s) => s.id === id)?.status === 'running'

  const cancelScan = async (id: number) => {
    await aiAgentApi.cancelScan(id)
    qc.invalidateQueries({ queryKey: ['ai-agent-scans'] })
  }

  const deleteScan = async (id: number) => {
    await aiAgentApi.deleteScan(id)
    qc.invalidateQueries({ queryKey: ['ai-agent-scans'] })
  }

  return (
    <div className="flex flex-col h-full border-r border-bg-border">
      {/* Target config */}
      <div className="px-4 py-3 border-b border-bg-border space-y-3">
        <div className="flex items-center gap-2">
          <Bot size={14} className="text-purple-400 shrink-0" />
          <span className="text-xs font-semibold text-zinc-200">AI Agent Scanner</span>
        </div>

        <div className="space-y-1">
          <label className="text-xs text-zinc-500">Target URL</label>
          <input
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://localhost:7002"
            className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs font-mono text-zinc-300 placeholder-zinc-600 focus:outline-none focus:border-purple-500/50"
          />
        </div>

        <div className="space-y-1">
          <label className="text-xs text-zinc-500">Protocol</label>
          <select
            value={protocol}
            onChange={(e) => setProtocol(e.target.value as ProtocolType)}
            className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-300 focus:outline-none focus:border-purple-500/50"
          >
            {PROTOCOLS.map((p) => (
              <option key={p.value} value={p.value}>{p.label} — {p.description}</option>
            ))}
          </select>
        </div>

        <div className="space-y-1.5">
          <label className="text-xs text-zinc-500">Probe Categories</label>
          {PROBE_CATEGORIES.map((cat) => (
            <label key={cat.value} className="flex items-start gap-2 cursor-pointer group">
              <input
                type="checkbox"
                checked={probes.includes(cat.value)}
                onChange={() => toggleProbe(cat.value)}
                className="mt-0.5 accent-purple-500"
              />
              <div>
                <div className="text-xs text-zinc-300 group-hover:text-zinc-100">{cat.label}</div>
                <div className="text-[10px] text-zinc-600 leading-snug">{cat.description}</div>
              </div>
            </label>
          ))}
        </div>

        {error && (
          <div className="flex items-center gap-1.5 text-xs text-red-400 bg-red-500/10 rounded px-2 py-1.5">
            <AlertTriangle size={11} /> {error}
          </div>
        )}

        <button
          onClick={startScan}
          disabled={launching || !targetUrl.trim() || probes.length === 0}
          className="w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded text-xs font-medium bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {launching ? <><span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" /> Starting…</> : <><Play size={11} /> Start Scan</>}
        </button>
      </div>

      {/* Scan history */}
      <div className="flex-1 overflow-y-auto">
        <div className="px-3 py-2 text-[10px] text-zinc-600 uppercase tracking-wider font-semibold border-b border-bg-border">
          Scan History
        </div>
        {activeScans.length === 0 && (
          <div className="px-3 py-4 text-xs text-zinc-600 text-center">No scans yet</div>
        )}
        {activeScans.map((scan) => (
          <div
            key={scan.id}
            onClick={() => onSelectScan(scan.id)}
            className={clsx(
              'px-3 py-2 border-b border-bg-border cursor-pointer hover:bg-bg-elevated transition-colors',
              selectedScanId === scan.id ? 'bg-purple-500/5 border-l-2 border-l-purple-500' : 'border-l-2 border-l-transparent'
            )}
          >
            <div className="flex items-center gap-1.5 mb-1">
              <StatusBadge status={scan.status} />
              {scan.finding_count > 0 && (
                <span className="text-[10px] text-orange-400 font-mono">{scan.finding_count} findings</span>
              )}
              <span className="ml-auto flex gap-1">
                {isRunning(scan.id) && (
                  <button
                    onClick={(e) => { e.stopPropagation(); cancelScan(scan.id) }}
                    className="text-zinc-600 hover:text-red-400 transition-colors"
                    title="Cancel scan"
                  >
                    <Square size={10} />
                  </button>
                )}
                <button
                  onClick={(e) => { e.stopPropagation(); deleteScan(scan.id) }}
                  className="text-zinc-600 hover:text-red-400 transition-colors"
                  title="Delete scan"
                >
                  <Trash2 size={10} />
                </button>
              </span>
            </div>
            <div className="text-[10px] text-zinc-500 font-mono truncate">{scan.target_url}</div>
            {scan.duration_seconds && (
              <div className="text-[10px] text-zinc-700 mt-0.5">{scan.duration_seconds.toFixed(1)}s</div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Findings list ───────────────────────────────────────────────────────────

function FindingsList({
  findings,
  selectedId,
  onSelect,
  scanStatus,
}: {
  findings: AIAgentFinding[]
  selectedId: number | null
  onSelect: (f: AIAgentFinding) => void
  scanStatus: string
}) {
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null)
  const sorted = [...findings].sort(
    (a, b) => SEV_ORDER[a.severity as Severity] - SEV_ORDER[b.severity as Severity]
  )
  const filtered = severityFilter ? sorted.filter((f) => f.severity === severityFilter) : sorted

  const counts: Partial<Record<Severity, number>> = {}
  for (const f of findings) counts[f.severity as Severity] = (counts[f.severity as Severity] ?? 0) + 1

  return (
    <div className="flex flex-col h-full border-r border-bg-border">
      {/* Header + filter */}
      <div className="px-3 py-2 border-b border-bg-border bg-bg-surface shrink-0 space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-zinc-300">Findings</span>
          {(scanStatus === 'pending' || scanStatus === 'running') && (
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
          )}
          <span className="ml-auto text-xs text-zinc-600">{findings.length} total</span>
        </div>
        <div className="flex gap-1 flex-wrap">
          <button
            onClick={() => setSeverityFilter(null)}
            className={clsx('px-2 py-0.5 rounded text-[10px] transition-colors',
              severityFilter === null ? 'bg-zinc-600/40 text-zinc-200' : 'text-zinc-600 hover:text-zinc-300')}
          >
            All
          </button>
          {(Object.entries(counts) as [Severity, number][]).sort(([a], [b]) => SEV_ORDER[a] - SEV_ORDER[b]).map(([sev, cnt]) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(severityFilter === sev ? null : sev)}
              className={clsx('px-2 py-0.5 rounded text-[10px] border transition-colors capitalize',
                severityFilter === sev ? SEV_COLOR[sev] : 'text-zinc-600 border-transparent hover:text-zinc-300')}
            >
              {sev} {cnt}
            </button>
          ))}
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 && (
          <div className="flex items-center justify-center h-24 text-xs text-zinc-600">
            {scanStatus === 'running' ? 'Scanning…' : 'No findings'}
          </div>
        )}
        {filtered.map((f) => (
          <div
            key={f.id}
            onClick={() => onSelect(f)}
            className={clsx(
              'flex items-center gap-2 px-3 py-2 text-xs cursor-pointer hover:bg-bg-elevated border-l-2 transition-colors',
              selectedId === f.id ? 'bg-purple-500/5 border-l-purple-500' : 'border-l-transparent'
            )}
          >
            <SeverityBadge severity={f.severity as Severity} />
            <span className="flex-1 text-zinc-300 truncate">{f.title}</span>
            {f.confirmed && <span className="text-[10px] text-green-400 shrink-0">confirmed</span>}
            <ChevronRight size={10} className="text-zinc-600 shrink-0" />
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Finding detail ──────────────────────────────────────────────────────────

function FindingDetail({ finding }: { finding: AIAgentFinding | null }) {
  if (!finding) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-zinc-600 gap-2">
        <Bot size={24} />
        <span className="text-sm">Select a finding</span>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full overflow-y-auto">
      <div className="px-4 py-3 border-b border-bg-border bg-bg-surface shrink-0 space-y-1.5">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={finding.severity as Severity} />
          {finding.confirmed && (
            <span className="px-1.5 py-0.5 text-[10px] rounded border text-green-400 bg-green-500/10 border-green-500/20 font-semibold">
              Confirmed
            </span>
          )}
          <span className="text-[10px] text-zinc-600 font-mono">{finding.probe_id}</span>
        </div>
        <h2 className="text-sm font-semibold text-zinc-200">{finding.title}</h2>
      </div>

      <div className="flex-1 px-4 py-3 space-y-4 overflow-y-auto">
        <Section title="Detail">
          <p className="text-xs text-zinc-400 leading-relaxed">{finding.detail}</p>
        </Section>

        {finding.evidence && (
          <Section title="Evidence">
            <pre className="text-[11px] font-mono text-zinc-300 bg-bg-elevated rounded p-3 whitespace-pre-wrap break-all leading-relaxed border border-bg-border">
              {finding.evidence}
            </pre>
          </Section>
        )}

        {finding.request_payload && (
          <Section title="Request Payload">
            <pre className="text-[11px] font-mono text-zinc-500 bg-bg-elevated rounded p-3 whitespace-pre-wrap break-all leading-relaxed border border-bg-border">
              {finding.request_payload}
            </pre>
          </Section>
        )}

        {finding.raw_response && (
          <Section title="Raw Response">
            <pre className="text-[11px] font-mono text-zinc-400 bg-bg-elevated rounded p-3 whitespace-pre-wrap break-all leading-relaxed border border-bg-border max-h-64 overflow-y-auto">
              {finding.raw_response}
            </pre>
          </Section>
        )}
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <div className="text-[10px] text-zinc-600 uppercase tracking-wider font-semibold">{title}</div>
      {children}
    </div>
  )
}

// ── Main page ───────────────────────────────────────────────────────────────

export default function AIAgentPage() {
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null)
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null)
  const qc = useQueryClient()

  const { data: scans = [] } = useQuery<AIAgentScan[]>({
    queryKey: ['ai-agent-scans'],
    queryFn: () => aiAgentApi.listScans(),
    refetchInterval: 3000,
  })

  const isActiveState = (status: string) => status === 'pending' || status === 'running'

  const { data: scanResults } = useQuery<AIAgentScanWithFindings>({
    queryKey: ['ai-agent-results', selectedScanId],
    queryFn: () => aiAgentApi.getScanResults(selectedScanId!),
    enabled: !!selectedScanId,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status && isActiveState(status) ? 2000 : false
    },
  })

  const findings: AIAgentFinding[] = scanResults?.findings ?? []
  const selectedFinding = findings.find((f) => f.id === selectedFindingId) ?? null
  const scanStatus = scanResults?.status ?? 'pending'

  const handleScanStarted = (id: number) => {
    setSelectedScanId(id)
    setSelectedFindingId(null)
    qc.invalidateQueries({ queryKey: ['ai-agent-scans'] })
  }

  const handleSelectScan = (id: number) => {
    setSelectedScanId(id)
    setSelectedFindingId(null)
  }

  return (
    <div className="flex h-full overflow-hidden">
      {/* Left: config + history */}
      <div className="w-72 shrink-0 flex flex-col overflow-hidden">
        <ConfigPanel
          onScanStarted={handleScanStarted}
          activeScans={scans}
          onSelectScan={handleSelectScan}
          selectedScanId={selectedScanId}
        />
      </div>

      {/* Center: findings list */}
      <div className="w-72 shrink-0 flex flex-col overflow-hidden">
        <FindingsList
          findings={findings}
          selectedId={selectedFindingId}
          onSelect={(f) => setSelectedFindingId(f.id)}
          scanStatus={scanStatus}
        />
      </div>

      {/* Right: finding detail */}
      <div className="flex-1 overflow-hidden">
        <FindingDetail finding={selectedFinding} />
      </div>
    </div>
  )
}

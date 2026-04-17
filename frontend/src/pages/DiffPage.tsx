import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { GitCompare, Plus, Trash2, ChevronDown, ChevronRight, ArrowUp, ArrowDown } from 'lucide-react'
import { diffApi, type DiffOut, type DiffSummary, type FindingSnap } from '@/api/diff'
import { api } from '@/api/client'

interface AnalysisSummary {
  id: number
  apk_filename: string
  package_name: string | null
  platform: string
  status: string
  created_at: string
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-400/10 border-orange-500/30',
  medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-500/30',
  low: 'text-blue-400 bg-blue-400/10 border-blue-500/30',
  info: 'text-zinc-400 bg-zinc-400/10 border-zinc-500/30',
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`text-xs px-1.5 py-0.5 rounded border font-mono ${SEVERITY_COLOR[severity] ?? SEVERITY_COLOR.info}`}>
      {severity}
    </span>
  )
}

function FindingList({ findings, label, color }: { findings: FindingSnap[]; label: string; color: string }) {
  const [open, setOpen] = useState(true)
  if (!findings.length) return null
  return (
    <div className="mb-4">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 text-sm font-semibold mb-2 hover:opacity-80"
      >
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <span className={color}>{label}</span>
        <span className="text-zinc-500 font-normal">({findings.length})</span>
      </button>
      {open && (
        <div className="space-y-1 pl-4">
          {findings.map((f, i) => (
            <div key={i} className="flex items-start gap-2 text-xs py-1 border-b border-bg-border last:border-0">
              <SeverityBadge severity={f.severity} />
              <div className="flex-1 min-w-0">
                <span className="font-medium text-zinc-200">{f.title}</span>
                {f.file_path && (
                  <span className="ml-2 text-zinc-500 font-mono">{f.file_path}</span>
                )}
              </div>
              <span className="text-zinc-600 shrink-0">{f.category}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function DiffDetail({ diff }: { diff: DiffOut }) {
  const net = Object.entries(diff.severity_delta)
    .sort(([a], [b]) => SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b))

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="flex items-center gap-3 flex-wrap">
        {net.map(([sev, delta]) => (
          <div key={sev} className={`flex items-center gap-1 text-xs px-2 py-1 rounded border ${SEVERITY_COLOR[sev] ?? SEVERITY_COLOR.info}`}>
            {delta > 0 ? <ArrowUp size={11} /> : <ArrowDown size={11} />}
            <span className="font-mono">{delta > 0 ? `+${delta}` : delta}</span>
            <span>{sev}</span>
          </div>
        ))}
        {net.length === 0 && (
          <span className="text-xs text-zinc-500">No severity changes</span>
        )}
      </div>

      {/* Findings */}
      <FindingList findings={diff.added_findings} label="Added Findings" color="text-red-400" />
      <FindingList findings={diff.removed_findings} label="Removed Findings" color="text-green-400" />

      {/* Permissions */}
      {(diff.added_permissions.length > 0 || diff.removed_permissions.length > 0) && (
        <div>
          <p className="text-xs font-semibold text-zinc-400 mb-2">Permissions</p>
          {diff.added_permissions.map((p) => (
            <div key={p} className="text-xs text-red-400 font-mono pl-2">+ {p}</div>
          ))}
          {diff.removed_permissions.map((p) => (
            <div key={p} className="text-xs text-green-400 font-mono pl-2">− {p}</div>
          ))}
        </div>
      )}

      {!diff.added_findings.length && !diff.removed_findings.length &&
       !diff.added_permissions.length && !diff.removed_permissions.length && (
        <p className="text-sm text-zinc-500">No differences found between these two analyses.</p>
      )}
    </div>
  )
}

export default function DiffPage() {
  const qc = useQueryClient()
  const [baselineId, setBaselineId] = useState('')
  const [targetId, setTargetId] = useState('')
  const [activeDiff, setActiveDiff] = useState<DiffOut | null>(null)

  const { data: analyses = [] } = useQuery<AnalysisSummary[]>({
    queryKey: ['analyses-list'],
    queryFn: () => api.get('/analyses').then((r) => r.data),
  })

  const { data: diffs = [], isLoading } = useQuery<DiffSummary[]>({
    queryKey: ['diffs'],
    queryFn: () => diffApi.list(),
    refetchInterval: 5000,
  })

  const createMutation = useMutation({
    mutationFn: () => diffApi.create(Number(baselineId), Number(targetId)),
    onSuccess: (diff) => {
      setActiveDiff(diff)
      qc.invalidateQueries({ queryKey: ['diffs'] })
    },
  })

  const loadDiff = async (id: number) => {
    const diff = await diffApi.get(id)
    setActiveDiff(diff)
  }

  const deleteMutation = useMutation({
    mutationFn: (id: number) => diffApi.delete(id),
    onSuccess: () => {
      setActiveDiff(null)
      qc.invalidateQueries({ queryKey: ['diffs'] })
    },
  })

  const completed = analyses.filter((a) => a.status === 'complete')

  return (
    <div className="flex h-full">
      {/* Left panel */}
      <div className="w-72 shrink-0 border-r border-bg-border flex flex-col">
        <div className="p-4 border-b border-bg-border">
          <h2 className="text-sm font-semibold text-zinc-200 flex items-center gap-2 mb-3">
            <GitCompare size={15} />
            New Diff
          </h2>
          <div className="space-y-2">
            <div>
              <label className="text-xs text-zinc-500 mb-1 block">Baseline (before)</label>
              <select
                value={baselineId}
                onChange={(e) => setBaselineId(e.target.value)}
                className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent"
              >
                <option value="">Select analysis…</option>
                {completed.map((a) => (
                  <option key={a.id} value={a.id}>
                    #{a.id} {a.package_name ?? a.apk_filename}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-zinc-500 mb-1 block">Target (after)</label>
              <select
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent"
              >
                <option value="">Select analysis…</option>
                {completed.map((a) => (
                  <option key={a.id} value={a.id}>
                    #{a.id} {a.package_name ?? a.apk_filename}
                  </option>
                ))}
              </select>
            </div>
            <button
              onClick={() => createMutation.mutate()}
              disabled={!baselineId || !targetId || baselineId === targetId || createMutation.isPending}
              className="w-full flex items-center justify-center gap-1.5 bg-accent hover:bg-accent/80 disabled:opacity-40 text-white text-xs py-1.5 rounded transition-colors"
            >
              <Plus size={13} />
              {createMutation.isPending ? 'Computing…' : 'Run Diff'}
            </button>
          </div>
        </div>

        {/* History */}
        <div className="flex-1 overflow-y-auto p-2">
          <p className="text-xs text-zinc-600 px-2 pt-1 pb-2 uppercase tracking-wider">History</p>
          {isLoading && <p className="text-xs text-zinc-500 px-2">Loading…</p>}
          {diffs.map((d) => (
            <button
              key={d.id}
              onClick={() => loadDiff(d.id)}
              className={`w-full text-left rounded px-2 py-2 text-xs hover:bg-bg-elevated transition-colors mb-0.5 ${activeDiff?.id === d.id ? 'bg-bg-elevated border border-accent/30' : ''}`}
            >
              <div className="flex items-center justify-between">
                <span className="text-zinc-300 font-mono">
                  #{d.baseline_id} → #{d.target_id}
                </span>
                <button
                  onClick={(e) => { e.stopPropagation(); deleteMutation.mutate(d.id) }}
                  className="text-zinc-600 hover:text-red-400 transition-colors"
                >
                  <Trash2 size={11} />
                </button>
              </div>
              <p className="text-zinc-500 truncate mt-0.5">{d.summary ?? 'No changes'}</p>
            </button>
          ))}
          {!isLoading && diffs.length === 0 && (
            <p className="text-xs text-zinc-600 px-2">No diffs yet</p>
          )}
        </div>
      </div>

      {/* Main panel */}
      <div className="flex-1 overflow-y-auto p-6">
        {activeDiff ? (
          <div>
            <div className="flex items-center gap-3 mb-4">
              <GitCompare size={18} className="text-accent" />
              <div>
                <h2 className="text-sm font-semibold text-zinc-200">
                  Analysis #{activeDiff.baseline_id} → #{activeDiff.target_id}
                </h2>
                <p className="text-xs text-zinc-500">{activeDiff.summary}</p>
              </div>
            </div>
            <DiffDetail diff={activeDiff} />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-64 text-zinc-600">
            <GitCompare size={40} className="mb-3 opacity-30" />
            <p className="text-sm">Select two analyses and run a diff</p>
            <p className="text-xs mt-1 opacity-70">or click a diff from the history list</p>
          </div>
        )}
      </div>
    </div>
  )
}

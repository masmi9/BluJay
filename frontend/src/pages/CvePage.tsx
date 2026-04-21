import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert, ChevronDown, ChevronRight, ExternalLink, RefreshCw } from 'lucide-react'
import { clsx } from 'clsx'
import { cveApi } from '@/api/cve'
import type { DetectedLibrary, CveMatch } from '@/types/cve'

const SEV_COLORS: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
}

function CvssBar({ score }: { score: number | null }) {
  if (score === null) return <span className="text-zinc-600 text-xs">N/A</span>
  const pct = Math.min((score / 10) * 100, 100)
  const color = score >= 9 ? 'bg-red-500' : score >= 7 ? 'bg-orange-500' : score >= 4 ? 'bg-yellow-500' : 'bg-blue-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-2 bg-bg-elevated rounded-full overflow-hidden">
        <div className={clsx('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-zinc-300">{score.toFixed(1)}</span>
    </div>
  )
}

function LibraryRow({ lib, matches }: { lib: DetectedLibrary; matches: CveMatch[] }) {
  const [open, setOpen] = useState(false)
  const libMatches = matches.filter((m) => m.library_id === lib.id)

  return (
    <div className="border border-bg-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-3 px-4 py-3 bg-bg-surface hover:bg-bg-elevated transition-colors text-left"
      >
        {open ? <ChevronDown size={14} className="shrink-0 text-zinc-400" /> : <ChevronRight size={14} className="shrink-0 text-zinc-400" />}
        <span className="font-mono text-sm text-zinc-200 flex-1">{lib.name}</span>
        <span className="text-xs text-zinc-500 font-mono">{lib.version ?? 'unknown version'}</span>
        <span className="text-xs px-2 py-0.5 bg-bg-elevated rounded text-zinc-400">{lib.ecosystem}</span>
        <span className="text-xs px-2 py-0.5 bg-bg-elevated rounded text-zinc-500">{lib.source}</span>
        {libMatches.length > 0 && (
          <span className="text-xs px-2 py-0.5 bg-red-900/50 text-red-400 rounded">
            {libMatches.length} CVE{libMatches.length > 1 ? 's' : ''}
          </span>
        )}
      </button>

      {open && libMatches.length > 0 && (
        <div className="divide-y divide-bg-border">
          {libMatches.map((m) => (
            <div key={m.id} className="flex items-start gap-4 px-6 py-3 bg-bg-elevated">
              <div className="flex flex-col gap-1 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs text-zinc-300">{m.osv_id}</span>
                  {m.cve_id && <span className="font-mono text-xs text-zinc-400">{m.cve_id}</span>}
                  {m.severity && (
                    <span className={clsx('text-xs px-2 py-0.5 rounded font-medium', SEV_COLORS[m.severity])}>
                      {m.severity.toUpperCase()}
                    </span>
                  )}
                  <a
                    href={`https://osv.dev/vulnerability/${m.osv_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-zinc-500 hover:text-zinc-200 ml-auto"
                  >
                    <ExternalLink size={12} />
                  </a>
                </div>
                {m.summary && <p className="text-xs text-zinc-400">{m.summary}</p>}
                <div className="flex gap-4 text-xs text-zinc-500">
                  {m.fixed_version && <span>Fixed in: <span className="text-zinc-300">{m.fixed_version}</span></span>}
                  {m.published && <span>Published: <span className="text-zinc-300">{m.published.substring(0, 10)}</span></span>}
                </div>
              </div>
              <CvssBar score={m.cvss_score} />
            </div>
          ))}
        </div>
      )}

      {open && libMatches.length === 0 && (
        <div className="px-6 py-3 bg-bg-elevated text-xs text-zinc-500">No known CVEs found.</div>
      )}
    </div>
  )
}

export default function CvePage() {
  const { id } = useParams<{ id: string }>()
  const analysisId = Number(id)
  const qc = useQueryClient()

  const { data: summary, isLoading } = useQuery({
    queryKey: ['cve-summary', analysisId],
    queryFn: () => cveApi.getSummary(analysisId),
  })

  const scan = useMutation({
    mutationFn: () => cveApi.triggerScan(analysisId),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['cve-summary', analysisId] }), 3000),
  })

  const libs = summary?.libraries ?? []
  const matches = summary?.cve_matches ?? []

  return (
    <div className="flex flex-col h-full p-6 gap-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <ShieldAlert size={20} className="text-orange-400" />
        <h1 className="text-lg font-semibold text-zinc-100">CVE Correlation</h1>
        <div className="flex-1" />
        {summary && (
          <div className="flex gap-3">
            {summary.total_critical > 0 && (
              <span className="px-2 py-1 text-xs rounded bg-red-600 text-white">
                {summary.total_critical} Critical
              </span>
            )}
            {summary.total_high > 0 && (
              <span className="px-2 py-1 text-xs rounded bg-orange-500 text-white">
                {summary.total_high} High
              </span>
            )}
          </div>
        )}
        <button
          onClick={() => scan.mutate()}
          disabled={scan.isPending}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-sm text-white transition-colors"
        >
          <RefreshCw size={13} className={scan.isPending ? 'animate-spin' : ''} />
          {scan.isPending ? 'Scanning…' : 'Run Scan'}
        </button>
      </div>

      {isLoading && <p className="text-zinc-500 text-sm">Loading…</p>}

      {!isLoading && libs.length === 0 && (
        <p className="text-zinc-500 text-sm">No libraries detected. Run a scan after completing static analysis.</p>
      )}

      {/* Library list grouped by ecosystem */}
      <div className="flex flex-col gap-4 overflow-auto">
        {Object.entries(
          libs.reduce<Record<string, typeof libs>>((acc, lib) => {
            const eco = lib.ecosystem || 'Unknown'
            ;(acc[eco] ??= []).push(lib)
            return acc
          }, {})
        ).sort(([a], [b]) => a.localeCompare(b)).map(([ecosystem, ecosystemLibs]) => (
          <div key={ecosystem}>
            <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2 px-1">
              {ecosystem} <span className="font-normal text-zinc-600">({ecosystemLibs.length})</span>
            </h3>
            <div className="flex flex-col gap-2">
              {ecosystemLibs.map((lib) => (
                <LibraryRow key={lib.id} lib={lib} matches={matches} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

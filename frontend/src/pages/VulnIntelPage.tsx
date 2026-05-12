import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  AlertOctagon, Search, Loader2, ExternalLink, CheckCircle2,
  XCircle, ChevronRight, Play, RefreshCw,
} from 'lucide-react'
import { clsx } from 'clsx'
import { vulnIntelApi } from '@/api/vulnIntel'
import type { CVEResult } from '@/api/vulnIntel'

// ── Severity helpers ───────────────────────────────────────────────────────

const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH:     'bg-orange-500 text-white',
  MEDIUM:   'bg-yellow-500 text-black',
  LOW:      'bg-blue-500 text-white',
  NONE:     'bg-zinc-600 text-zinc-300',
  UNKNOWN:  'bg-zinc-700 text-zinc-400',
}

function SeverityBadge({ severity, score }: { severity: string; score: number | null }) {
  return (
    <div className="flex items-center gap-1.5 shrink-0">
      <span className={clsx('text-[10px] px-1.5 py-0.5 rounded font-semibold', SEV_BADGE[severity] ?? SEV_BADGE.UNKNOWN)}>
        {severity}
      </span>
      {score !== null && <span className="text-[10px] text-zinc-400 font-mono">{score.toFixed(1)}</span>}
    </div>
  )
}

function CVECard({ cve }: { cve: CVEResult }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border border-bg-border rounded-lg overflow-hidden">
      <button onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-3 px-4 py-2.5 bg-bg-surface hover:bg-bg-elevated text-left transition-colors">
        {open ? <ChevronRight size={12} className="text-zinc-500 rotate-90" /> : <ChevronRight size={12} className="text-zinc-500" />}
        <span className="text-xs font-mono text-accent shrink-0 w-28">{cve.id}</span>
        <SeverityBadge severity={cve.severity} score={cve.score} />
        <p className="text-xs text-zinc-400 flex-1 truncate">{cve.description}</p>
        <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="shrink-0 text-zinc-600 hover:text-accent transition-colors">
          <ExternalLink size={11} />
        </a>
      </button>
      {open && (
        <div className="px-4 py-3 bg-bg-elevated border-t border-bg-border space-y-2">
          <p className="text-xs text-zinc-300 leading-relaxed">{cve.description}</p>
          {cve.vector && <p className="text-[10px] font-mono text-zinc-500">{cve.vector}</p>}
          {cve.published && <p className="text-[10px] text-zinc-600">Published: {cve.published?.slice(0, 10)}</p>}
          {cve.refs.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {cve.refs.map((r, i) => (
                <a key={i} href={r} target="_blank" rel="noreferrer"
                  className="text-[10px] text-accent hover:underline truncate max-w-xs">{r}</a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── CVE Search Tab ─────────────────────────────────────────────────────────

function CVESearchTab() {
  const [keyword, setKeyword]   = useState('')
  const [results, setResults]   = useState<CVEResult[]>([])
  const [total, setTotal]       = useState(0)
  const [mode, setMode]         = useState<'keyword' | 'versions'>('keyword')
  const [versionText, setVText] = useState('')

  const search = useMutation({
    mutationFn: () => vulnIntelApi.cveSearch(keyword),
    onSuccess: (data) => { setResults(data.results); setTotal(data.total) },
  })

  const matchVersions = useMutation({
    mutationFn: () => {
      const services = versionText.split('\n').map((line) => {
        const parts = line.trim().split(/\s+/)
        return { service: parts[0] ?? '', version: parts.slice(1).join(' ') }
      }).filter((s) => s.service)
      return vulnIntelApi.versionsMatch(services)
    },
  })

  return (
    <div className="space-y-5">
      <div className="flex gap-1">
        {(['keyword', 'versions'] as const).map((m) => (
          <button key={m} onClick={() => setMode(m)}
            className={clsx('px-3 py-1.5 text-xs rounded border transition-colors capitalize',
              mode === m ? 'border-accent bg-accent/10 text-accent' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
            )}>
            {m === 'versions' ? 'Version Match (from nmap)' : 'Keyword Search'}
          </button>
        ))}
      </div>

      {mode === 'keyword' ? (
        <div className="flex gap-2">
          <input
            className="flex-1 bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="e.g. Apache Struts 2.5, OpenSSH 8.1, log4j"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && keyword.trim() && search.mutate()}
          />
          <button onClick={() => search.mutate()} disabled={search.isPending || !keyword.trim()}
            className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
            {search.isPending ? <Loader2 size={11} className="animate-spin" /> : <Search size={11} />}
            Search
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          <div>
            <label className="block text-[10px] text-zinc-500 mb-1">Paste nmap service output (service version, one per line)</label>
            <textarea
              className="w-full h-28 bg-bg-elevated border border-bg-border rounded p-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent resize-none placeholder-zinc-600"
              placeholder={"ssh OpenSSH 7.4\nhttpd Apache 2.4.49\nmysql MySQL 5.7.32"}
              value={versionText}
              onChange={(e) => setVText(e.target.value)}
            />
          </div>
          <button onClick={() => matchVersions.mutate()} disabled={matchVersions.isPending || !versionText.trim()}
            className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
            {matchVersions.isPending ? <Loader2 size={11} className="animate-spin" /> : <Search size={11} />}
            Match CVEs
          </button>
        </div>
      )}

      {mode === 'keyword' && results.length > 0 && (
        <div className="space-y-2">
          <p className="text-[10px] text-zinc-500">{total} total results, showing {results.length}</p>
          {results.map((cve) => <CVECard key={cve.id} cve={cve} />)}
        </div>
      )}

      {mode === 'versions' && matchVersions.data && (
        <div className="space-y-4">
          {(matchVersions.data as { services: { service: string; version: string; cves: CVEResult[]; highest_severity: string }[] }).services.map((svc, i) => (
            <div key={i} className="rounded-xl border border-bg-border overflow-hidden">
              <div className="flex items-center gap-3 px-4 py-2.5 bg-bg-elevated border-b border-bg-border">
                <span className="text-xs font-medium text-zinc-200">{svc.service}</span>
                <span className="text-xs text-zinc-500 font-mono">{svc.version}</span>
                <div className="flex-1" />
                <SeverityBadge severity={svc.highest_severity} score={null} />
                <span className="text-[10px] text-zinc-500">{svc.cves.length} CVEs</span>
              </div>
              {svc.cves.length > 0 ? (
                <div className="divide-y divide-bg-border/50">
                  {svc.cves.map((cve) => <CVECard key={cve.id} cve={cve} />)}
                </div>
              ) : (
                <p className="px-4 py-3 text-xs text-zinc-600">No CVEs found for this version</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Nuclei Tab ─────────────────────────────────────────────────────────────

const ALL_TAGS     = ['cves', 'exposures', 'misconfigs', 'default-login', 'takeovers', 'network', 'tech']
const ALL_SEVERITY = ['critical', 'high', 'medium', 'low', 'info']
const SEV_ORDER    = ['critical', 'high', 'medium', 'low', 'info']

function NucleiTab() {
  const [target, setTarget]     = useState('')
  const [tags, setTags]         = useState(['cves', 'exposures', 'misconfigs', 'default-login'])
  const [severity, setSeverity] = useState(['critical', 'high', 'medium'])
  const [scanId, setScanId]     = useState<string | null>(null)

  const { data: nucleiStatus } = useQuery({ queryKey: ['nuclei-status'], queryFn: vulnIntelApi.nucleiStatus, refetchInterval: 60_000 })

  const { data: scanData } = useQuery({
    queryKey: ['nuclei-scan', scanId],
    queryFn: () => vulnIntelApi.nucleiResults(scanId!),
    enabled: !!scanId,
    refetchInterval: (q) => {
      const d = q.state.data as { status?: string } | undefined
      return d?.status === 'running' ? 3000 : false
    },
  })

  const runScan = useMutation({
    mutationFn: () => vulnIntelApi.nucleiScan(target, tags, severity),
    onSuccess: (data) => setScanId(data.id),
  })

  const toggleTag = (t: string) => setTags((prev) => prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t])
  const toggleSev = (s: string) => setSeverity((prev) => prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s])

  const findings = (scanData?.findings ?? []) as Record<string, unknown>[]
  const bySeverity = SEV_ORDER.reduce((acc, s) => {
    acc[s] = findings.filter((f) => (f['info'] as { severity?: string })?.severity?.toLowerCase() === s)
    return acc
  }, {} as Record<string, Record<string, unknown>[]>)

  return (
    <div className="space-y-5">
      {nucleiStatus && (
        <div className={clsx('flex items-center gap-2 text-xs px-3 py-2 rounded border',
          nucleiStatus.available
            ? 'bg-green-500/10 border-green-500/30 text-green-400'
            : 'bg-red-500/10 border-red-500/30 text-red-400'
        )}>
          {nucleiStatus.available ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
          {nucleiStatus.available
            ? `nuclei ${nucleiStatus.version ?? 'ready'}`
            : `nuclei not found — ${nucleiStatus.hint}`}
        </div>
      )}

      <div className="space-y-3">
        <input
          className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
          placeholder="https://target.example.com or http://10.10.10.1"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <div className="space-y-1.5">
          <p className="text-[10px] text-zinc-500">Tags</p>
          <div className="flex flex-wrap gap-1.5">
            {ALL_TAGS.map((t) => (
              <button key={t} onClick={() => toggleTag(t)}
                className={clsx('px-2 py-0.5 text-[10px] rounded border transition-colors',
                  tags.includes(t) ? 'border-accent bg-accent/10 text-accent' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
                )}>
                {t}
              </button>
            ))}
          </div>
        </div>
        <div className="space-y-1.5">
          <p className="text-[10px] text-zinc-500">Severity</p>
          <div className="flex flex-wrap gap-1.5">
            {ALL_SEVERITY.map((s) => (
              <button key={s} onClick={() => toggleSev(s)}
                className={clsx('px-2 py-0.5 text-[10px] rounded border transition-colors capitalize',
                  severity.includes(s) ? 'border-accent bg-accent/10 text-accent' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
                )}>
                {s}
              </button>
            ))}
          </div>
        </div>
        <button onClick={() => runScan.mutate()} disabled={runScan.isPending || !target.trim() || !nucleiStatus?.available}
          className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {runScan.isPending ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
          Run Nuclei Scan
        </button>
      </div>

      {scanData && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <span className={clsx('text-[10px] px-2 py-0.5 rounded border',
              scanData.status === 'running' ? 'border-blue-500/40 bg-blue-500/10 text-blue-400' :
              scanData.status === 'complete' ? 'border-green-500/40 bg-green-500/10 text-green-400' :
              'border-red-500/40 bg-red-500/10 text-red-400'
            )}>
              {scanData.status.toUpperCase()}
            </span>
            <span className="text-xs text-zinc-400">{findings.length} findings</span>
            {scanData.status === 'running' && <Loader2 size={11} className="animate-spin text-accent" />}
          </div>

          {SEV_ORDER.map((s) => bySeverity[s].length > 0 && (
            <div key={s} className="space-y-1.5">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">{s} ({bySeverity[s].length})</p>
              {bySeverity[s].map((f, i) => {
                const info = f['info'] as Record<string, unknown> | undefined
                return (
                  <div key={i} className="rounded-lg border border-bg-border bg-bg-surface px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className={clsx('text-[10px] px-1.5 py-0.5 rounded font-semibold capitalize shrink-0', SEV_BADGE[s.toUpperCase()] ?? SEV_BADGE.UNKNOWN)}>
                        {s}
                      </span>
                      <span className="text-xs font-medium text-zinc-200">{String(info?.name ?? f['template-id'] ?? '')}</span>
                    </div>
                    <p className="text-[10px] text-zinc-400 mt-1">{String(f['matched-at'] ?? '')}</p>
                    {info?.description && <p className="text-[10px] text-zinc-500 mt-1">{String(info.description)}</p>}
                  </div>
                )
              })}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── ExploitDB Tab ──────────────────────────────────────────────────────────

function ExploitDBTab() {
  const [keyword, setKeyword] = useState('')
  const [results, setResults] = useState<{ id: string; title: string; type: string; date: string; url: string }[]>([])
  const [source, setSource]   = useState('')

  const search = useMutation({
    mutationFn: () => vulnIntelApi.exploitdbSearch(keyword),
    onSuccess: (data: { source: string; results: { id: string; title: string; type: string; date: string; url: string }[] }) => {
      setResults(data.results)
      setSource(data.source)
    },
  })

  return (
    <div className="space-y-5">
      <div className="flex gap-2">
        <input
          className="flex-1 bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
          placeholder="e.g. Apache 2.4.49, vsftpd 2.3.4, EternalBlue"
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && keyword.trim() && search.mutate()}
        />
        <button onClick={() => search.mutate()} disabled={search.isPending || !keyword.trim()}
          className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {search.isPending ? <Loader2 size={11} className="animate-spin" /> : <Search size={11} />}
          Search
        </button>
      </div>

      {results.length > 0 && (
        <div className="space-y-2">
          <p className="text-[10px] text-zinc-500">{results.length} results via {source}</p>
          <div className="rounded-xl border border-bg-border overflow-hidden">
            <div className="grid grid-cols-[4rem_1fr_6rem_5rem_2rem] text-[10px] text-zinc-500 uppercase tracking-wider px-4 py-2 bg-bg-elevated border-b border-bg-border">
              <span>EDB-ID</span><span>Title</span><span>Type</span><span>Date</span><span></span>
            </div>
            <div className="divide-y divide-bg-border/50">
              {results.map((r) => (
                <div key={r.id} className="grid grid-cols-[4rem_1fr_6rem_5rem_2rem] items-center px-4 py-2.5 bg-bg-surface hover:bg-bg-elevated transition-colors">
                  <span className="text-xs font-mono text-accent">{r.id}</span>
                  <span className="text-xs text-zinc-200 truncate pr-2">{r.title}</span>
                  <span className="text-[10px] text-zinc-500 capitalize">{r.type}</span>
                  <span className="text-[10px] text-zinc-600">{r.date?.slice(0, 10)}</span>
                  <a href={r.url} target="_blank" rel="noreferrer" className="text-zinc-600 hover:text-accent transition-colors">
                    <ExternalLink size={11} />
                  </a>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────

const TABS = [
  { id: 'cve',      label: 'CVE Search' },
  { id: 'nuclei',   label: 'Nuclei Scanner' },
  { id: 'exploitdb', label: 'ExploitDB' },
]

export default function VulnIntelPage() {
  const [tab, setTab] = useState('cve')

  return (
    <div className="h-full overflow-auto p-6">
      <div className="max-w-4xl space-y-5">
        <div className="flex items-center gap-2">
          <AlertOctagon size={18} className="text-accent" />
          <h1 className="text-base font-semibold text-zinc-100">Vulnerability Intelligence</h1>
        </div>
        <p className="text-xs text-zinc-500">NVD CVE lookup · version matching · Nuclei template scanning · ExploitDB search</p>

        <div className="flex gap-1 border-b border-bg-border">
          {TABS.map(({ id, label }) => (
            <button key={id} onClick={() => setTab(id)}
              className={clsx('px-4 py-2 text-xs font-medium rounded-t transition-colors border-b-2 -mb-px',
                tab === id ? 'border-accent text-accent bg-accent/5' : 'border-transparent text-zinc-500 hover:text-zinc-300'
              )}>
              {label}
            </button>
          ))}
        </div>

        <div className="pt-1">
          {tab === 'cve'       && <CVESearchTab />}
          {tab === 'nuclei'    && <NucleiTab />}
          {tab === 'exploitdb' && <ExploitDBTab />}
        </div>
      </div>
    </div>
  )
}

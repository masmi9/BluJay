import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2, AlertCircle, ChevronRight, ChevronDown, File, Folder, RefreshCw, ShieldAlert, Code2 } from 'lucide-react'
import { RiskScoreCard } from '@/components/analysis/RiskScoreCard'
import { riskApi } from '@/api/risk'
import { clsx } from 'clsx'
import { analysisApi } from '@/api/analysis'
import { iosApi } from '@/api/ios'
import { cveApi } from '@/api/cve'
import { Badge } from '@/components/common/Badge'
import { CodeBlock } from '@/components/common/CodeBlock'
import type { PermissionInfo, ComponentInfo, StaticFinding, SourceEntry } from '@/types/analysis'

const TABS = ['Overview', 'Manifest', 'Permissions', 'Components', 'Secrets', 'Source'] as const
type Tab = typeof TABS[number]

export default function StaticAnalysis() {
  const { id } = useParams<{ id: string }>()
  const analysisId = Number(id)
  const [tab, setTab] = useState<Tab>('Overview')
  const [sourcePath, setSourcePath] = useState('')
  const [openFile, setOpenFile] = useState<string | null>(null)
  const [reanalyzing, setReanalyzing] = useState(false)
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const { data: analysis, isLoading } = useQuery({
    queryKey: ['analysis', analysisId],
    queryFn: () => analysisApi.get(analysisId),
    refetchInterval: (q) => q.state.data?.status === 'complete' || q.state.data?.status === 'failed' ? false : 2000,
  })

  const handleReanalyze = async () => {
    setReanalyzing(true)
    try {
      await analysisApi.reanalyze(analysisId)
      queryClient.invalidateQueries({ queryKey: ['analysis', analysisId] })
      queryClient.invalidateQueries({ queryKey: ['findings', analysisId] })
      queryClient.invalidateQueries({ queryKey: ['permissions', analysisId] })
      queryClient.invalidateQueries({ queryKey: ['manifest', analysisId] })
    } finally {
      setReanalyzing(false)
    }
  }

  const { data: findings } = useQuery({
    queryKey: ['findings', analysisId],
    queryFn: () => analysisApi.getFindings(analysisId, { limit: 500 }),
    enabled: analysis?.status === 'complete',
  })

  const { data: permissions } = useQuery({
    queryKey: ['permissions', analysisId],
    queryFn: () => analysisApi.getPermissions(analysisId),
    enabled: analysis?.status === 'complete',
  })

  const { data: manifest } = useQuery({
    queryKey: ['manifest', analysisId],
    queryFn: () => analysisApi.getManifest(analysisId),
    enabled: analysis?.status === 'complete' && analysis?.platform !== 'ios',
  })

  const { data: infoPlist } = useQuery({
    queryKey: ['ipa-plist', analysisId],
    queryFn: () => iosApi.getPlist(analysisId),
    enabled: analysis?.status === 'complete' && analysis?.platform === 'ios',
  })

  const { data: cveSummary } = useQuery({
    queryKey: ['cve-summary', analysisId],
    queryFn: () => cveApi.getSummary(analysisId),
    enabled: analysis?.status === 'complete',
  })

  const { data: sourceEntries } = useQuery({
    queryKey: ['source', analysisId, sourcePath],
    queryFn: () => analysisApi.listSource(analysisId, sourcePath),
    enabled: tab === 'Source' && analysis?.status === 'complete',
  })

  const { data: fileContent } = useQuery({
    queryKey: ['file', analysisId, openFile],
    queryFn: () => analysisApi.readFile(analysisId, openFile!),
    enabled: !!openFile,
  })

  if (isLoading) return <div className="flex items-center justify-center h-64"><Loader2 className="animate-spin text-accent" /></div>
  if (!analysis) return <div className="p-6 text-zinc-400">Analysis not found</div>

  const isPending = analysis.status !== 'complete' && analysis.status !== 'failed'

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 pt-4 pb-0 border-b border-bg-border">
        <div className="flex items-center gap-3 mb-3">
          <h1 className="text-sm font-semibold text-zinc-200 truncate">{analysis.apk_filename}</h1>
          <Badge variant="severity" value={analysis.status === 'complete' ? 'info' : analysis.status === 'failed' ? 'critical' : 'medium'} />
          <div className="ml-auto flex items-center gap-2">
            {analysis.status === 'complete' && (
              <>
                <button
                  onClick={() => navigate(`/cve/${analysisId}`)}
                  className="flex items-center gap-1.5 px-2 py-1 text-xs text-zinc-500 hover:text-orange-400 rounded hover:bg-bg-elevated transition-colors"
                  title="CVE Correlation"
                >
                  <ShieldAlert size={12} />
                  CVE
                  {cveSummary && cveSummary.total_critical > 0 && (
                    <span className="px-1.5 py-0.5 rounded bg-red-600 text-white text-xs leading-none">
                      {cveSummary.total_critical}C
                    </span>
                  )}
                  {cveSummary && cveSummary.total_high > 0 && (
                    <span className="px-1.5 py-0.5 rounded bg-orange-500 text-white text-xs leading-none">
                      {cveSummary.total_high}H
                    </span>
                  )}
                </button>
                <button
                  onClick={() => navigate(`/webview/${analysisId}`)}
                  className="flex items-center gap-1 px-2 py-1 text-xs text-zinc-500 hover:text-blue-400 rounded hover:bg-bg-elevated transition-colors"
                  title="WebView JS Analysis"
                >
                  <Code2 size={12} /> WebView JS
                </button>
              </>
            )}
            <button
              onClick={handleReanalyze}
              disabled={reanalyzing || (analysis.status !== 'complete' && analysis.status !== 'failed')}
              title="Re-run analysis pipeline (clears existing findings)"
              className="flex items-center gap-1 px-2 py-1 text-xs text-zinc-500 hover:text-zinc-200 rounded hover:bg-bg-elevated disabled:opacity-40 transition-colors"
            >
              <RefreshCw size={12} className={reanalyzing ? 'animate-spin' : ''} />
              {reanalyzing ? 'Re-analyzing...' : 'Re-analyze'}
            </button>
          </div>
        </div>
        {isPending && (
          <div className="flex items-center gap-2 text-xs text-zinc-400 mb-3">
            <Loader2 size={12} className="animate-spin text-accent" />
            {analysis.status}...
          </div>
        )}
        <div className="flex gap-1">
          {TABS.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={clsx(
                'px-3 py-1.5 text-xs rounded-t-md transition-colors',
                tab === t ? 'bg-bg-base text-zinc-200 border-t border-x border-bg-border' : 'text-zinc-500 hover:text-zinc-300'
              )}
            >
              {t === 'Manifest' && analysis?.platform === 'ios' ? 'Info.plist' : t}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-auto p-6">
        {tab === 'Overview' && (
          <OverviewTab analysisId={analysisId} analysis={analysis} findings={findings?.items ?? []} />
        )}
        {tab === 'Manifest' && analysis?.platform === 'ios' && (
          <InfoPlistTab plist={infoPlist ?? {}} />
        )}
        {tab === 'Manifest' && analysis?.platform !== 'ios' && manifest && (
          <ManifestTab manifest={manifest} />
        )}
        {tab === 'Permissions' && (
          <PermissionsTab permissions={permissions ?? []} />
        )}
        {tab === 'Components' && manifest && (
          <ComponentsTab components={manifest.components} />
        )}
        {tab === 'Secrets' && (
          <SecretsTab findings={(findings?.items ?? []).filter(f => f.category !== 'dangerous_permission')} />
        )}
        {tab === 'Source' && (
          <SourceTab
            entries={sourceEntries ?? []}
            sourcePath={sourcePath}
            onNavigate={(p) => { setSourcePath(p); setOpenFile(null) }}
            onOpenFile={setOpenFile}
            openFile={openFile}
            fileContent={fileContent?.content}
          />
        )}
      </div>
    </div>
  )
}

function OverviewTab({ analysisId, analysis, findings }: { analysisId: number; analysis: any; findings: StaticFinding[] }) {
  const { data: riskScore } = useQuery({
    queryKey: ['risk-score', analysisId],
    queryFn: () => riskApi.getScore(analysisId),
    enabled: analysis?.status === 'complete',
  })
  const bySeverity = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  const isIos = analysis.platform === 'ios'
  const metaRows = isIos ? [
    ['Bundle ID', analysis.bundle_id],
    ['Min iOS', analysis.min_ios_version],
    ['SHA-256', analysis.apk_sha256],
  ] : [
    ['Package', analysis.package_name],
    ['Version', analysis.version_name],
    ['Min SDK', analysis.min_sdk],
    ['Target SDK', analysis.target_sdk],
    ['SHA-256', analysis.apk_sha256],
  ]

  return (
    <div className="space-y-6 max-w-2xl">
      {riskScore && (
        <RiskScoreCard analysisId={analysisId} score={riskScore} compact />
      )}
      <div className="grid grid-cols-2 gap-3">
        {metaRows.map(([k, v]) => (
          <div key={k} className={k === 'SHA-256' ? 'col-span-2 bg-bg-surface rounded-lg p-3 border border-bg-border' : 'bg-bg-surface rounded-lg p-3 border border-bg-border'}>
            <p className="text-xs text-zinc-500 mb-1">{k}</p>
            <p className="text-sm text-zinc-200 font-mono break-all">{v ?? '—'}</p>
          </div>
        ))}
      </div>
      <div>
        <h3 className="text-xs text-zinc-400 mb-2 uppercase tracking-wide">Findings</h3>
        <div className="flex gap-3">
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
            <div key={s} className="flex flex-col items-center bg-bg-surface rounded-lg p-3 border border-bg-border w-20">
              <span className="text-xl font-semibold font-mono">{bySeverity[s] || 0}</span>
              <Badge variant="severity" value={s} className="mt-1" />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function InfoPlistTab({ plist }: { plist: Record<string, unknown> }) {
  const highlight = [
    'CFBundleIdentifier', 'CFBundleName', 'CFBundleDisplayName',
    'CFBundleShortVersionString', 'CFBundleVersion', 'MinimumOSVersion',
    'CFBundleExecutable', 'DTXcode', 'UIRequiresFullScreen',
    'NSAppTransportSecurity', 'UIBackgroundModes',
  ]
  const highlighted = highlight.filter(k => k in plist)
  const rest = Object.keys(plist).filter(k => !highlight.includes(k)).sort()

  const renderValue = (v: unknown): string => {
    if (typeof v === 'object' && v !== null) return JSON.stringify(v, null, 2)
    return String(v)
  }

  return (
    <div className="space-y-4 max-w-3xl text-sm">
      <div className="grid grid-cols-2 gap-2">
        {highlighted.map(k => (
          <div key={k} className="bg-bg-surface p-3 rounded-lg border border-bg-border">
            <p className="text-xs text-zinc-500 mb-1">{k}</p>
            <p className="font-mono text-zinc-200 break-all text-xs">{renderValue(plist[k])}</p>
          </div>
        ))}
      </div>
      {rest.length > 0 && (
        <details className="group">
          <summary className="text-xs text-zinc-500 cursor-pointer select-none hover:text-zinc-300">
            {rest.length} more keys
          </summary>
          <div className="mt-2 grid grid-cols-2 gap-2">
            {rest.map(k => (
              <div key={k} className="bg-bg-surface p-3 rounded-lg border border-bg-border">
                <p className="text-xs text-zinc-500 mb-1">{k}</p>
                <p className="font-mono text-zinc-200 break-all text-xs">{renderValue(plist[k])}</p>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  )
}

function ManifestTab({ manifest }: { manifest: any }) {
  return (
    <div className="space-y-4 max-w-2xl text-sm">
      <div className="grid grid-cols-2 gap-2">
        {[
          ['Debuggable', manifest.debuggable ? '⚠ true' : 'false'],
          ['Allow Backup', manifest.allow_backup ? '⚠ true' : 'false'],
          ['Cleartext Traffic', manifest.uses_cleartext_traffic === null ? 'not set' : manifest.uses_cleartext_traffic ? '⚠ true' : 'false'],
          ['Network Security Config', manifest.network_security_config ? 'yes' : 'no'],
        ].map(([k, v]) => (
          <div key={k} className="bg-bg-surface p-3 rounded-lg border border-bg-border">
            <p className="text-xs text-zinc-500">{k}</p>
            <p className={clsx('font-mono', String(v).startsWith('⚠') ? 'text-yellow-400' : 'text-zinc-200')}>{v}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

function PermissionsTab({ permissions }: { permissions: PermissionInfo[] }) {
  const sorted = [...permissions].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, none: 4 }
    return (order[a.risk as keyof typeof order] ?? 5) - (order[b.risk as keyof typeof order] ?? 5)
  })

  return (
    <div className="space-y-1">
      {sorted.map((p) => (
        <div key={p.name} className="flex items-start gap-3 px-3 py-2 bg-bg-surface rounded border border-bg-border">
          <Badge variant="severity" value={p.risk === 'none' ? 'info' : p.risk} className="mt-0.5 shrink-0" />
          <div className="min-w-0">
            <p className="text-sm font-mono text-zinc-200 truncate">{p.short_name}</p>
            <p className="text-xs text-zinc-500">{p.description}</p>
          </div>
          <span className="text-xs text-zinc-600 shrink-0">{p.protection_level}</span>
        </div>
      ))}
    </div>
  )
}

function ComponentsTab({ components }: { components: ComponentInfo[] }) {
  const types = ['activity', 'service', 'receiver', 'provider'] as const
  const [type, setType] = useState<string>('activity')

  return (
    <div>
      <div className="flex gap-2 mb-4">
        {types.map((t) => (
          <button key={t} onClick={() => setType(t)}
            className={clsx('px-3 py-1 text-xs rounded', type === t ? 'bg-accent text-white' : 'bg-bg-surface text-zinc-400 hover:text-zinc-200')}>
            {t}
          </button>
        ))}
      </div>
      <div className="space-y-1">
        {components.filter((c) => c.type === type).map((c, i) => (
          <div key={i} className="flex items-center gap-3 px-3 py-2 bg-bg-surface rounded border border-bg-border">
            {c.exported && !c.permission && <AlertCircle size={12} className="text-yellow-400 shrink-0" />}
            <span className="text-xs font-mono text-zinc-300 truncate flex-1">{c.name}</span>
            {c.exported && <span className="text-xs text-yellow-400 shrink-0">exported</span>}
            {c.permission && <span className="text-xs text-zinc-500 shrink-0 truncate max-w-48">{c.permission}</span>}
          </div>
        ))}
      </div>
    </div>
  )
}

function SecretsTab({ findings }: { findings: StaticFinding[] }) {
  const [expanded, setExpanded] = useState<number | null>(null)
  const [detailTab, setDetailTab] = useState<Record<number, 'description' | 'impact' | 'attack_path'>>({})

  const getTab = (id: number) => detailTab[id] ?? 'description'
  const setTab = (id: number, t: 'description' | 'impact' | 'attack_path') =>
    setDetailTab((prev) => ({ ...prev, [id]: t }))

  return (
    <div className="space-y-1">
      {findings.map((f) => (
        <div key={f.id} className="bg-bg-surface rounded border border-bg-border overflow-hidden">
          <div
            className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-bg-elevated"
            onClick={() => setExpanded(expanded === f.id ? null : f.id)}
          >
            <Badge variant="severity" value={f.severity} className="shrink-0" />
            <span className="text-sm text-zinc-200 flex-1 truncate">{f.title}</span>
            {f.file_path && (
              <span className="text-xs text-zinc-500 font-mono truncate max-w-48">
                {f.file_path}{f.line_number ? `:${f.line_number}` : ''}
              </span>
            )}
            {expanded === f.id
              ? <ChevronDown size={12} className="text-zinc-500 shrink-0" />
              : <ChevronRight size={12} className="text-zinc-500 shrink-0" />}
          </div>

          {expanded === f.id && (
            <div className="border-t border-bg-border">
              {/* Sub-tabs */}
              <div className="flex gap-0 border-b border-bg-border">
                {(['description', 'impact', 'attack_path'] as const).map((t) => {
                  const label = t === 'attack_path' ? 'Attack Path' : t.charAt(0).toUpperCase() + t.slice(1)
                  const available = t === 'description' || !!f[t]
                  return (
                    <button
                      key={t}
                      onClick={(e) => { e.stopPropagation(); setTab(f.id, t) }}
                      disabled={!available}
                      className={clsx(
                        'px-3 py-1.5 text-xs transition-colors disabled:opacity-30',
                        getTab(f.id) === t
                          ? 'bg-bg-base text-zinc-200'
                          : 'text-zinc-500 hover:text-zinc-300'
                      )}
                    >
                      {label}
                    </button>
                  )
                })}
              </div>

              <div className="px-3 pb-3 pt-2 space-y-2">
                {getTab(f.id) === 'description' && (
                  <>
                    <p className="text-xs text-zinc-400">{f.description}</p>
                    {f.evidence && (() => {
                      try {
                        const ev = JSON.parse(f.evidence)
                        return <CodeBlock code={ev.context || ev.match || ''} language="markup" className="text-xs" />
                      } catch { return null }
                    })()}
                  </>
                )}

                {getTab(f.id) === 'impact' && f.impact && (
                  <p className="text-xs text-zinc-300 leading-relaxed">{f.impact}</p>
                )}

                {getTab(f.id) === 'attack_path' && f.attack_path && (
                  <ol className="space-y-1">
                    {f.attack_path.split(/\d+\.\s+/).filter(Boolean).map((step, i) => (
                      <li key={i} className="flex gap-2 text-xs text-zinc-300">
                        <span className="text-zinc-600 shrink-0 font-mono">{i + 1}.</span>
                        <span className="leading-relaxed">{step.trim()}</span>
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            </div>
          )}
        </div>
      ))}
      {findings.length === 0 && <p className="text-zinc-500 text-sm">No findings</p>}
    </div>
  )
}

function SourceTab({ entries, sourcePath, onNavigate, onOpenFile, openFile, fileContent }: {
  entries: SourceEntry[]
  sourcePath: string
  onNavigate: (p: string) => void
  onOpenFile: (p: string) => void
  openFile: string | null
  fileContent: string | undefined
}) {
  const ext = openFile?.split('.').pop() || 'markup'
  const lang = ext === 'java' ? 'java' : ext === 'smali' ? 'markup' : ext === 'xml' ? 'markup' : ext === 'json' ? 'json' : 'markup'

  return (
    <div className="flex gap-4 h-full min-h-96">
      <div className="w-64 shrink-0 overflow-auto space-y-0.5">
        {sourcePath && (
          <button
            className="flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300 px-2 py-1 w-full"
            onClick={() => onNavigate(sourcePath.split('/').slice(0, -1).join('/'))}
          >
            ← ..
          </button>
        )}
        {entries.map((e) => (
          <button
            key={e.path}
            className="flex items-center gap-2 text-xs px-2 py-1 w-full rounded hover:bg-bg-elevated text-left truncate"
            onClick={() => e.is_dir ? onNavigate(e.path) : onOpenFile(e.path)}
          >
            {e.is_dir ? <Folder size={12} className="text-zinc-500 shrink-0" /> : <File size={12} className="text-zinc-600 shrink-0" />}
            <span className="truncate text-zinc-300">{e.path.split('/').pop()}</span>
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-auto">
        {fileContent ? (
          <CodeBlock code={fileContent} language={lang} className="h-full" />
        ) : (
          <div className="text-zinc-600 text-sm p-4">Select a file to view its source</div>
        )}
      </div>
    </div>
  )
}

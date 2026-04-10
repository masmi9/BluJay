import { useState, useEffect, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Shield, Play, Trash2, ChevronDown, ChevronRight, Loader2, AlertCircle, ExternalLink, RefreshCw, Smartphone, Package } from 'lucide-react'
import { clsx } from 'clsx'
import { owaspApi } from '@/api/owasp'
import { analysisApi } from '@/api/analysis'
import { adbApi } from '@/api/adb'
import { iosApi } from '@/api/ios'
import type { OwaspScanSummary, OwaspFinding } from '@/types/owasp'

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  info: 'text-zinc-400 bg-zinc-500/10 border-zinc-500/30',
}

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-400',
  high: 'bg-orange-400',
  medium: 'bg-yellow-400',
  low: 'bg-blue-400',
  info: 'bg-zinc-400',
}

function bySev(scan: OwaspScanSummary, sev: string): number {
  return scan.by_severity?.[sev] ?? 0
}

export default function OwaspScan() {
  const qc = useQueryClient()
  const [apkPath, setApkPath] = useState('')
  const [packageName, setPackageName] = useState('')
  const [mode, setMode] = useState('safe')
  const [analysisId, setAnalysisId] = useState<string>('')
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  // Platform toggle
  const [platform, setPlatform] = useState<'android' | 'ios'>('android')

  // Android device + package picker state
  const [selectedSerial, setSelectedSerial] = useState<string>('')
  const [pkgSearch, setPkgSearch] = useState('')
  const [pkgPickerOpen, setPkgPickerOpen] = useState(false)

  // iOS device + app picker state
  const [selectedUdid, setSelectedUdid] = useState<string>('')
  const [iosAppSearch, setIosAppSearch] = useState('')
  const [iosAppPickerOpen, setIosAppPickerOpen] = useState(false)
  const [selectedScan, setSelectedScan] = useState<number | null>(null)
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null)
  const [progressMap, setProgressMap] = useState<Record<number, number>>({})
  const wsRefs = useRef<Record<number, WebSocket>>({})

  const { data: analyses = [] } = useQuery({
    queryKey: ['analyses-list'],
    queryFn: () => analysisApi.list(),
  })

  const { data: devices = [] } = useQuery({
    queryKey: ['devices'],
    queryFn: () => adbApi.listDevices(),
    refetchInterval: 10000,
  })

  const { data: iosDevices = [] } = useQuery({
    queryKey: ['ios-devices'],
    queryFn: () => iosApi.listDevices(),
    refetchInterval: 10000,
  })

  const { data: devicePackages = [], isFetching: fetchingPkgs } = useQuery({
    queryKey: ['device-packages', selectedSerial],
    queryFn: () => adbApi.listPackages(selectedSerial, true),
    enabled: !!selectedSerial && pkgPickerOpen,
    staleTime: 30000,
  })

  const { data: iosApps = [], isFetching: fetchingIosApps } = useQuery({
    queryKey: ['ios-apps', selectedUdid],
    queryFn: () => iosApi.listApps(selectedUdid),
    enabled: !!selectedUdid && iosAppPickerOpen,
    staleTime: 30000,
  })

  const { data: scans = [], refetch: refetchScans } = useQuery({
    queryKey: ['owasp-scans'],
    queryFn: () => owaspApi.list(),
    refetchInterval: 8000,
  })

  const { data: scanDetail } = useQuery({
    queryKey: ['owasp-scan', selectedScan],
    queryFn: () => owaspApi.get(selectedScan!),
    enabled: !!selectedScan,
    refetchInterval: (data) =>
      data?.status === 'running' || data?.status === 'pending' ? 4000 : false,
  })

  const { data: findingsPage } = useQuery({
    queryKey: ['owasp-findings', selectedScan, severityFilter],
    queryFn: () => owaspApi.getFindings(selectedScan!, {
      severity: severityFilter === 'all' ? undefined : severityFilter,
      limit: 200,
    }),
    enabled: !!selectedScan,
  })

  // Connect WebSocket for running scans
  useEffect(() => {
    const running = scans.filter((s) => s.status === 'running' || s.status === 'pending')
    running.forEach((scan) => {
      if (wsRefs.current[scan.id]) return
      const ws = new WebSocket(`ws://localhost:8000/ws/owasp/${scan.id}`)
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (typeof msg.progress === 'number') {
            setProgressMap((p) => ({ ...p, [scan.id]: msg.progress }))
          }
          if (msg.status === 'complete' || msg.status === 'error') {
            qc.invalidateQueries({ queryKey: ['owasp-scans'] })
            qc.invalidateQueries({ queryKey: ['owasp-scan', scan.id] })
            ws.close()
            delete wsRefs.current[scan.id]
          }
        } catch { /* ignore */ }
      }
      ws.onclose = () => { delete wsRefs.current[scan.id] }
      wsRefs.current[scan.id] = ws
    })
    return () => { /* cleanup handled on close */ }
  }, [scans, qc])

  const handlePickPackage = (pkg: { package: string; apk_path: string }) => {
    setPackageName(pkg.package)
    setApkPath(pkg.apk_path)
    setPkgPickerOpen(false)
    setPkgSearch('')
  }

  const handlePickIosApp = (app: { bundle_id: string; name: string }) => {
    setPackageName(app.bundle_id)
    setIosAppPickerOpen(false)
    setIosAppSearch('')
  }

  const handleStart = async () => {
    if (!packageName) {
      setFormError('Package name is required')
      return
    }
    if (!selectedSerial && !apkPath) {
      setFormError('Either select a device to pull from, or enter an APK path')
      return
    }
    setSubmitting(true)
    setFormError(null)
    try {
      const { id } = await owaspApi.start(
        apkPath,
        packageName,
        mode,
        analysisId ? Number(analysisId) : undefined,
        platform === 'android' ? (selectedSerial || undefined) : undefined,
        platform
      )
      await refetchScans()
      setSelectedScan(id)
    } catch (e: any) {
      setFormError(e?.response?.data?.detail ?? e?.message ?? 'Failed to start scan')
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation()
    await owaspApi.delete(id)
    qc.invalidateQueries({ queryKey: ['owasp-scans'] })
    if (selectedScan === id) setSelectedScan(null)
  }

  const findings = findingsPage?.items ?? []

  return (
    <div className="flex h-full overflow-hidden">
      {/* Left — scan list + new scan form */}
      <div className="w-72 shrink-0 border-r border-bg-border flex flex-col bg-bg-surface">
        {/* New Scan Form */}
        <div className="p-4 border-b border-bg-border">
          <div className="flex items-center gap-2 mb-4">
            <Shield size={16} className="text-accent" />
            <h2 className="text-sm font-semibold text-zinc-200">OWASP Scanner</h2>
          </div>

          {/* Platform toggle */}
          <div className="mb-3 flex rounded border border-bg-border overflow-hidden text-xs">
            {(['android', 'ios'] as const).map((p) => (
              <button
                key={p}
                onClick={() => { setPlatform(p); setSelectedSerial(''); setSelectedUdid(''); setPackageName(''); setApkPath('') }}
                className={clsx(
                  'flex-1 py-1.5 capitalize transition-colors',
                  platform === p ? 'bg-accent/20 text-accent' : 'text-zinc-400 hover:text-zinc-200'
                )}
              >
                {p === 'android' ? 'Android' : 'iOS'}
              </button>
            ))}
          </div>

          {/* Device app picker */}
          <div className="mb-3 p-2.5 bg-bg-elevated rounded border border-bg-border">
            <p className="text-[10px] text-zinc-500 uppercase font-medium mb-2 flex items-center gap-1.5">
              <Smartphone size={10} /> Auto-fill from device
            </p>

            {platform === 'android' ? (
              <>
                <label className="block text-xs text-zinc-500 mb-1">Device</label>
                <select
                  className="w-full bg-bg-base border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 mb-2 focus:outline-none focus:border-accent"
                  value={selectedSerial}
                  onChange={(e) => { setSelectedSerial(e.target.value); setPkgPickerOpen(false) }}
                >
                  <option value="">— select device —</option>
                  {devices.map((d) => (
                    <option key={d.serial} value={d.serial}>
                      {d.model ?? d.serial} ({d.state})
                    </option>
                  ))}
                </select>

                {selectedSerial && (
                  <>
                    <button
                      onClick={() => setPkgPickerOpen((o) => !o)}
                      className="w-full flex items-center justify-between px-2 py-1.5 bg-bg-base border border-bg-border rounded text-xs text-zinc-300 hover:border-accent/50 transition-colors"
                    >
                      <span className="flex items-center gap-1.5 text-zinc-400">
                        <Package size={10} />
                        {packageName || 'Pick installed package…'}
                      </span>
                      {fetchingPkgs
                        ? <Loader2 size={11} className="animate-spin text-zinc-500" />
                        : <ChevronDown size={11} className="text-zinc-500" />}
                    </button>

                    {pkgPickerOpen && (
                      <div className="mt-1 border border-bg-border rounded overflow-hidden bg-bg-base">
                        <input
                          autoFocus
                          className="w-full px-2 py-1.5 text-xs bg-bg-elevated border-b border-bg-border text-zinc-200 focus:outline-none"
                          placeholder="Filter packages…"
                          value={pkgSearch}
                          onChange={(e) => setPkgSearch(e.target.value)}
                        />
                        <div className="max-h-40 overflow-auto">
                          {fetchingPkgs ? (
                            <div className="flex justify-center py-3">
                              <Loader2 size={14} className="animate-spin text-accent" />
                            </div>
                          ) : devicePackages
                              .filter((p) => p.package.toLowerCase().includes(pkgSearch.toLowerCase()))
                              .map((p) => (
                                <button
                                  key={p.package}
                                  onClick={() => handlePickPackage(p)}
                                  className="w-full text-left px-2 py-1.5 text-xs text-zinc-300 hover:bg-bg-elevated truncate border-b border-bg-border/50 last:border-b-0"
                                >
                                  {p.package}
                                </button>
                              ))
                          }
                          {!fetchingPkgs && devicePackages.filter((p) => p.package.toLowerCase().includes(pkgSearch.toLowerCase())).length === 0 && (
                            <p className="text-xs text-zinc-600 text-center py-3">No packages found</p>
                          )}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </>
            ) : (
              <>
                <label className="block text-xs text-zinc-500 mb-1">iOS Device</label>
                <select
                  className="w-full bg-bg-base border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 mb-2 focus:outline-none focus:border-accent"
                  value={selectedUdid}
                  onChange={(e) => { setSelectedUdid(e.target.value); setIosAppPickerOpen(false) }}
                >
                  <option value="">— select device —</option>
                  {iosDevices.map((d) => (
                    <option key={d.udid} value={d.udid}>
                      {d.name ?? d.udid}{d.ios_version ? ` (iOS ${d.ios_version})` : ''}
                    </option>
                  ))}
                </select>

                {selectedUdid && (
                  <>
                    <button
                      onClick={() => setIosAppPickerOpen((o) => !o)}
                      className="w-full flex items-center justify-between px-2 py-1.5 bg-bg-base border border-bg-border rounded text-xs text-zinc-300 hover:border-accent/50 transition-colors"
                    >
                      <span className="flex items-center gap-1.5 text-zinc-400">
                        <Package size={10} />
                        {packageName || 'Pick installed app…'}
                      </span>
                      {fetchingIosApps
                        ? <Loader2 size={11} className="animate-spin text-zinc-500" />
                        : <ChevronDown size={11} className="text-zinc-500" />}
                    </button>

                    {iosAppPickerOpen && (
                      <div className="mt-1 border border-bg-border rounded overflow-hidden bg-bg-base">
                        <input
                          autoFocus
                          className="w-full px-2 py-1.5 text-xs bg-bg-elevated border-b border-bg-border text-zinc-200 focus:outline-none"
                          placeholder="Filter apps…"
                          value={iosAppSearch}
                          onChange={(e) => setIosAppSearch(e.target.value)}
                        />
                        <div className="max-h-40 overflow-auto">
                          {fetchingIosApps ? (
                            <div className="flex justify-center py-3">
                              <Loader2 size={14} className="animate-spin text-accent" />
                            </div>
                          ) : iosApps
                              .filter((a) =>
                                a.bundle_id.toLowerCase().includes(iosAppSearch.toLowerCase()) ||
                                a.name.toLowerCase().includes(iosAppSearch.toLowerCase())
                              )
                              .map((a) => (
                                <button
                                  key={a.bundle_id}
                                  onClick={() => handlePickIosApp(a)}
                                  className="w-full text-left px-2 py-1.5 text-xs text-zinc-300 hover:bg-bg-elevated border-b border-bg-border/50 last:border-b-0"
                                >
                                  <span className="block truncate">{a.name}</span>
                                  <span className="block text-[10px] text-zinc-500 truncate">{a.bundle_id}</span>
                                </button>
                              ))
                          }
                          {!fetchingIosApps && iosApps.filter((a) =>
                            a.bundle_id.toLowerCase().includes(iosAppSearch.toLowerCase()) ||
                            a.name.toLowerCase().includes(iosAppSearch.toLowerCase())
                          ).length === 0 && (
                            <p className="text-xs text-zinc-600 text-center py-3">No apps found</p>
                          )}
                        </div>
                      </div>
                    )}
                </>
                )}
              </>
            )}
          </div>

          <label className="block text-xs text-zinc-500 mb-1">
            {platform === 'ios' ? 'IPA Path' : 'APK Path (on device)'}
          </label>
          <input
            className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 font-mono mb-2 focus:outline-none focus:border-accent"
            placeholder={platform === 'ios' ? 'C:\\path\\to\\app.ipa' : '/data/app/com.example-1/base.apk'}
            value={apkPath}
            onChange={(e) => setApkPath(e.target.value)}
          />

          <label className="block text-xs text-zinc-500 mb-1">Package Name</label>
          <input
            className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 font-mono mb-2 focus:outline-none focus:border-accent"
            placeholder="com.example.app"
            value={packageName}
            onChange={(e) => setPackageName(e.target.value)}
          />

          <label className="block text-xs text-zinc-500 mb-1">Mode</label>
          <select
            className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 mb-2"
            value={mode}
            onChange={(e) => setMode(e.target.value)}
          >
            <option value="deep">Deep (full analysis)</option>
            <option value="safe">Safe (faster, non-destructive)</option>
          </select>

          <label className="block text-xs text-zinc-500 mb-1">Link to Analysis (optional)</label>
          <select
            className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 mb-3"
            value={analysisId}
            onChange={(e) => setAnalysisId(e.target.value)}
          >
            <option value="">— none —</option>
            {analyses.map((a: any) => (
              <option key={a.id} value={a.id}>{a.package_name ?? `#${a.id}`}</option>
            ))}
          </select>

          {formError && (
            <div className="flex items-start gap-2 mb-2 p-2 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
              <AlertCircle size={12} className="mt-0.5 shrink-0" />
              {formError}
            </div>
          )}

          <button
            onClick={handleStart}
            disabled={submitting}
            className="w-full flex items-center justify-center gap-2 py-2 text-xs font-medium bg-accent/20 text-accent rounded hover:bg-accent/30 disabled:opacity-40 transition-colors"
          >
            {submitting ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
            {submitting ? 'Starting...' : 'Start Scan'}
          </button>
        </div>

        {/* Scan List */}
        <div className="flex-1 overflow-auto">
          {scans.length === 0 && (
            <p className="text-xs text-zinc-600 p-4 text-center">No scans yet</p>
          )}
          {scans.map((scan) => (
            <ScanListItem
              key={scan.id}
              scan={scan}
              selected={selectedScan === scan.id}
              progress={progressMap[scan.id]}
              onClick={() => setSelectedScan(scan.id)}
              onDelete={(e) => handleDelete(scan.id, e)}
            />
          ))}
        </div>
      </div>

      {/* Right — findings */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {!selectedScan ? (
          <div className="flex flex-col items-center justify-center h-full text-zinc-600 gap-2">
            <Shield size={32} />
            <p className="text-sm">Select a scan or start a new one</p>
          </div>
        ) : !scanDetail ? (
          <div className="flex justify-center pt-16"><Loader2 className="animate-spin text-accent" /></div>
        ) : (
          <>
            {/* Header */}
            <div className="px-4 py-3 border-b border-bg-border bg-bg-surface shrink-0 flex items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <p className="text-sm font-medium text-zinc-200">{scanDetail.package_name}</p>
                  <span className={clsx(
                    'text-[10px] px-1.5 py-0.5 rounded border capitalize',
                    scanDetail.platform === 'ios'
                      ? 'text-sky-400 bg-sky-500/10 border-sky-500/30'
                      : 'text-green-400 bg-green-500/10 border-green-500/30'
                  )}>
                    {scanDetail.platform ?? 'android'}
                  </span>
                </div>
                <p className="text-xs text-zinc-500 font-mono truncate max-w-md">{scanDetail.apk_path}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <StatusChip status={scanDetail.status} />
                {scanDetail.has_html && (
                  <a
                    href={owaspApi.reportUrl(scanDetail.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 text-xs text-accent hover:underline"
                  >
                    <ExternalLink size={12} /> HTML Report
                  </a>
                )}
                <button
                  onClick={() => { qc.invalidateQueries({ queryKey: ['owasp-scan', selectedScan] }); qc.invalidateQueries({ queryKey: ['owasp-findings', selectedScan, severityFilter] }) }}
                  className="p-1 rounded text-zinc-500 hover:text-zinc-200 hover:bg-bg-elevated"
                >
                  <RefreshCw size={13} />
                </button>
              </div>
            </div>

            {/* Severity summary */}
            {scanDetail.status === 'complete' && (
              <div className="px-4 py-2 border-b border-bg-border bg-bg-base shrink-0 flex items-center gap-4">
                {(['critical','high','medium','low','info'] as const).map((sev) => {
                  const count = bySev(scanDetail, sev)
                  if (!count) return null
                  return (
                    <button
                      key={sev}
                      onClick={() => setSeverityFilter(severityFilter === sev ? 'all' : sev)}
                      className={clsx(
                        'flex items-center gap-1.5 px-2 py-1 rounded text-xs border transition-colors',
                        severityFilter === sev
                          ? SEVERITY_COLOR[sev]
                          : 'text-zinc-400 border-bg-border hover:border-zinc-600'
                      )}
                    >
                      <span className={clsx('w-1.5 h-1.5 rounded-full', SEVERITY_DOT[sev])} />
                      {count} {sev}
                    </button>
                  )
                })}
                {severityFilter !== 'all' && (
                  <button onClick={() => setSeverityFilter('all')} className="text-xs text-zinc-500 hover:text-zinc-300">
                    clear filter
                  </button>
                )}
              </div>
            )}

            {/* Findings list */}
            <div className="flex-1 overflow-auto p-4 space-y-2">
              {scanDetail.status === 'running' || scanDetail.status === 'pending' ? (
                <div className="flex flex-col items-center justify-center h-48 gap-3 text-zinc-500">
                  <Loader2 className="animate-spin text-accent" size={24} />
                  <p className="text-sm">Scan in progress… {progressMap[selectedScan] != null ? `${progressMap[selectedScan]}%` : ''}</p>
                </div>
              ) : scanDetail.status === 'failed' ? (
                <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
                  <AlertCircle size={12} className="mt-0.5 shrink-0" />
                  {(scanDetail as any).error ?? 'Scan failed'}
                </div>
              ) : findings.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-48 text-zinc-600 gap-2">
                  <Shield size={24} />
                  <p className="text-sm">No findings{severityFilter !== 'all' ? ` for severity: ${severityFilter}` : ''}</p>
                </div>
              ) : (
                findings.map((f, idx) => (
                  <FindingCard
                    key={f.id ?? idx}
                    finding={f}
                    expanded={expandedFinding === (f.id ?? idx)}
                    onToggle={() => setExpandedFinding(expandedFinding === (f.id ?? idx) ? null : (f.id ?? idx))}
                  />
                ))
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function ScanListItem({
  scan, selected, progress, onClick, onDelete
}: {
  scan: OwaspScanSummary
  selected: boolean
  progress?: number
  onClick: () => void
  onDelete: (e: React.MouseEvent) => void
}) {
  return (
    <div
      onClick={onClick}
      className={clsx(
        'px-3 py-2.5 border-b border-bg-border cursor-pointer hover:bg-bg-elevated transition-colors',
        selected && 'bg-bg-elevated border-l-2 border-l-accent'
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-medium text-zinc-200 truncate flex-1">{scan.package_name}</p>
        <div className="flex items-center gap-1 shrink-0">
          <span className={clsx(
            'text-[10px] px-1 rounded border capitalize',
            scan.platform === 'ios'
              ? 'text-sky-400 bg-sky-500/10 border-sky-500/30'
              : 'text-green-400 bg-green-500/10 border-green-500/30'
          )}>
            {scan.platform ?? 'android'}
          </span>
          <StatusChip status={scan.status} small />
          <button
            onClick={onDelete}
            className="p-0.5 rounded text-zinc-600 hover:text-red-400 transition-colors"
          >
            <Trash2 size={11} />
          </button>
        </div>
      </div>
      {(scan.status === 'running' || scan.status === 'pending') && progress != null && (
        <div className="mt-1.5 h-0.5 bg-bg-border rounded-full overflow-hidden">
          <div className="h-full bg-accent transition-all" style={{ width: `${progress}%` }} />
        </div>
      )}
      {scan.status === 'complete' && (
        <div className="flex gap-2 mt-1">
          {(['critical','high','medium','low'] as const).map((sev) => {
            const count = bySev(scan, sev)
            if (!count) return null
            return (
              <span key={sev} className={clsx('text-[10px] px-1 rounded border', SEVERITY_COLOR[sev])}>
                {count} {sev[0].toUpperCase()}
              </span>
            )
          })}
        </div>
      )}
      <p className="text-[10px] text-zinc-600 mt-1">{new Date(scan.created_at).toLocaleString()}</p>
    </div>
  )
}

function StatusChip({ status, small }: { status: string; small?: boolean }) {
  const map: Record<string, string> = {
    complete: 'text-green-400 bg-green-500/10',
    running: 'text-yellow-400 bg-yellow-500/10',
    pending: 'text-zinc-400 bg-zinc-500/10',
    failed: 'text-red-400 bg-red-500/10',
  }
  return (
    <span className={clsx('rounded px-1.5 py-0.5 font-mono capitalize', small ? 'text-[10px]' : 'text-xs', map[status] ?? 'text-zinc-400')}>
      {status}
    </span>
  )
}

function FindingCard({ finding, expanded, onToggle }: { finding: OwaspFinding; expanded: boolean; onToggle: () => void }) {
  const sev = (finding.severity ?? finding.risk_level ?? 'info').toLowerCase()
  const title = finding.title ?? finding.name ?? 'Unknown Finding'
  const category = finding.category ?? finding.type
  const cweLabel = finding.cwe_id ?? (finding.cwe_name ? `CWE: ${finding.cwe_name}` : null)
  return (
    <div className="bg-bg-surface rounded border border-bg-border overflow-hidden">
      <div
        className="flex items-start gap-3 px-3 py-2.5 cursor-pointer hover:bg-bg-elevated"
        onClick={onToggle}
      >
        <span className={clsx('w-1.5 h-1.5 rounded-full mt-1.5 shrink-0', SEVERITY_DOT[sev] ?? 'bg-zinc-400')} />
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-zinc-200">{title}</p>
          {category && (
            <p className="text-[10px] text-zinc-500 mt-0.5">{category}</p>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {cweLabel && (
            <span className="text-[10px] font-mono text-zinc-600">{cweLabel}</span>
          )}
          <span className={clsx('text-[10px] px-1.5 py-0.5 rounded border capitalize', SEVERITY_COLOR[sev] ?? SEVERITY_COLOR.info)}>
            {sev}
          </span>
          {expanded ? <ChevronDown size={12} className="text-zinc-500" /> : <ChevronRight size={12} className="text-zinc-500" />}
        </div>
      </div>
      {expanded && (
        <div className="border-t border-bg-border bg-bg-base px-3 py-3 space-y-3">
          {finding.description && (
            <div>
              <p className="text-[10px] text-zinc-500 uppercase mb-1 font-medium">Description</p>
              <p className="text-xs text-zinc-300 leading-relaxed">{finding.description}</p>
            </div>
          )}
          {finding.evidence && (
            <div>
              <p className="text-[10px] text-zinc-500 uppercase mb-1 font-medium">Evidence</p>
              <pre className="text-xs font-mono text-zinc-300 whitespace-pre-wrap break-all bg-bg-elevated rounded p-2 max-h-40 overflow-auto">
                {typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence, null, 2)}
              </pre>
            </div>
          )}
          {finding.remediation && (
            <div>
              <p className="text-[10px] text-zinc-500 uppercase mb-1 font-medium">Remediation</p>
              <p className="text-xs text-zinc-400 leading-relaxed">{finding.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

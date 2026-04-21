import { useState, useCallback, useMemo } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Upload, CheckCircle, XCircle, Loader2, Package, Smartphone, Search, ArrowRight, Tablet, ShieldCheck, ShieldOff, Trash2, Zap } from 'lucide-react'
import { clsx } from 'clsx'
import { analysisApi } from '@/api/analysis'
import { adbApi, sessionApi } from '@/api/adb'
import { iosApi } from '@/api/ios'
import { proxyApi } from '@/api/proxy'
import { useDeviceStore } from '@/store/deviceStore'
import type { Analysis } from '@/types/analysis'
import type { IosDeviceInfo } from '@/types/adb'
import { format } from 'date-fns'

function StatusIcon({ status }: { status: Analysis['status'] }) {
  if (status === 'complete') return <CheckCircle size={14} className="text-green-400" />
  if (status === 'failed') return <XCircle size={14} className="text-red-400" />
  return <Loader2 size={14} className="text-accent animate-spin" />
}

export default function Dashboard() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [pulling, setPulling] = useState(false)
  const [deletingId, setDeletingId] = useState<number | null>(null)
  const [selectedPackage, setSelectedPackage] = useState('')
  const [packageSearch, setPackageSearch] = useState('')
  const [showAllPackages, setShowAllPackages] = useState(false)

  // iOS app search state
  const [iosAppSearch, setIosAppSearch] = useState('')
  const [selectedIosUdid, setSelectedIosUdid] = useState<string>('')
  const [selectedBundleId, setSelectedBundleId] = useState('')
  const [iosPulling, setIosPulling] = useState(false)
  const [iosDynStarting, setIosDynStarting] = useState(false)
  const [iosIpaFile, setIosIpaFile] = useState<File | null>(null)

  const { devices, selectedSerial, selectDevice } = useDeviceStore()

  // Auto-select the first connected device
  const connectedDevices = devices.filter((d) => d.state === 'device')
  const effectiveSerial = selectedSerial ?? connectedDevices[0]?.serial ?? null

  const { data: analyses = [], refetch } = useQuery({
    queryKey: ['analyses'],
    queryFn: analysisApi.list,
    refetchInterval: 3000,
  })

  // Fetch device list on this page too so it populates even without TopBar polling
  useQuery({
    queryKey: ['devices'],
    queryFn: async () => {
      const devs = await adbApi.listDevices()
      useDeviceStore.getState().setDevices(devs)
      return devs
    },
    refetchInterval: 5000,
  })

  const { data: iosDevices = [] } = useQuery<IosDeviceInfo[]>({
    queryKey: ['ios-devices'],
    queryFn: iosApi.listDevices,
    refetchInterval: 5000,
  })

  const effectiveIosUdid = selectedIosUdid || iosDevices[0]?.udid || ''

  const { data: iosApps = [], isFetching: iosAppsLoading } = useQuery({
    queryKey: ['ios-apps', effectiveIosUdid],
    queryFn: () => iosApi.listApps(effectiveIosUdid),
    enabled: !!effectiveIosUdid,
    staleTime: 30_000,
  })

  const filteredIosApps = useMemo(() => {
    if (!iosAppSearch) return iosApps
    const q = iosAppSearch.toLowerCase()
    return iosApps.filter(
      (a) => a.bundle_id.toLowerCase().includes(q) || a.name.toLowerCase().includes(q)
    )
  }, [iosApps, iosAppSearch])

  // Fetch package list for selected device
  const { data: packages = [], isFetching: packagesLoading } = useQuery({
    queryKey: ['packages', effectiveSerial, showAllPackages],
    queryFn: () => adbApi.listPackages(effectiveSerial!, !showAllPackages),
    enabled: !!effectiveSerial,
    staleTime: 30_000,
  })

  const filteredPackages = useMemo(() => {
    if (!packageSearch) return packages
    const q = packageSearch.toLowerCase()
    return packages.filter((p) => p.package.toLowerCase().includes(q))
  }, [packages, packageSearch])

  const handleFile = useCallback(async (file: File) => {
    const isApk = file.name.endsWith('.apk')
    const isIpa = file.name.endsWith('.ipa')
    if (!isApk && !isIpa) return
    setUploading(true)
    try {
      const result = isIpa
        ? await iosApi.uploadIpa(file)
        : await analysisApi.upload(file)
      refetch()
      navigate(`/analysis/${result.id}`)
    } finally {
      setUploading(false)
    }
  }, [navigate, refetch])

  const handlePullAndAnalyze = useCallback(async () => {
    if (!effectiveSerial || !selectedPackage) return
    setPulling(true)
    try {
      const result = await analysisApi.fromDevice(effectiveSerial, selectedPackage)
      refetch()
      navigate(`/analysis/${result.id}`)
    } catch (err: any) {
      alert(`Failed to pull APK: ${err.message}`)
    } finally {
      setPulling(false)
    }
  }, [effectiveSerial, selectedPackage, navigate, refetch])

  const handleIosPullAndAnalyze = useCallback(async () => {
    if (!effectiveIosUdid || !selectedBundleId) return
    setIosPulling(true)
    try {
      const result = await iosApi.pullAndAnalyze(effectiveIosUdid, selectedBundleId)
      refetch()
      navigate(`/analysis/${result.id}`)
    } catch (err: any) {
      alert(`Failed to pull IPA: ${err?.response?.data?.detail ?? err.message}`)
    } finally {
      setIosPulling(false)
    }
  }, [effectiveIosUdid, selectedBundleId, navigate, refetch])

  const handleIosDynamicSession = useCallback(async () => {
    if (!effectiveIosUdid || !selectedBundleId) return
    setIosDynStarting(true)
    try {
      // 1. Create dynamic session — starts idevicesyslog, no IPA pull needed
      const session = await sessionApi.create({
        deviceSerial: effectiveIosUdid,
        packageName: selectedBundleId,
        platform: 'ios',
      })

      // 2. Start mitmproxy for traffic interception
      await proxyApi.start(session.id)

      // 3. If the user already has an uploaded IPA analysis for this bundle, kick off
      //    IODS deep scan linked to it. Otherwise they can trigger it from the OWASP
      //    page after uploading the IPA manually.
      if (iosIpaFile) {
        const uploaded = await iosApi.uploadIpa(iosIpaFile)
        await iosApi.startOwaspScan({
          udid: effectiveIosUdid,
          bundleId: selectedBundleId,
          ipaPath: '',
          analysisId: uploaded.id,
        })
      }

      refetch()
      navigate(`/dynamic/${session.id}`)
    } catch (err: any) {
      alert(`Failed to start iOS dynamic session: ${err?.response?.data?.detail ?? err.message}`)
    } finally {
      setIosDynStarting(false)
    }
  }, [effectiveIosUdid, selectedBundleId, iosIpaFile, navigate, refetch])

  const handleDelete = useCallback(async (e: React.MouseEvent, id: number) => {
    e.stopPropagation()
    setDeletingId(id)
    try {
      await analysisApi.delete(id)
      queryClient.invalidateQueries({ queryKey: ['analyses'] })
    } finally {
      setDeletingId(null)
    }
  }, [queryClient])

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <h1 className="text-lg font-semibold text-zinc-100">Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {/* --- Upload APK / IPA --- */}
        <div className="space-y-2">
          <h2 className="text-xs text-zinc-500 uppercase tracking-wide">Upload APK / IPA</h2>
          <div
            className={clsx(
              'border-2 border-dashed rounded-xl p-8 flex flex-col items-center gap-3 transition-colors cursor-pointer',
              dragging ? 'border-accent bg-accent/10' : 'border-bg-border hover:border-zinc-600'
            )}
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            onClick={() => {
              const input = document.createElement('input')
              input.type = 'file'
              input.accept = '.apk,.ipa'
              input.onchange = (e) => {
                const file = (e.target as HTMLInputElement).files?.[0]
                if (file) handleFile(file)
              }
              input.click()
            }}
          >
            {uploading ? (
              <Loader2 size={28} className="text-accent animate-spin" />
            ) : (
              <Upload size={28} className="text-zinc-500" />
            )}
            <p className="text-sm text-zinc-400 text-center">
              {uploading ? 'Uploading and analysing...' : 'Drop an APK or IPA here, or click to browse'}
            </p>
          </div>
        </div>

        {/* --- From Device --- */}
        <div className="space-y-2">
          <h2 className="text-xs text-zinc-500 uppercase tracking-wide">From Connected Device</h2>
          <div className="bg-bg-surface rounded-xl border border-bg-border p-4 space-y-3 h-full min-h-36">
            {connectedDevices.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-28 gap-2 text-zinc-600">
                <Smartphone size={24} />
                <p className="text-sm">No device connected</p>
                <p className="text-xs text-center">Connect an Android device or start an emulator, then run <code className="font-mono text-zinc-500">adb devices</code></p>
              </div>
            ) : (
              <>
                {/* Device selector */}
                {connectedDevices.length > 1 && (
                  <select
                    className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200"
                    value={effectiveSerial ?? ''}
                    onChange={(e) => selectDevice(e.target.value)}
                  >
                    {connectedDevices.map((d) => (
                      <option key={d.serial} value={d.serial}>
                        {d.model ? `${d.model} (${d.serial})` : d.serial}
                      </option>
                    ))}
                  </select>
                )}

                {connectedDevices.length === 1 && (
                  <div className="flex items-center gap-2 text-xs text-green-400">
                    <Smartphone size={12} />
                    <span>{connectedDevices[0].model || connectedDevices[0].serial}</span>
                    <span className="text-zinc-600">({connectedDevices[0].serial})</span>
                  </div>
                )}

                {/* Package search */}
                <div className="relative">
                  <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
                  <input
                    className="w-full bg-bg-elevated border border-bg-border rounded pl-7 pr-2 py-1.5 text-xs text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-accent"
                    placeholder={packagesLoading ? 'Loading packages...' : `Search ${packages.length} apps...`}
                    value={packageSearch}
                    onChange={(e) => { setPackageSearch(e.target.value); setSelectedPackage('') }}
                    disabled={packagesLoading}
                  />
                </div>

                {/* Package list */}
                {packageSearch && filteredPackages.length > 0 && (
                  <div className="max-h-40 overflow-y-auto rounded border border-bg-border bg-bg-elevated divide-y divide-bg-border">
                    {filteredPackages.slice(0, 50).map((p) => (
                      <button
                        key={p.package}
                        className={clsx(
                          'w-full text-left px-3 py-2 text-xs font-mono truncate hover:bg-bg-base transition-colors',
                          selectedPackage === p.package ? 'text-accent bg-accent/10' : 'text-zinc-300'
                        )}
                        onClick={() => { setSelectedPackage(p.package); setPackageSearch(p.package) }}
                      >
                        {p.package}
                      </button>
                    ))}
                    {filteredPackages.length > 50 && (
                      <p className="px-3 py-1.5 text-xs text-zinc-600">{filteredPackages.length - 50} more — type more to narrow</p>
                    )}
                  </div>
                )}

                {/* Toggle all/3rd-party */}
                <div className="flex items-center justify-between gap-2">
                  <label className="flex items-center gap-1.5 text-xs text-zinc-500 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={showAllPackages}
                      onChange={(e) => { setShowAllPackages(e.target.checked); setSelectedPackage(''); setPackageSearch('') }}
                      className="accent-accent"
                    />
                    Show system apps
                  </label>

                  <button
                    onClick={handlePullAndAnalyze}
                    disabled={!selectedPackage || pulling}
                    className={clsx(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors',
                      selectedPackage && !pulling
                        ? 'bg-accent hover:bg-accent-hover text-white'
                        : 'bg-bg-elevated text-zinc-600 cursor-not-allowed'
                    )}
                  >
                    {pulling ? (
                      <><Loader2 size={12} className="animate-spin" /> Pulling APK...</>
                    ) : (
                      <><ArrowRight size={12} /> Pull &amp; Analyze</>
                    )}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
        {/* --- iOS Device --- */}
        <div className="space-y-2">
          <h2 className="text-xs text-zinc-500 uppercase tracking-wide">iOS Device</h2>
          <div className="bg-bg-surface rounded-xl border border-bg-border p-4 space-y-3 h-full min-h-36">
            {iosDevices.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-28 gap-2 text-zinc-600">
                <Tablet size={24} />
                <p className="text-sm">No iOS device detected</p>
                <p className="text-xs text-center">Connect an iPhone and install <code className="font-mono text-zinc-500">libimobiledevice</code></p>
              </div>
            ) : (
              <div className="space-y-3">
                {/* Device selector / info */}
                {iosDevices.length > 1 ? (
                  <select
                    className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200"
                    value={effectiveIosUdid}
                    onChange={(e) => { setSelectedIosUdid(e.target.value); setIosAppSearch('') }}
                  >
                    {iosDevices.map((d) => (
                      <option key={d.udid} value={d.udid}>
                        {d.name || d.model || d.udid}
                        {d.ios_version ? ` (iOS ${d.ios_version})` : ''}
                      </option>
                    ))}
                  </select>
                ) : (
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-xs text-blue-400">
                      <Tablet size={12} />
                      <span className="font-medium">{iosDevices[0].name || iosDevices[0].model || 'iPhone'}</span>
                      {iosDevices[0].ios_version && (
                        <span className="text-zinc-500">iOS {iosDevices[0].ios_version}</span>
                      )}
                    </div>
                    {iosDevices[0].jailbroken ? (
                      <div className="flex items-center gap-1 text-xs text-amber-400">
                        <ShieldOff size={11} /><span>Jailbroken</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 text-xs text-zinc-500">
                        <ShieldCheck size={11} /><span>Not jailbroken</span>
                      </div>
                    )}
                  </div>
                )}

                {/* App search */}
                <div className="relative">
                  <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
                  <input
                    className="w-full bg-bg-elevated border border-bg-border rounded pl-7 pr-2 py-1.5 text-xs text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-accent"
                    placeholder={iosAppsLoading ? 'Loading apps...' : `Search ${iosApps.length} apps...`}
                    value={iosAppSearch}
                    onChange={(e) => setIosAppSearch(e.target.value)}
                    disabled={iosAppsLoading}
                  />
                </div>

                {/* App list */}
                {iosAppSearch && filteredIosApps.length > 0 && (
                  <div className="max-h-40 overflow-y-auto rounded border border-bg-border bg-bg-elevated divide-y divide-bg-border">
                    {filteredIosApps.slice(0, 50).map((a) => (
                      <button
                        key={a.bundle_id}
                        className={clsx(
                          'w-full text-left px-3 py-2 text-xs hover:bg-bg-base transition-colors',
                          selectedBundleId === a.bundle_id ? 'bg-accent/10' : ''
                        )}
                        onClick={() => { setSelectedBundleId(a.bundle_id); setIosAppSearch(a.name) }}
                      >
                        <p className={clsx('truncate font-medium', selectedBundleId === a.bundle_id ? 'text-accent' : 'text-zinc-200')}>{a.name}</p>
                        <p className="text-zinc-500 font-mono truncate">{a.bundle_id}</p>
                      </button>
                    ))}
                    {filteredIosApps.length > 50 && (
                      <p className="px-3 py-1.5 text-xs text-zinc-600">{filteredIosApps.length - 50} more — type more to narrow</p>
                    )}
                  </div>
                )}

                {iosAppSearch && filteredIosApps.length === 0 && !iosAppsLoading && (
                  <p className="text-xs text-zinc-600 text-center py-2">No apps found</p>
                )}

                {/* Optional IPA for IODS — used when device pull isn't supported */}
                <div
                  className="flex items-center gap-2 border border-dashed border-bg-border rounded px-2 py-1.5 cursor-pointer hover:border-zinc-500 transition-colors"
                  onClick={() => {
                    const input = document.createElement('input')
                    input.type = 'file'
                    input.accept = '.ipa'
                    input.onchange = (e) => {
                      const f = (e.target as HTMLInputElement).files?.[0]
                      if (f) setIosIpaFile(f)
                    }
                    input.click()
                  }}
                >
                  <Upload size={11} className="text-zinc-500 shrink-0" />
                  <span className="text-[10px] text-zinc-500 truncate">
                    {iosIpaFile ? iosIpaFile.name : 'Attach IPA for IODS scan (optional)'}
                  </span>
                  {iosIpaFile && (
                    <button
                      className="ml-auto text-zinc-600 hover:text-zinc-400"
                      onClick={(e) => { e.stopPropagation(); setIosIpaFile(null) }}
                    >×</button>
                  )}
                </div>

                <div className="flex justify-end gap-2">
                  <button
                    onClick={handleIosPullAndAnalyze}
                    disabled={!selectedBundleId || iosPulling || iosDynStarting}
                    className={clsx(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors',
                      selectedBundleId && !iosPulling && !iosDynStarting
                        ? 'bg-bg-elevated hover:bg-bg-border text-zinc-300 border border-bg-border'
                        : 'bg-bg-elevated text-zinc-600 cursor-not-allowed border border-bg-border'
                    )}
                  >
                    {iosPulling ? (
                      <><Loader2 size={12} className="animate-spin" /> Pulling...</>
                    ) : (
                      <><ArrowRight size={12} /> Pull &amp; Analyze</>
                    )}
                  </button>
                  <button
                    onClick={handleIosDynamicSession}
                    disabled={!selectedBundleId || iosDynStarting || iosPulling}
                    className={clsx(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors',
                      selectedBundleId && !iosDynStarting && !iosPulling
                        ? 'bg-accent hover:bg-accent-hover text-white'
                        : 'bg-bg-elevated text-zinc-600 cursor-not-allowed'
                    )}
                  >
                    {iosDynStarting ? (
                      <><Loader2 size={12} className="animate-spin" /> Starting...</>
                    ) : (
                      <><Zap size={12} /> Dynamic Session</>
                    )}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent analyses */}
      {analyses.length > 0 && (
        <div>
          <h2 className="text-sm font-medium text-zinc-400 mb-3">Recent Analyses</h2>
          <div className="space-y-2">
            {analyses.map((a) => (
              <div
                key={a.id}
                className="flex items-center gap-3 px-4 py-3 bg-bg-surface rounded-lg border border-bg-border hover:border-zinc-600 cursor-pointer transition-colors"
                onClick={() => navigate(`/analysis/${a.id}`)}
              >
                <Package size={16} className="text-zinc-500 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-zinc-200 truncate">{a.apk_filename}</p>
                  <p className="text-xs text-zinc-500">{a.package_name || a.apk_sha256.slice(0, 16) + '...'}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <StatusIcon status={a.status} />
                  <span className="text-xs text-zinc-500">
                    {format(new Date(a.created_at), 'MMM d, HH:mm')}
                  </span>
                  <button
                    onClick={(e) => handleDelete(e, a.id)}
                    disabled={deletingId === a.id}
                    className="p-1 rounded text-zinc-600 hover:text-red-400 hover:bg-red-400/10 transition-colors disabled:opacity-40"
                    title="Delete analysis"
                  >
                    {deletingId === a.id
                      ? <Loader2 size={13} className="animate-spin" />
                      : <Trash2 size={13} />}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

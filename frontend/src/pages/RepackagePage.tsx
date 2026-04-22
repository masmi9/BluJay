import { useState } from 'react'
import axios from 'axios'
import { useQuery } from '@tanstack/react-query'
import { analysisApi } from '@/api/analysis'
import { Download, Play, Loader2, CheckCircle, XCircle } from 'lucide-react'
import { clsx } from 'clsx'

interface Job {
  id: number
  status: string
  patches: string[]
  signed_apk: string | null
  error: string | null
  warning: string | null
}

export default function RepackagePage() {
  const [analysisId, setAnalysisId] = useState('')
  const [sslBypass, setSslBypass] = useState(true)
  const [rootBypass, setRootBypass] = useState(false)
  const [debuggable, setDebuggable] = useState(true)
  const [backupEnabled, setBackupEnabled] = useState(false)
  const [jobId, setJobId] = useState<number | null>(null)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState('')

  const { data: analyses = [] } = useQuery({
    queryKey: ['analyses'],
    queryFn: analysisApi.list,
  })
  const androidAnalyses = analyses.filter((a: any) => a.platform === 'android' && a.status === 'complete')

  const { data: job, refetch } = useQuery<Job>({
    queryKey: ['repackage-job', jobId],
    queryFn: async () => {
      const r = await axios.get(`/api/v1/repackage/${jobId}/status`)
      return r.data
    },
    enabled: jobId !== null,
    refetchInterval: (q) => {
      const s = (q as any).state?.data?.status
      return (s === 'running' || s === 'pending') ? 2000 : false
    },
  })

  const start = async () => {
    if (!analysisId) { setError('Select an analysis first'); return }
    setError('')
    setStarting(true)
    try {
      const r = await axios.post('/api/v1/repackage/start', {
        analysis_id: parseInt(analysisId),
        ssl_bypass: sslBypass,
        root_bypass: rootBypass,
        debuggable,
        backup_enabled: backupEnabled,
      })
      setJobId(r.data.job_id)
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setStarting(false)
    }
  }

  const download = () => {
    window.open(`/api/v1/repackage/${jobId}/download`, '_blank')
  }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-6">
      <div>
        <h2 className="text-sm font-semibold text-zinc-100 mb-1">APK Repackage + Resign</h2>
        <p className="text-xs text-zinc-500">Decode, patch, recompile, and re-sign an APK with a debug keystore.</p>
      </div>

      {/* Analysis selector */}
      <div className="space-y-2">
        <label className="text-xs text-zinc-400">Target Analysis (Android only)</label>
        <select
          value={analysisId}
          onChange={e => setAnalysisId(e.target.value)}
          aria-label="Target analysis"
          className="w-full bg-bg-elevated border border-bg-border rounded-lg px-3 py-2 text-sm text-zinc-200"
        >
          <option value="">— select —</option>
          {androidAnalyses.map((a: any) => (
            <option key={a.id} value={a.id}>
              {a.apk_filename} ({a.package_name || 'unknown'})
            </option>
          ))}
        </select>
      </div>

      {/* Patch options */}
      <div className="bg-bg-surface border border-bg-border rounded-xl p-4 space-y-3">
        <p className="text-xs font-medium text-zinc-400 uppercase tracking-wide">Patches</p>
        {[
          { key: 'ssl', label: 'SSL Pinning Bypass', desc: 'Injects network_security_config.xml to trust all CAs including user-installed', val: sslBypass, set: setSslBypass },
          { key: 'root', label: 'Root Detection Bypass', desc: 'Stubs common root-check methods in smali (isRooted, checkRoot, etc.)', val: rootBypass, set: setRootBypass },
          { key: 'debug', label: 'Force Debuggable', desc: 'Sets android:debuggable="true" in AndroidManifest.xml', val: debuggable, set: setDebuggable },
          { key: 'backup', label: 'Enable ADB Backup', desc: 'Sets android:allowBackup="true" for adb backup extraction', val: backupEnabled, set: setBackupEnabled },
        ].map(({ key, label, desc, val, set }) => (
          <label key={key} className="flex items-start gap-3 cursor-pointer group">
            <div className="mt-0.5">
              <input
                type="checkbox"
                checked={val}
                onChange={e => set(e.target.checked)}
                className="accent-accent"
              />
            </div>
            <div>
              <div className="text-sm text-zinc-200">{label}</div>
              <div className="text-xs text-zinc-500">{desc}</div>
            </div>
          </label>
        ))}
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <button
        onClick={start}
        disabled={starting || job?.status === 'running' || job?.status === 'pending'}
        className="flex items-center gap-2 px-4 py-2 bg-accent text-white text-sm rounded-lg hover:bg-accent/80 disabled:opacity-50"
      >
        {starting ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
        Start Repackage
      </button>

      {/* Job status */}
      {job && (
        <div className="bg-bg-surface border border-bg-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            {job.status === 'done' && <CheckCircle size={14} className="text-green-400" />}
            {job.status === 'error' && <XCircle size={14} className="text-red-400" />}
            {(job.status === 'running' || job.status === 'pending') && <Loader2 size={14} className="animate-spin text-accent" />}
            <span className={clsx('text-sm font-medium', {
              'text-green-400': job.status === 'done',
              'text-red-400': job.status === 'error',
              'text-zinc-300': job.status === 'running' || job.status === 'pending',
            })}>
              {job.status.toUpperCase()}
            </span>
          </div>

          {job.patches.length > 0 && (
            <div>
              <p className="text-xs text-zinc-500 mb-1">Patches applied:</p>
              <div className="flex flex-wrap gap-1">
                {job.patches.map(p => (
                  <span key={p} className="text-xs bg-accent/10 text-accent border border-accent/20 px-2 py-0.5 rounded">{p}</span>
                ))}
              </div>
            </div>
          )}

          {job.warning && <p className="text-xs text-yellow-400">{job.warning}</p>}
          {job.error && <p className="text-xs text-red-400">{job.error}</p>}

          {job.status === 'done' && (
            <button
              onClick={download}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white text-sm rounded-lg hover:bg-green-500"
            >
              <Download size={14} />
              Download Patched APK
            </button>
          )}
        </div>
      )}
    </div>
  )
}

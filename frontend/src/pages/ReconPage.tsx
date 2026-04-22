import { useState } from 'react'
import axios from 'axios'
import { useQuery } from '@tanstack/react-query'
import { analysisApi } from '@/api/analysis'
import { Play, Loader2, Globe, Cloud, AlertTriangle } from 'lucide-react'
import { clsx } from 'clsx'

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-blue-400',
  info:     'text-zinc-400',
}

export default function ReconPage() {
  const [target, setTarget] = useState('')
  const [packageName, setPackageName] = useState('')
  const [checkSubdomains, setCheckSubdomains] = useState(true)
  const [checkBuckets, setCheckBuckets] = useState(true)
  const [jobId, setJobId] = useState<number | null>(null)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState('')

  const { data: analyses = [] } = useQuery({
    queryKey: ['analyses'],
    queryFn: analysisApi.list,
  })

  const { data: job } = useQuery({
    queryKey: ['recon-job', jobId],
    queryFn: async () => {
      const r = await axios.get(`/api/v1/recon/${jobId}`)
      return r.data
    },
    enabled: jobId !== null,
    refetchInterval: (q: any) => q?.state?.data?.status === 'running' ? 3000 : false,
  })

  const fillFromAnalysis = (id: string) => {
    const a = (analyses as any[]).find(x => String(x.id) === id)
    if (!a) return
    setPackageName(a.package_name || '')
  }

  const run = async () => {
    if (!target) { setError('Enter a target domain or URL'); return }
    setError('')
    setStarting(true)
    try {
      const r = await axios.post('/api/v1/recon/start', {
        target,
        package_name: packageName || null,
        check_subdomains: checkSubdomains,
        check_buckets: checkBuckets,
        resolve_hosts: true,
      })
      setJobId(r.data.job_id)
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setStarting(false)
    }
  }

  const result = job?.result

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-5">
      <div>
        <h2 className="text-sm font-semibold text-zinc-100 mb-1">Passive Recon</h2>
        <p className="text-xs text-zinc-500">
          Subdomain enumeration (crt.sh / certificate transparency) + cloud bucket discovery (S3, GCS, Azure).
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-3">
          <div className="space-y-1">
            <label className="text-xs text-zinc-400">Target Domain / URL</label>
            <input
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="api.target.com or https://api.target.com"
              className="w-full bg-bg-elevated border border-bg-border rounded-lg px-3 py-2 text-sm font-mono text-zinc-200"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-zinc-400">Package / App Name (for bucket guessing)</label>
            <input
              value={packageName}
              onChange={e => setPackageName(e.target.value)}
              placeholder="com.example.app or just example"
              className="w-full bg-bg-elevated border border-bg-border rounded-lg px-3 py-2 text-sm font-mono text-zinc-200"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-zinc-400">Pre-fill from Analysis</label>
            <select
              onChange={e => fillFromAnalysis(e.target.value)}
              aria-label="Pre-fill from analysis"
              className="w-full bg-bg-elevated border border-bg-border rounded-lg px-3 py-2 text-sm text-zinc-200"
            >
              <option value="">— select analysis —</option>
              {(analyses as any[]).filter(a => a.status === 'complete').map((a: any) => (
                <option key={a.id} value={a.id}>{a.apk_filename} ({a.package_name || 'unknown'})</option>
              ))}
            </select>
          </div>
        </div>

        <div className="space-y-3">
          <p className="text-xs text-zinc-400 font-medium">Options</p>
          {[
            { label: 'Subdomain enumeration (crt.sh)', val: checkSubdomains, set: setCheckSubdomains },
            { label: 'Cloud bucket discovery (S3 / GCS / Azure)', val: checkBuckets, set: setCheckBuckets },
          ].map(({ label, val, set }) => (
            <label key={label} className="flex items-center gap-2 cursor-pointer text-sm text-zinc-300">
              <input type="checkbox" checked={val} onChange={e => set(e.target.checked)} className="accent-accent" />
              {label}
            </label>
          ))}
        </div>
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <button
        onClick={run}
        disabled={starting || job?.status === 'running'}
        className="flex items-center gap-2 px-4 py-2 bg-accent text-white text-sm rounded-lg hover:bg-accent/80 disabled:opacity-50"
      >
        {starting || job?.status === 'running'
          ? <Loader2 size={14} className="animate-spin" />
          : <Play size={14} />}
        {job?.status === 'running' ? 'Running…' : 'Start Recon'}
      </button>

      {job?.status === 'error' && (
        <p className="text-xs text-red-400">Error: {job.error}</p>
      )}

      {result && (
        <div className="space-y-5">
          {/* Findings */}
          {result.findings?.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs text-zinc-500 uppercase tracking-wide font-medium flex items-center gap-2">
                <AlertTriangle size={11} /> Findings ({result.findings.length})
              </p>
              {result.findings.map((f: any, i: number) => (
                <div key={i} className="flex items-start gap-3 bg-bg-surface border border-bg-border rounded-lg p-3">
                  <span className={clsx('text-xs font-semibold mt-0.5 w-14 shrink-0', SEV_COLOR[f.severity])}>{f.severity.toUpperCase()}</span>
                  <div className="min-w-0">
                    <p className="text-sm text-zinc-200 font-mono truncate">{f.host}</p>
                    <p className="text-xs text-zinc-500 mt-0.5">{f.detail}</p>
                  </div>
                  {f.status_code && <span className="ml-auto text-xs text-zinc-500 shrink-0">HTTP {f.status_code}</span>}
                </div>
              ))}
            </div>
          )}

          {/* Subdomains */}
          {result.subdomains?.length > 0 && (
            <div>
              <p className="text-xs text-zinc-500 uppercase tracking-wide font-medium flex items-center gap-2 mb-2">
                <Globe size={11} /> Subdomains ({result.subdomains.length})
              </p>
              <div className="bg-bg-surface border border-bg-border rounded-lg overflow-hidden">
                <div className="divide-y divide-bg-border max-h-64 overflow-y-auto">
                  {result.subdomains.map((sub: string) => {
                    const resolved = result.resolved_hosts?.find((h: any) => h.host === sub)
                    return (
                      <div key={sub} className="flex items-center justify-between px-3 py-1.5 text-xs">
                        <span className="font-mono text-zinc-300">{sub}</span>
                        {resolved && <span className="text-zinc-500">{resolved.ip}</span>}
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Open Buckets */}
          {result.open_buckets?.length > 0 && (
            <div>
              <p className="text-xs text-zinc-500 uppercase tracking-wide font-medium flex items-center gap-2 mb-2">
                <Cloud size={11} /> Exposed Buckets ({result.open_buckets.length})
              </p>
              <div className="space-y-2">
                {result.open_buckets.map((b: any, i: number) => (
                  <div key={i} className={clsx('border rounded-lg p-3', b.listing_enabled ? 'border-red-400/30 bg-red-400/5' : 'border-orange-400/30 bg-orange-400/5')}>
                    <div className="flex items-center gap-2">
                      <span className={clsx('text-xs font-semibold', b.listing_enabled ? 'text-red-400' : 'text-orange-400')}>
                        HTTP {b.status} {b.listing_enabled ? '— LISTING ENABLED' : '— PUBLIC'}
                      </span>
                    </div>
                    <p className="text-xs font-mono text-zinc-300 mt-1 break-all">{b.url}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.findings?.length === 0 && result.subdomains?.length === 0 && result.open_buckets?.length === 0 && (
            <p className="text-sm text-zinc-500">No results found for this target.</p>
          )}
        </div>
      )}
    </div>
  )
}

import { useState, useCallback } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Crosshair, Play, Loader2, Trash2, ChevronDown, RefreshCw, Plus, X } from 'lucide-react'
import { clsx } from 'clsx'
import Editor from '@monaco-editor/react'

const BASE = '/api/v1/intruder'

const ATTACK_TYPES = [
  { id: 'sniper',       label: 'Sniper',        desc: 'One list, one position at a time' },
  { id: 'battering_ram', label: 'Battering Ram', desc: 'Same payload into all positions' },
  { id: 'pitchfork',    label: 'Pitchfork',      desc: 'Parallel lists, zipped together' },
  { id: 'cluster_bomb', label: 'Cluster Bomb',   desc: 'All combinations — use carefully' },
] as const
type AttackType = typeof ATTACK_TYPES[number]['id']

const DEFAULT_REQUEST = `GET /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=§admin§&password=§password§`

interface Result {
  idx: number
  payloads: string[]
  status: number | null
  length: number
  time_ms: number
  error: string | null
}

interface Job {
  job_id: string
  status: string
  total: number
  completed: number
  results: Result[]
  error: string | null
}

const STATUS_COLOR = (s: number | null) => {
  if (!s) return 'text-zinc-600'
  if (s < 300) return 'text-green-400'
  if (s < 400) return 'text-blue-400'
  if (s < 500) return 'text-yellow-400'
  return 'text-red-400'
}

export default function IntruderPage() {
  const [targetUrl, setTargetUrl] = useState('https://example.com')
  const [rawRequest, setRawRequest] = useState(DEFAULT_REQUEST)
  const [attackType, setAttackType] = useState<AttackType>('sniper')
  const [payloadLists, setPayloadLists] = useState<string[]>(['admin\nroot\ntest\nguest'])
  const [concurrency, setConcurrency] = useState(10)
  const [jobId, setJobId] = useState<string | null>(null)
  const [sortCol, setSortCol] = useState<keyof Result>('idx')
  const [sortAsc, setSortAsc] = useState(true)

  const { data: job, refetch } = useQuery<Job>({
    queryKey: ['intruder-job', jobId],
    queryFn: async () => {
      const r = await fetch(`${BASE}/jobs/${jobId}`)
      if (!r.ok) throw new Error(await r.text())
      return r.json()
    },
    enabled: !!jobId,
    refetchInterval: (q) => q.state.data?.status === 'running' ? 800 : false,
  })

  const { data: allJobs = [] } = useQuery<Job[]>({
    queryKey: ['intruder-jobs'],
    queryFn: async () => {
      const r = await fetch(`${BASE}/jobs`)
      return r.json()
    },
  })

  const run = useMutation({
    mutationFn: async () => {
      const r = await fetch(`${BASE}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl,
          raw_request: rawRequest,
          payloads: payloadLists.map((l) => l.split('\n').map((s) => s.trim()).filter(Boolean)),
          attack_type: attackType,
          concurrency,
        }),
      })
      if (!r.ok) {
        const body = await r.json().catch(() => ({ detail: r.statusText }))
        throw new Error(body.detail ?? r.statusText)
      }
      return r.json() as Promise<Job>
    },
    onSuccess: (j) => setJobId(j.job_id),
  })

  const clearJob = async (id: string) => {
    await fetch(`${BASE}/jobs/${id}`, { method: 'DELETE' })
    if (jobId === id) setJobId(null)
    refetch()
  }

  const addPayloadList = () => setPayloadLists((l) => [...l, ''])
  const removePayloadList = (i: number) => setPayloadLists((l) => l.filter((_, idx) => idx !== i))
  const updatePayloadList = (i: number, val: string) => setPayloadLists((l) => l.map((v, idx) => idx === i ? val : v))

  const sortedResults = [...(job?.results ?? [])].sort((a, b) => {
    const av = a[sortCol] ?? 0
    const bv = b[sortCol] ?? 0
    return sortAsc ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1)
  })

  const handleSort = (col: keyof Result) => {
    if (sortCol === col) setSortAsc((s) => !s)
    else { setSortCol(col); setSortAsc(true) }
  }

  const ColHeader = ({ col, label }: { col: keyof Result; label: string }) => (
    <th
      className="px-3 py-2 text-left text-[10px] text-zinc-500 uppercase tracking-wide cursor-pointer hover:text-zinc-300 select-none"
      onClick={() => handleSort(col)}
    >
      {label} {sortCol === col ? (sortAsc ? '↑' : '↓') : ''}
    </th>
  )

  return (
    <div className="flex h-full overflow-hidden">
      {/* Config panel */}
      <div className="w-80 shrink-0 border-r border-bg-border bg-bg-surface flex flex-col overflow-y-auto">
        <div className="p-4 space-y-4">
          <div className="flex items-center gap-2">
            <Crosshair size={14} className="text-red-400" />
            <h1 className="text-sm font-semibold text-zinc-200">Intruder</h1>
          </div>

          {/* Target */}
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Target URL</label>
            <input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-red-500 font-mono"
            />
          </div>

          {/* Attack type */}
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Attack Type</label>
            <div className="space-y-1">
              {ATTACK_TYPES.map(({ id, label, desc }) => (
                <label key={id} className={clsx(
                  'flex items-start gap-2 p-2 rounded cursor-pointer border transition-colors text-xs',
                  attackType === id ? 'border-red-500/40 bg-red-500/10 text-zinc-200' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
                )}>
                  <input type="radio" name="attack" value={id} checked={attackType === id} onChange={() => setAttackType(id)} className="mt-0.5 accent-red-500" />
                  <div>
                    <p className="font-medium">{label}</p>
                    <p className="text-zinc-600 text-[10px]">{desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Payload lists */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs text-zinc-400">Payload Lists</label>
              <button onClick={addPayloadList} className="text-xs text-zinc-500 hover:text-zinc-300 flex items-center gap-0.5">
                <Plus size={10} /> Add
              </button>
            </div>
            <div className="space-y-2">
              {payloadLists.map((list, i) => (
                <div key={i}>
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-[10px] text-zinc-600">List {i + 1} ({list.split('\n').filter(Boolean).length} entries)</span>
                    {payloadLists.length > 1 && (
                      <button onClick={() => removePayloadList(i)} className="text-zinc-600 hover:text-red-400">
                        <X size={10} />
                      </button>
                    )}
                  </div>
                  <textarea
                    value={list}
                    onChange={(e) => updatePayloadList(i, e.target.value)}
                    rows={5}
                    placeholder="One payload per line"
                    className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-red-500 font-mono resize-none"
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Concurrency */}
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Concurrency: {concurrency}</label>
            <input type="range" min={1} max={50} value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value))} className="w-full accent-red-500" />
          </div>

          {run.error && <p className="text-xs text-red-400">{(run.error as Error).message}</p>}

          <button
            onClick={() => run.mutate()}
            disabled={run.isPending}
            className="flex items-center gap-2 w-full justify-center px-3 py-2 rounded bg-red-600/80 hover:bg-red-600 text-white text-xs font-medium disabled:opacity-40 transition-colors"
          >
            {run.isPending ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
            {run.isPending ? 'Starting…' : 'Start Attack'}
          </button>
        </div>

        {/* Job history */}
        {allJobs.length > 0 && (
          <div className="border-t border-bg-border p-3 space-y-1">
            <p className="text-[10px] text-zinc-600 uppercase tracking-wide mb-2">History</p>
            {allJobs.map((j) => (
              <div
                key={j.job_id}
                className={clsx(
                  'flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer text-xs transition-colors',
                  jobId === j.job_id ? 'bg-red-500/20 text-zinc-200' : 'text-zinc-500 hover:bg-bg-elevated'
                )}
                onClick={() => setJobId(j.job_id)}
              >
                <span className="font-mono flex-1 truncate">{j.job_id}</span>
                <span>{j.completed}/{j.total}</span>
                <button onClick={(e) => { e.stopPropagation(); clearJob(j.job_id) }} className="text-zinc-600 hover:text-red-400">
                  <Trash2 size={10} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Right side: request editor + results */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Request editor */}
        <div className="h-56 shrink-0 border-b border-bg-border">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-bg-surface border-b border-bg-border">
            <span className="text-[10px] text-zinc-500 uppercase tracking-wide">Request Template</span>
            <span className="text-[10px] text-zinc-600 ml-2">Mark positions with §value§</span>
          </div>
          <Editor
            height="calc(100% - 32px)"
            language="http"
            value={rawRequest}
            onChange={(v) => setRawRequest(v ?? '')}
            theme="vs-dark"
            options={{
              fontSize: 12,
              fontFamily: 'monospace',
              minimap: { enabled: false },
              lineNumbers: 'on',
              scrollBeyondLastLine: false,
              wordWrap: 'on',
            }}
          />
        </div>

        {/* Results */}
        <div className="flex-1 overflow-auto">
          {!job && (
            <div className="flex items-center justify-center h-full text-zinc-600 text-sm">
              Configure a request and start an attack to see results
            </div>
          )}
          {job && (
            <div className="flex flex-col h-full">
              {/* Status bar */}
              <div className="flex items-center gap-4 px-4 py-2 bg-bg-surface border-b border-bg-border text-xs shrink-0">
                <span className="text-zinc-400">Job <span className="font-mono text-zinc-300">{job.job_id}</span></span>
                <span className={clsx(
                  job.status === 'complete' ? 'text-green-400' :
                  job.status === 'running' ? 'text-yellow-400' :
                  job.status === 'error' ? 'text-red-400' : 'text-zinc-500'
                )}>{job.status}</span>
                <span className="text-zinc-500">{job.completed}/{job.total}</span>
                {job.status === 'running' && <Loader2 size={12} className="animate-spin text-yellow-400" />}
                {job.error && <span className="text-red-400">{job.error}</span>}
                <button onClick={() => refetch()} className="ml-auto text-zinc-600 hover:text-zinc-300">
                  <RefreshCw size={12} />
                </button>
              </div>

              {/* Progress bar */}
              {job.status === 'running' && (
                <div className="h-0.5 bg-bg-border shrink-0">
                  <div
                    className="h-full bg-red-500 transition-all"
                    style={{ width: `${job.total ? (job.completed / job.total) * 100 : 0}%` }}
                  />
                </div>
              )}

              {/* Results table */}
              <div className="flex-1 overflow-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-bg-surface border-b border-bg-border">
                    <tr>
                      <ColHeader col="idx" label="#" />
                      <th className="px-3 py-2 text-left text-[10px] text-zinc-500 uppercase tracking-wide">Payloads</th>
                      <ColHeader col="status" label="Status" />
                      <ColHeader col="length" label="Length" />
                      <ColHeader col="time_ms" label="Time (ms)" />
                    </tr>
                  </thead>
                  <tbody>
                    {sortedResults.map((r) => (
                      <tr key={r.idx} className="border-b border-bg-border hover:bg-bg-elevated">
                        <td className="px-3 py-2 font-mono text-zinc-600">{r.idx}</td>
                        <td className="px-3 py-2 font-mono text-zinc-300 max-w-xs truncate">{r.payloads.join(' | ')}</td>
                        <td className={`px-3 py-2 font-mono font-semibold ${STATUS_COLOR(r.status)}`}>
                          {r.error ? <span className="text-red-400 text-[10px]">{r.error.slice(0, 30)}</span> : r.status}
                        </td>
                        <td className="px-3 py-2 font-mono text-zinc-400">{r.length}</td>
                        <td className="px-3 py-2 font-mono text-zinc-400">{r.time_ms}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {sortedResults.length === 0 && job.status !== 'running' && (
                  <p className="text-center text-zinc-600 text-xs py-8">No results yet</p>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

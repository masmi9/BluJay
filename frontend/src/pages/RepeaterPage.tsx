import { useState, useCallback, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeftRight, Play, Trash2, Plus, X, ChevronDown, ChevronRight,
  Loader2, Clock, Weight, History, Copy, Check, AlertTriangle,
  RefreshCw, Settings2, GitCompare, Zap,
} from 'lucide-react'
import { clsx } from 'clsx'
import { repeaterApi } from '@/api/repeater'
import type { RepeaterRequest, RepeaterResponse, ReplaceRule, HistoryEntry } from '@/api/repeater'

// ── Constants ──────────────────────────────────────────────────────────────

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

const METHOD_COLOR: Record<string, string> = {
  GET:     'text-green-400',
  POST:    'text-blue-400',
  PUT:     'text-yellow-400',
  PATCH:   'text-orange-400',
  DELETE:  'text-red-400',
  HEAD:    'text-purple-400',
  OPTIONS: 'text-zinc-400',
}

const STATUS_COLOR = (s: number) =>
  s < 200 ? 'text-zinc-400' :
  s < 300 ? 'text-green-400' :
  s < 400 ? 'text-blue-400' :
  s < 500 ? 'text-yellow-400' :
             'text-red-400'

const STATUS_BG = (s: number) =>
  s < 200 ? 'bg-zinc-500/15 border-zinc-500/30' :
  s < 300 ? 'bg-green-500/15 border-green-500/30' :
  s < 400 ? 'bg-blue-500/15 border-blue-500/30' :
  s < 500 ? 'bg-yellow-500/15 border-yellow-500/30' :
             'bg-red-500/15 border-red-500/30'

// ── Helpers ────────────────────────────────────────────────────────────────

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1048576).toFixed(1)} MB`
}

function timeAgo(iso: string): string {
  const s = (Date.now() - new Date(iso).getTime()) / 1000
  if (s < 60)    return `${Math.floor(s)}s ago`
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function buildRaw(req: RepeaterRequest): string {
  const url = new URL(req.url.startsWith('http') ? req.url : `http://${req.url}`)
  const path = url.pathname + url.search
  const hdrs = Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join('\n')
  return `${req.method} ${path} HTTP/1.1\n${hdrs}${req.body ? `\n\n${req.body}` : ''}`
}

// ── Copy button ────────────────────────────────────────────────────────────

function CopyBtn({ text, size = 13 }: { text: string; size?: number }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
      className="text-zinc-500 hover:text-zinc-200 transition-colors"
    >
      {copied ? <Check size={size} className="text-green-400" /> : <Copy size={size} />}
    </button>
  )
}

// ── Header editor ──────────────────────────────────────────────────────────

function HeaderEditor({ headers, onChange }: {
  headers: Record<string, string>
  onChange: (h: Record<string, string>) => void
}) {
  const entries = Object.entries(headers)

  const set = (i: number, k: string, v: string) => {
    const next = [...entries]
    next[i] = [k, v]
    onChange(Object.fromEntries(next.filter(([key]) => key)))
  }

  const remove = (i: number) => {
    const next = entries.filter((_, idx) => idx !== i)
    onChange(Object.fromEntries(next))
  }

  const add = () => onChange({ ...headers, '': '' })

  return (
    <div className="space-y-1">
      {entries.map(([k, v], i) => (
        <div key={i} className="flex gap-1.5 items-center">
          <input
            className="flex-1 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs text-zinc-200 font-mono focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="Header-Name"
            value={k}
            onChange={(e) => set(i, e.target.value, v)}
          />
          <input
            className="flex-1 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs text-zinc-200 font-mono focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="value"
            value={v}
            onChange={(e) => set(i, k, e.target.value)}
          />
          <button onClick={() => remove(i)} className="text-zinc-600 hover:text-red-400 transition-colors shrink-0">
            <X size={12} />
          </button>
        </div>
      ))}
      <button onClick={add} className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors mt-1">
        <Plus size={10} /> Add header
      </button>
    </div>
  )
}

// ── Replace rules editor ───────────────────────────────────────────────────

function RulesEditor({ rules, onChange }: {
  rules: ReplaceRule[]
  onChange: (r: ReplaceRule[]) => void
}) {
  const [open, setOpen] = useState(false)

  const update = (i: number, patch: Partial<ReplaceRule>) => {
    const next = rules.map((r, idx) => idx === i ? { ...r, ...patch } : r)
    onChange(next)
  }

  const remove = (i: number) => onChange(rules.filter((_, idx) => idx !== i))

  const add = () => onChange([...rules, { find: '', replace: '', target: 'all' }])

  return (
    <div>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
      >
        <Settings2 size={10} />
        Match &amp; Replace{rules.length > 0 ? ` (${rules.length})` : ''}
        {open ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
      </button>
      {open && (
        <div className="mt-2 space-y-1.5 border-t border-bg-border pt-2">
          {rules.map((r, i) => (
            <div key={i} className="flex gap-1.5 items-center">
              <input
                className="w-28 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
                placeholder="find (regex)"
                value={r.find}
                onChange={(e) => update(i, { find: e.target.value })}
              />
              <span className="text-zinc-600 text-xs shrink-0">→</span>
              <input
                className="w-28 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
                placeholder="replace"
                value={r.replace}
                onChange={(e) => update(i, { replace: e.target.value })}
              />
              <select
                aria-label="Match target"
                value={r.target}
                onChange={(e) => update(i, { target: e.target.value as ReplaceRule['target'] })}
                className="bg-bg-elevated border border-bg-border rounded px-1.5 py-1 text-xs text-zinc-300 focus:outline-none focus:border-accent"
              >
                <option value="all">all</option>
                <option value="url">url</option>
                <option value="headers">headers</option>
                <option value="body">body</option>
              </select>
              <button onClick={() => remove(i)} className="text-zinc-600 hover:text-red-400 transition-colors shrink-0">
                <X size={12} />
              </button>
            </div>
          ))}
          <button onClick={add} className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors">
            <Plus size={10} /> Add rule
          </button>
        </div>
      )}
    </div>
  )
}

// ── Response viewer ────────────────────────────────────────────────────────

function ResponseViewer({ response, diffResponse }: {
  response: RepeaterResponse | null
  diffResponse?: RepeaterResponse | null
}) {
  const [tab, setTab] = useState<'body' | 'headers'>('body')
  const [showDiff, setShowDiff] = useState(false)

  if (!response) {
    return (
      <div className="flex-1 flex items-center justify-center text-zinc-600">
        <div className="text-center">
          <ArrowLeftRight size={32} strokeWidth={1} className="mx-auto mb-2" />
          <p className="text-xs">Send a request to see the response</p>
        </div>
      </div>
    )
  }

  const renderDiff = () => {
    if (!diffResponse) return null
    const a = response.body.split('\n')
    const b = diffResponse.body.split('\n')
    const maxLen = Math.max(a.length, b.length)
    return (
      <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
        <div>
          <div className="text-[10px] text-zinc-500 mb-1">Response A — {response.status_code}</div>
          <pre className="text-zinc-300 whitespace-pre-wrap break-all leading-relaxed">{a.join('\n')}</pre>
        </div>
        <div>
          <div className="text-[10px] text-zinc-500 mb-1">Response B — {diffResponse.status_code}</div>
          {Array.from({ length: maxLen }, (_, i) => {
            const lineA = a[i] ?? ''
            const lineB = b[i] ?? ''
            return (
              <div key={i} className={lineA !== lineB ? 'bg-yellow-500/10 text-yellow-200' : 'text-zinc-300'}>
                {lineB}
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {/* Status bar */}
      <div className={clsx('flex items-center gap-3 px-3 py-2 rounded-lg border mb-3 text-xs', STATUS_BG(response.status_code))}>
        <span className={clsx('font-semibold text-sm', STATUS_COLOR(response.status_code))}>
          {response.status_code} {response.reason}
        </span>
        <span className="text-zinc-500 flex items-center gap-1">
          <Clock size={10} /> {response.elapsed_ms}ms
        </span>
        <span className="text-zinc-500 flex items-center gap-1">
          <Weight size={10} /> {fmtBytes(response.size_bytes)}
        </span>
        {response.redirects.length > 0 && (
          <span className="text-zinc-500">{response.redirects.length} redirect{response.redirects.length !== 1 ? 's' : ''}</span>
        )}
        <div className="flex-1" />
        <CopyBtn text={response.body} />
        {diffResponse && (
          <button
            onClick={() => setShowDiff((v) => !v)}
            className={clsx('flex items-center gap-1 text-[10px] border rounded px-2 py-0.5 transition-colors',
              showDiff ? 'border-accent/50 bg-accent/10 text-accent' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
            )}
          >
            <GitCompare size={10} /> Diff
          </button>
        )}
      </div>

      {/* Tabs */}
      {!showDiff && (
        <div className="flex gap-1 mb-2">
          {(['body', 'headers'] as const).map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={clsx('px-3 py-1 text-[10px] rounded capitalize transition-colors',
                tab === t ? 'bg-accent/15 text-accent' : 'text-zinc-500 hover:text-zinc-300'
              )}
            >
              {t}
              {t === 'headers' && ` (${Object.keys(response.headers).length})`}
            </button>
          ))}
        </div>
      )}

      <div className="flex-1 overflow-auto rounded-lg border border-bg-border bg-bg-elevated p-3">
        {showDiff ? renderDiff() : tab === 'body' ? (
          <pre className="text-[11px] text-zinc-300 whitespace-pre-wrap break-all leading-relaxed font-mono">
            {response.body || <span className="text-zinc-600 italic">(empty body)</span>}
          </pre>
        ) : (
          <div className="space-y-0.5">
            {Object.entries(response.headers).map(([k, v]) => (
              <div key={k} className="flex gap-2 text-[11px]">
                <span className="text-accent font-mono shrink-0">{k}:</span>
                <span className="text-zinc-300 font-mono break-all">{v}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── History sidebar ────────────────────────────────────────────────────────

function HistorySidebar({ onLoad, onClose }: {
  onLoad: (entry: { request: RepeaterRequest; response: RepeaterResponse }) => void
  onClose: () => void
}) {
  const qc = useQueryClient()
  const { data: entries = [] } = useQuery({
    queryKey: ['repeater-history'],
    queryFn: repeaterApi.listHistory,
  })

  const del = useMutation({
    mutationFn: (id: number) => repeaterApi.deleteEntry(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['repeater-history'] }),
  })

  const clearAll = useMutation({
    mutationFn: () => repeaterApi.clearHistory(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['repeater-history'] }),
  })

  const load = async (id: number) => {
    const full = await repeaterApi.getEntry(id)
    onLoad({ request: full.request, response: full.response })
    onClose()
  }

  return (
    <div className="w-64 border-l border-bg-border bg-bg-surface flex flex-col">
      <div className="flex items-center justify-between px-3 py-2.5 border-b border-bg-border">
        <span className="flex items-center gap-1.5 text-[10px] font-semibold text-zinc-400 uppercase tracking-wider">
          <History size={10} /> History ({entries.length})
        </span>
        <div className="flex items-center gap-2">
          {entries.length > 0 && (
            <button onClick={() => clearAll.mutate()}
              className="text-[10px] text-zinc-600 hover:text-red-400 transition-colors">
              Clear
            </button>
          )}
          <button onClick={onClose} className="text-zinc-600 hover:text-zinc-300 transition-colors">
            <X size={13} />
          </button>
        </div>
      </div>
      <div className="flex-1 overflow-auto p-2 space-y-1">
        {entries.length === 0 && (
          <p className="text-[10px] text-zinc-600 text-center pt-4">No history yet</p>
        )}
        {entries.map((e: HistoryEntry) => (
          <div
            key={e.id}
            className="px-2.5 py-2 rounded border border-bg-border bg-bg-elevated hover:bg-bg-elevated/80 cursor-pointer group"
            onClick={() => load(e.id)}
          >
            <div className="flex items-center gap-2">
              <span className={clsx('text-[10px] font-semibold shrink-0', METHOD_COLOR[e.method] ?? 'text-zinc-400')}>
                {e.method}
              </span>
              <span className={clsx('text-[10px] font-mono shrink-0', STATUS_COLOR(e.status))}>
                {e.status}
              </span>
              <button
                onClick={(ev) => { ev.stopPropagation(); del.mutate(e.id) }}
                className="ml-auto text-zinc-700 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all shrink-0"
              >
                <Trash2 size={10} />
              </button>
            </div>
            <p className="text-[10px] font-mono text-zinc-400 truncate mt-0.5">{e.url}</p>
            <div className="flex gap-2 mt-0.5 text-[10px] text-zinc-600">
              <span>{e.elapsed_ms}ms</span>
              <span>·</span>
              <span>{fmtBytes(e.size_bytes)}</span>
              <span>·</span>
              <span>{timeAgo(e.saved_at)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────

const DEFAULT_REQ: RepeaterRequest = {
  method: 'GET',
  url: '',
  headers: { 'User-Agent': 'BluJay/1.0' },
  body: null,
  follow_redirects: true,
  verify_ssl: false,
  timeout: 30,
  save: true,
  rules: [],
}

type RaceResult = { idx: number; status: number; length: number; duration_ms: number; body_snippet: string; error?: string }

export default function RepeaterPage() {
  const [req, setReq]             = useState<RepeaterRequest>(DEFAULT_REQ)
  const [response, setResponse]   = useState<RepeaterResponse | null>(null)
  const [diffResp, setDiffResp]   = useState<RepeaterResponse | null>(null)
  const [rawMode, setRawMode]     = useState(false)
  const [rawText, setRawText]     = useState('')
  const [showHistory, setShowHistory] = useState(false)
  const [bodyTab, setBodyTab]     = useState<'raw' | 'headers' | 'body'>('body')
  const [error, setError]         = useState<string | null>(null)
  const [mode, setMode]           = useState<'response' | 'race'>('response')
  const [raceCount, setRaceCount] = useState(10)
  const [raceResults, setRaceResults] = useState<RaceResult[]>([])
  const [raceRunning, setRaceRunning] = useState(false)
  const qc = useQueryClient()

  // Pre-load request from Proxy "Send to Repeater"
  useEffect(() => {
    const raw = sessionStorage.getItem('repeater-preload')
    if (!raw) return
    sessionStorage.removeItem('repeater-preload')
    try {
      const p = JSON.parse(raw)
      setReq((r) => ({ ...r, method: p.method ?? r.method, url: p.url ?? r.url, headers: p.headers ?? r.headers, body: p.body ?? r.body }))
    } catch { /* ignore malformed preload */ }
  }, [])

  const patch = (p: Partial<RepeaterRequest>) => setReq((r) => ({ ...r, ...p }))

  const send = useMutation({
    mutationFn: () =>
      rawMode
        ? repeaterApi.sendRaw(rawText, '', req.rules)
        : repeaterApi.send(req),
    onSuccess: (data) => {
      setResponse(data.response)
      setError(null)
      qc.invalidateQueries({ queryKey: ['repeater-history'] })
    },
    onError: (e: Error) => setError(e.message),
  })

  const handleSend = () => {
    if (!req.url.trim() && !rawText.trim()) return
    setError(null)
    send.mutate()
  }

  const runRace = async () => {
    if (!req.url) return
    setRaceRunning(true)
    setRaceResults([])
    try {
      const res = await import('axios').then((ax) =>
        ax.default.post('/api/v1/race/run', { method: req.method, url: req.url, headers: req.headers, body: req.body, count: raceCount })
      )
      setRaceResults(res.data.results ?? [])
    } catch { /* ignore */ }
    finally { setRaceRunning(false) }
  }

  const loadEntry = useCallback(({ request, response: resp }: { request: RepeaterRequest; response: RepeaterResponse }) => {
    setReq(request)
    setResponse(resp)
    if (rawMode) setRawText(buildRaw(request))
  }, [rawMode])

  const pinDiff = () => setDiffResp(response)
  const clearDiff = () => setDiffResp(null)

  return (
    <div className="flex h-full overflow-hidden">

      {/* ── Request panel ───────────────────────────────────────────────── */}
      <div className="w-[480px] shrink-0 border-r border-bg-border flex flex-col overflow-hidden">

        {/* Toolbar */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-bg-border bg-bg-surface shrink-0">
          <ArrowLeftRight size={14} className="text-accent shrink-0" />
          <h2 className="text-sm font-semibold text-zinc-200">Repeater</h2>
          <div className="flex-1" />
          <button
            onClick={() => setRawMode((v) => !v)}
            className={clsx('text-[10px] border rounded px-2 py-0.5 transition-colors',
              rawMode ? 'border-accent/50 text-accent bg-accent/10' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
            )}
          >
            {rawMode ? 'Raw mode' : 'Form mode'}
          </button>
          <button
            onClick={() => setShowHistory((v) => !v)}
            className={clsx('text-zinc-500 hover:text-zinc-200 transition-colors', showHistory && 'text-zinc-200')}
            title="History"
          >
            <History size={14} />
          </button>
        </div>

        {rawMode ? (
          /* Raw HTTP editor */
          <div className="flex-1 flex flex-col p-3 gap-3 overflow-hidden">
            <div className="flex items-center gap-2">
              <input
                className="flex-1 bg-bg-elevated border border-bg-border rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
                placeholder="https://example.com (base URL for host resolution)"
                value={req.url}
                onChange={(e) => patch({ url: e.target.value })}
              />
            </div>
            <textarea
              className="flex-1 bg-bg-elevated border border-bg-border rounded p-3 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent resize-none leading-relaxed"
              placeholder={`GET /api/users HTTP/1.1\nHost: example.com\nAuthorization: Bearer <token>\n\n`}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
            />
            <div className="shrink-0">
              <RulesEditor rules={req.rules} onChange={(rules) => patch({ rules })} />
            </div>
          </div>
        ) : (
          /* Form editor */
          <div className="flex-1 overflow-auto p-4 space-y-4">
            {/* Method + URL */}
            <div className="flex gap-2">
              <select
                aria-label="HTTP method"
                value={req.method}
                onChange={(e) => patch({ method: e.target.value })}
                className="bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs font-semibold focus:outline-none focus:border-accent text-zinc-200"
              >
                {METHODS.map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
              <input
                className="flex-1 bg-bg-elevated border border-bg-border rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
                placeholder="https://example.com/api/endpoint"
                value={req.url}
                onChange={(e) => patch({ url: e.target.value })}
                onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              />
            </div>

            {/* Body tabs */}
            <div>
              <div className="flex gap-1 mb-2">
                {(['body', 'headers', 'raw'] as const).map((t) => (
                  <button key={t} onClick={() => setBodyTab(t)}
                    className={clsx('px-3 py-1 text-[10px] rounded capitalize transition-colors',
                      bodyTab === t ? 'bg-accent/15 text-accent' : 'text-zinc-500 hover:text-zinc-300'
                    )}
                  >
                    {t}{t === 'headers' && ` (${Object.keys(req.headers).length})`}
                  </button>
                ))}
              </div>

              {bodyTab === 'headers' && (
                <HeaderEditor headers={req.headers} onChange={(headers) => patch({ headers })} />
              )}
              {bodyTab === 'body' && (
                <div className="space-y-2">
                  <select
                    aria-label="Content type"
                    value={req.headers['Content-Type'] ?? ''}
                    onChange={(e) => patch({ headers: { ...req.headers, 'Content-Type': e.target.value } })}
                    className="bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-accent"
                  >
                    <option value="">— no content-type —</option>
                    <option value="application/json">application/json</option>
                    <option value="application/x-www-form-urlencoded">application/x-www-form-urlencoded</option>
                    <option value="text/plain">text/plain</option>
                    <option value="text/xml">text/xml</option>
                    <option value="multipart/form-data">multipart/form-data</option>
                  </select>
                  <textarea
                    className="w-full h-40 bg-bg-elevated border border-bg-border rounded p-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent resize-none leading-relaxed"
                    placeholder='{"key": "value"}'
                    value={req.body ?? ''}
                    onChange={(e) => patch({ body: e.target.value || null })}
                  />
                </div>
              )}
              {bodyTab === 'raw' && (
                <textarea
                  readOnly
                  className="w-full h-52 bg-bg-elevated border border-bg-border rounded p-2.5 text-[11px] font-mono text-zinc-400 resize-none leading-relaxed"
                  value={buildRaw(req)}
                />
              )}
            </div>

            {/* Options */}
            <div className="space-y-2 border-t border-bg-border pt-3">
              <div className="flex gap-4">
                <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer">
                  <input type="checkbox" checked={req.follow_redirects}
                    onChange={(e) => patch({ follow_redirects: e.target.checked })}
                    className="accent-accent" />
                  Follow redirects
                </label>
                <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer">
                  <input type="checkbox" checked={req.verify_ssl}
                    onChange={(e) => patch({ verify_ssl: e.target.checked })}
                    className="accent-accent" />
                  Verify SSL
                </label>
                <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer">
                  <input type="checkbox" checked={req.save}
                    onChange={(e) => patch({ save: e.target.checked })}
                    className="accent-accent" />
                  Save to history
                </label>
              </div>
              <div className="flex items-center gap-2 text-[10px] text-zinc-500">
                <span>Timeout</span>
                <input
                  type="number" min={1} max={300} step={1}
                  value={req.timeout}
                  onChange={(e) => patch({ timeout: Number(e.target.value) })}
                  className="w-16 bg-bg-elevated border border-bg-border rounded px-2 py-0.5 text-xs text-zinc-200 focus:outline-none focus:border-accent"
                />
                <span>s</span>
              </div>
            </div>

            <RulesEditor rules={req.rules} onChange={(rules) => patch({ rules })} />
          </div>
        )}

        {/* Send bar */}
        <div className="shrink-0 px-4 py-3 border-t border-bg-border bg-bg-surface flex items-center gap-2">
          <button
            onClick={handleSend}
            disabled={send.isPending || (!req.url.trim() && !rawText.trim())}
            className="flex items-center gap-1.5 px-4 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors"
          >
            {send.isPending ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
            {send.isPending ? 'Sending…' : 'Send'}
          </button>
          <button
            onClick={() => { setReq(DEFAULT_REQ); setResponse(null); setDiffResp(null); setRawText('') }}
            className="text-zinc-600 hover:text-zinc-300 transition-colors"
            title="Clear"
          >
            <RefreshCw size={13} />
          </button>
          {response && !diffResp && (
            <button
              onClick={pinDiff}
              className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300 border border-bg-border rounded px-2 py-0.5 transition-colors ml-auto"
            >
              <GitCompare size={10} /> Pin for diff
            </button>
          )}
          {diffResp && (
            <button onClick={clearDiff}
              className="flex items-center gap-1 text-[10px] text-accent border border-accent/30 rounded px-2 py-0.5 hover:bg-accent/10 transition-colors ml-auto">
              <X size={10} /> Clear diff
            </button>
          )}
        </div>

        {error && (
          <div className="px-4 py-2 bg-red-500/10 border-t border-red-500/30 flex items-center gap-2 text-xs text-red-400 shrink-0">
            <AlertTriangle size={11} className="shrink-0" />
            {error}
          </div>
        )}
      </div>

      {/* ── Response panel ───────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Mode tab bar */}
        <div className="flex items-center border-b border-bg-border bg-bg-surface shrink-0 px-1">
          {(['response', 'race'] as const).map((m) => (
            <button key={m} onClick={() => setMode(m)}
              className={clsx('flex items-center gap-1.5 px-4 py-2 text-xs font-medium capitalize transition-colors border-b-2 -mb-px',
                mode === m ? 'border-accent text-zinc-100' : 'border-transparent text-zinc-500 hover:text-zinc-300')}>
              {m === 'race' && <Zap size={11} className="text-red-400" />}
              {m === 'response' ? 'Response' : 'Race Conditions'}
            </button>
          ))}
        </div>

        {mode === 'response' && (
          <div className="flex-1 flex flex-col overflow-hidden p-4">
            <ResponseViewer response={response} diffResponse={diffResp} />
          </div>
        )}

        {mode === 'race' && (
          <div className="flex flex-col flex-1 overflow-hidden">
            {/* Race controls */}
            <div className="flex items-center gap-3 px-4 py-2.5 border-b border-bg-border bg-bg-surface shrink-0">
              <span className="text-xs font-mono text-zinc-500 flex-1 truncate">{req.url || 'Configure a URL in the request panel first'}</span>
              <label className="text-xs text-zinc-500 shrink-0">Requests</label>
              <input
                type="number" min={1} max={50} value={raceCount}
                onChange={(e) => setRaceCount(Number(e.target.value))}
                aria-label="Number of concurrent requests"
                title="Number of concurrent requests"
                className="w-16 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-300 focus:outline-none focus:border-red-500/50"
              />
              <button
                onClick={runRace}
                disabled={raceRunning || !req.url}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-red-500/20 text-red-400 hover:bg-red-500/30 rounded disabled:opacity-40 transition-colors font-medium"
              >
                {raceRunning ? <><RefreshCw size={11} className="animate-spin" /> Racing…</> : <><Zap size={11} /> Race</>}
              </button>
            </div>

            {/* Race summary */}
            {raceResults.length > 0 && (() => {
              const statuses = [...new Set(raceResults.map((r) => r.status))]
              const times = raceResults.map((r) => r.duration_ms)
              return (
                <div className="flex items-center gap-4 px-4 py-1.5 bg-bg-elevated border-b border-bg-border shrink-0 text-xs">
                  <span className="text-zinc-500">{raceResults.length} requests</span>
                  <span className="text-zinc-500">Statuses: <span className="text-zinc-300">{statuses.join(', ') || '—'}</span></span>
                  <span className="text-zinc-500">Fastest: <span className="text-green-400">{Math.min(...times)}ms</span></span>
                  <span className="text-zinc-500">Slowest: <span className="text-amber-400">{Math.max(...times)}ms</span></span>
                  <span className="text-zinc-500">Spread: <span className={clsx(Math.max(...times) - Math.min(...times) > 50 ? 'text-red-400' : 'text-zinc-300')}>{(Math.max(...times) - Math.min(...times)).toFixed(1)}ms</span></span>
                </div>
              )
            })()}

            {/* Race results */}
            <div className="flex-1 overflow-auto">
              {raceResults.length === 0 && !raceRunning && (
                <div className="flex flex-col items-center justify-center h-full text-zinc-600 gap-2">
                  <Zap size={28} strokeWidth={1} />
                  <p className="text-sm">No results yet</p>
                  <p className="text-xs text-center max-w-xs text-zinc-600">
                    Configure a request, then click Race to fire {raceCount} simultaneous requests. Differing status codes or sizes indicate a race condition window.
                  </p>
                </div>
              )}
              {raceResults.length > 0 && (
                <table className="w-full text-xs font-mono">
                  <thead className="sticky top-0 bg-bg-surface border-b border-bg-border">
                    <tr className="text-zinc-500">
                      <th className="text-left px-4 py-1.5 w-10">#</th>
                      <th className="text-left px-4 py-1.5 w-16">Status</th>
                      <th className="text-left px-4 py-1.5 w-20">Length</th>
                      <th className="text-left px-4 py-1.5 w-24">Time</th>
                      <th className="text-left px-4 py-1.5">Snippet / Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {raceResults.map((r) => {
                      const isAnomaly = r.status !== raceResults[0].status || Math.abs(r.length - raceResults[0].length) > 20
                      return (
                        <tr key={r.idx} className={clsx('border-b border-bg-border/50 hover:bg-bg-elevated transition-colors', isAnomaly && 'bg-red-500/5')}>
                          <td className="px-4 py-1 text-zinc-600">{r.idx + 1}</td>
                          <td className="px-4 py-1">
                            <span className={clsx(r.status === 0 ? 'text-red-400' : r.status >= 500 ? 'text-red-400' : r.status >= 400 ? 'text-amber-400' : r.status >= 300 ? 'text-yellow-400' : 'text-green-400')}>
                              {r.status || 'ERR'}
                            </span>
                          </td>
                          <td className="px-4 py-1 text-zinc-400">{r.length}</td>
                          <td className="px-4 py-1 text-zinc-400">{r.duration_ms}ms</td>
                          <td className="px-4 py-1 text-zinc-500 truncate max-w-xs">{r.error || r.body_snippet}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── History sidebar ──────────────────────────────────────────────── */}
      {showHistory && (
        <HistorySidebar onLoad={loadEntry} onClose={() => setShowHistory(false)} />
      )}
    </div>
  )
}

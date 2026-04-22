import { useState } from 'react'
import axios from 'axios'
import { Play, Loader2, ChevronDown, ChevronRight, AlertTriangle } from 'lucide-react'
import { clsx } from 'clsx'

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400 border-red-400/30 bg-red-400/5',
  high:     'text-orange-400 border-orange-400/30 bg-orange-400/5',
  medium:   'text-yellow-400 border-yellow-400/30 bg-yellow-400/5',
  low:      'text-blue-400 border-blue-400/30 bg-blue-400/5',
  info:     'text-zinc-400 border-zinc-600 bg-zinc-800/30',
}

export default function WsTestPage() {
  const [url, setUrl] = useState('ws://')
  const [headers, setHeaders] = useState('Authorization: Bearer <token>')
  const [testAuthStrip, setTestAuthStrip] = useState(true)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState('')
  const [expandedProbe, setExpandedProbe] = useState<number | null>(null)

  const parseHeaders = (raw: string): Record<string, string> => {
    const out: Record<string, string> = {}
    for (const line of raw.split('\n')) {
      const idx = line.indexOf(':')
      if (idx > 0) {
        out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
      }
    }
    return out
  }

  const run = async () => {
    setError('')
    setResult(null)
    setRunning(true)
    try {
      const r = await axios.post('/api/v1/ws-test/test', {
        url,
        headers: parseHeaders(headers),
        test_auth_strip: testAuthStrip,
      })
      setResult(r.data)
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-5">
      <div>
        <h2 className="text-sm font-semibold text-zinc-100 mb-1">WebSocket Security Testing</h2>
        <p className="text-xs text-zinc-500">Probe WS endpoints for unauthenticated access, injection, and misconfigs.</p>
      </div>

      <div className="space-y-3">
        <div className="space-y-1">
          <label className="text-xs text-zinc-400">WebSocket URL</label>
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="ws://host/endpoint or wss://host/endpoint"
            aria-label="WebSocket URL"
            title="WebSocket URL"
            className="w-full bg-bg-elevated border border-bg-border rounded-lg px-3 py-2 text-sm font-mono text-zinc-200"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-zinc-400">Headers (one per line, Name: value)</label>
          <textarea
            value={headers}
            onChange={e => setHeaders(e.target.value)}
            rows={3}
            aria-label="Request headers"
            title="Request headers"
            placeholder="Authorization: Bearer <token>"
            className="w-full bg-bg-elevated border border-bg-border rounded-lg px-3 py-2 text-sm font-mono text-zinc-200 resize-none"
          />
        </div>
        <label className="flex items-center gap-2 cursor-pointer text-sm text-zinc-300">
          <input type="checkbox" checked={testAuthStrip} onChange={e => setTestAuthStrip(e.target.checked)} className="accent-accent" />
          Also test without auth headers (auth strip)
        </label>
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <button
        onClick={run}
        disabled={running}
        className="flex items-center gap-2 px-4 py-2 bg-accent text-white text-sm rounded-lg hover:bg-accent/80 disabled:opacity-50"
      >
        {running ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
        Run WebSocket Test
      </button>

      {result && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 text-sm">
            <span className={clsx('px-2 py-0.5 rounded text-xs font-semibold', result.connected ? 'bg-green-500/15 text-green-400' : 'bg-red-500/15 text-red-400')}>
              {result.connected ? 'CONNECTED' : 'FAILED TO CONNECT'}
            </span>
            <span className="text-zinc-500">{result.finding_count} finding{result.finding_count !== 1 ? 's' : ''}</span>
          </div>

          {result.findings.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs text-zinc-500 uppercase tracking-wide font-medium">Findings</p>
              {result.findings.map((f: any, i: number) => (
                <div key={i} className={clsx('border rounded-lg p-3 space-y-1', SEV_COLOR[f.severity] || SEV_COLOR.info)}>
                  <div className="flex items-center gap-2">
                    <AlertTriangle size={12} />
                    <span className="text-xs font-semibold uppercase">{f.severity}</span>
                    <span className="text-sm font-medium">{f.title}</span>
                  </div>
                  <p className="text-xs opacity-80">{f.detail}</p>
                </div>
              ))}
            </div>
          )}

          <div className="space-y-1">
            <p className="text-xs text-zinc-500 uppercase tracking-wide font-medium">Probe Results</p>
            {result.probes.map((p: any, i: number) => (
              <div key={i} className="border border-bg-border rounded-lg overflow-hidden">
                <button
                  onClick={() => setExpandedProbe(expandedProbe === i ? null : i)}
                  className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-bg-elevated"
                >
                  {expandedProbe === i ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                  <code className="text-xs text-zinc-400 flex-1 truncate">{p.payload}</code>
                  {p.error
                    ? <span className="text-xs text-red-400">{p.error}</span>
                    : <span className="text-xs text-green-400">got response</span>
                  }
                </button>
                {expandedProbe === i && p.response && (
                  <div className="px-3 pb-3 bg-bg-elevated">
                    <pre className="text-xs text-zinc-300 whitespace-pre-wrap">{p.response}</pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

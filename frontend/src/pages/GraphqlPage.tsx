import { useState } from 'react'
import axios from 'axios'
import { Play, Loader2, AlertTriangle, Database } from 'lucide-react'
import { clsx } from 'clsx'

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400 border-red-400/30 bg-red-400/5',
  high:     'text-orange-400 border-orange-400/30 bg-orange-400/5',
  medium:   'text-yellow-400 border-yellow-400/30 bg-yellow-400/5',
  low:      'text-blue-400 border-blue-400/30 bg-blue-400/5',
  info:     'text-zinc-400 border-zinc-600 bg-zinc-800/30',
}

export default function GraphqlPage() {
  const [url, setUrl] = useState('')
  const [headers, setHeaders] = useState('Content-Type: application/json')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState('')
  const [opts, setOpts] = useState({
    test_introspection: true,
    test_batching: true,
    test_field_suggestions: true,
    test_injection: true,
    test_auth_bypass: true,
  })

  const parseHeaders = (raw: string): Record<string, string> => {
    const out: Record<string, string> = {}
    for (const line of raw.split('\n')) {
      const idx = line.indexOf(':')
      if (idx > 0) out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
    }
    return out
  }

  const run = async () => {
    setError('')
    setResult(null)
    setRunning(true)
    try {
      const r = await axios.post('/api/v1/graphql-test/test', {
        url,
        headers: parseHeaders(headers),
        ...opts,
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
        <h2 className="text-sm font-semibold text-zinc-100 mb-1">GraphQL Security Testing</h2>
        <p className="text-xs text-zinc-500">
          Introspection exposure, batching abuse, field suggestions, injection, auth bypass.
        </p>
      </div>

      <div className="space-y-3">
        <div className="space-y-1">
          <label className="text-xs text-zinc-400">GraphQL Endpoint URL</label>
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://api.target.com/graphql"
            aria-label="GraphQL endpoint URL"
            title="GraphQL endpoint URL"
            className="w-full bg-bg-elevated border border-bg-border rounded-lg px-3 py-2 text-sm font-mono text-zinc-200"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-zinc-400">Headers (one per line)</label>
          <textarea
            value={headers}
            onChange={e => setHeaders(e.target.value)}
            rows={3}
            aria-label="Request headers"
            title="Request headers"
            placeholder="Content-Type: application/json"
            className="w-full bg-bg-elevated border border-bg-border rounded-lg px-3 py-2 text-sm font-mono text-zinc-200 resize-none"
          />
        </div>

        <div className="grid grid-cols-2 gap-2">
          {Object.entries(opts).map(([k, v]) => (
            <label key={k} className="flex items-center gap-2 cursor-pointer text-xs text-zinc-300">
              <input
                type="checkbox"
                checked={v}
                onChange={e => setOpts(o => ({ ...o, [k]: e.target.checked }))}
                className="accent-accent"
              />
              {k.replace('test_', '').replace(/_/g, ' ')}
            </label>
          ))}
        </div>
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <button
        onClick={run}
        disabled={running || !url}
        className="flex items-center gap-2 px-4 py-2 bg-accent text-white text-sm rounded-lg hover:bg-accent/80 disabled:opacity-50"
      >
        {running ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
        Run GraphQL Test
      </button>

      {result && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 text-sm">
            <span className={clsx('px-2 py-0.5 rounded text-xs font-semibold', result.is_graphql ? 'bg-green-500/15 text-green-400' : 'bg-zinc-700 text-zinc-400')}>
              {result.is_graphql ? 'GraphQL DETECTED' : 'Not a GraphQL endpoint'}
            </span>
            {result.is_graphql && (
              <span className="text-zinc-500">{result.finding_count} finding{result.finding_count !== 1 ? 's' : ''}</span>
            )}
          </div>

          {result.findings?.length > 0 && (
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
                  {f.recommendation && <p className="text-xs opacity-60 italic">{f.recommendation}</p>}
                </div>
              ))}
            </div>
          )}

          {result.details?.introspection?.types?.length > 0 && (
            <div className="bg-bg-surface border border-bg-border rounded-lg p-3">
              <div className="flex items-center gap-2 mb-2">
                <Database size={12} className="text-zinc-500" />
                <span className="text-xs font-medium text-zinc-400">Exposed Schema Types</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {result.details.introspection.types.map((t: string) => (
                  <span key={t} className="text-xs font-mono bg-bg-elevated border border-bg-border text-zinc-400 px-1.5 py-0.5 rounded">{t}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

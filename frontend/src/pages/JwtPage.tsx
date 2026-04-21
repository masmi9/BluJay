import { useState, useEffect, useRef } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Key, Scan, Copy, ChevronDown, ChevronRight } from 'lucide-react'
import { clsx } from 'clsx'
import { jwtApi } from '@/api/jwt'
import type { JwtDecodeResult } from '@/types/jwt'
import { useWebSocket } from '@/hooks/useWebSocket'

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
      className="text-zinc-500 hover:text-zinc-200 transition-colors"
      title="Copy"
    >
      <Copy size={12} />
      {copied && <span className="ml-1 text-xs text-green-400">Copied</span>}
    </button>
  )
}

function JsonPane({ label, data }: { label: string; data: Record<string, unknown> }) {
  return (
    <div className="flex flex-col gap-1">
      <p className="text-xs font-medium text-zinc-400">{label}</p>
      <pre className="bg-bg-elevated rounded p-3 text-xs text-zinc-300 font-mono overflow-auto max-h-40 whitespace-pre-wrap">
        {JSON.stringify(data, null, 2)}
      </pre>
    </div>
  )
}

function Collapsible({ label, children }: { label: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border border-bg-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-2 px-4 py-2.5 bg-bg-surface hover:bg-bg-elevated text-left text-sm text-zinc-300"
      >
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        {label}
      </button>
      {open && <div className="p-4 bg-bg-elevated">{children}</div>}
    </div>
  )
}

export default function JwtPage() {
  const [tokenInput, setTokenInput] = useState('')
  const [sessionId, setSessionId] = useState('')
  const [decoded, setDecoded] = useState<JwtDecodeResult | null>(null)
  const [currentTestId, setCurrentTestId] = useState<number | null>(null)
  const [bruteProgress, setBruteProgress] = useState<{ count: number; found: string | null; done: boolean }>({ count: 0, found: null, done: false })
  const [scannedTokens, setScannedTokens] = useState<string[]>([])

  const decodeMutation = useMutation({
    mutationFn: () => jwtApi.decode(tokenInput.trim(), sessionId ? Number(sessionId) : undefined),
    onSuccess: (data) => {
      setDecoded(data)
      // Extract test_id from history via listTests — but we need the newly created one
      // Instead we refetch the list and pick the latest
    },
  })

  const { data: tests = [] } = useQuery({
    queryKey: ['jwt-tests'],
    queryFn: () => jwtApi.listTests(),
    refetchInterval: decoded ? 5000 : false,
  })

  const latestTestId = tests[0]?.id ?? null

  const bruteMutation = useMutation({
    mutationFn: () => jwtApi.startBruteForce(latestTestId!),
    onSuccess: () => {
      setBruteProgress({ count: 0, found: null, done: false })
      setCurrentTestId(latestTestId)
    },
  })

  const scanMutation = useMutation({
    mutationFn: () => jwtApi.scanFlows(Number(sessionId)),
    onSuccess: (tokens) => setScannedTokens(tokens),
  })

  // WebSocket for brute-force progress
  const wsUrl = currentTestId ? `/ws/jwt/${currentTestId}` : null
  const { lastMessage } = useWebSocket(wsUrl)

  useEffect(() => {
    if (!lastMessage) return
    try {
      const msg = JSON.parse(lastMessage)
      if (msg.type === 'brute_progress') {
        setBruteProgress((p) => ({ ...p, count: msg.tested_count }))
      } else if (msg.type === 'brute_found') {
        setBruteProgress({ count: msg.tested_count, found: msg.secret, done: true })
      } else if (msg.type === 'brute_done') {
        setBruteProgress((p) => ({ ...p, count: msg.tested_count, done: true }))
      }
    } catch { /* ignore */ }
  }, [lastMessage])

  return (
    <div className="flex flex-col h-full p-6 gap-4 overflow-auto">
      <div className="flex items-center gap-3">
        <Key size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-zinc-100">JWT Attack Testing</h1>
      </div>

      {/* Input area */}
      <div className="bg-bg-surface rounded-lg border border-bg-border p-4 flex flex-col gap-3">
        <textarea
          rows={4}
          className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent resize-none"
          placeholder="Paste JWT token here (eyJ...)"
          value={tokenInput}
          onChange={(e) => setTokenInput(e.target.value)}
        />
        <div className="flex items-center gap-3 flex-wrap">
          <input
            className="w-36 bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-accent"
            placeholder="Session ID (opt.)"
            value={sessionId}
            onChange={(e) => setSessionId(e.target.value)}
          />
          <button
            onClick={() => decodeMutation.mutate()}
            disabled={!tokenInput.trim() || decodeMutation.isPending}
            className="px-4 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-sm text-white transition-colors"
          >
            {decodeMutation.isPending ? 'Decoding…' : 'Decode & Analyze'}
          </button>
          {sessionId && (
            <button
              onClick={() => scanMutation.mutate()}
              disabled={!sessionId || scanMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-bg-elevated hover:bg-bg-border rounded text-sm text-zinc-300 transition-colors"
            >
              <Scan size={13} />
              {scanMutation.isPending ? 'Scanning…' : 'Scan Flows'}
            </button>
          )}
        </div>
        {decodeMutation.isError && (
          <p className="text-xs text-red-400">{(decodeMutation.error as Error).message}</p>
        )}
      </div>

      {/* Scanned tokens */}
      {scannedTokens.length > 0 && (
        <div className="bg-bg-surface rounded-lg border border-bg-border p-4">
          <p className="text-xs font-medium text-zinc-400 mb-2">JWTs found in proxy flows ({scannedTokens.length})</p>
          <div className="flex flex-col gap-1 max-h-32 overflow-auto">
            {scannedTokens.map((t, i) => (
              <div key={i} className="flex items-center gap-2">
                <button
                  onClick={() => setTokenInput(t)}
                  className="text-xs font-mono text-accent hover:underline truncate flex-1 text-left"
                >
                  {t.substring(0, 60)}…
                </button>
                <CopyButton text={t} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Decoded results */}
      {decoded && (
        <div className="flex flex-col gap-3">
          <div className="grid grid-cols-2 gap-3">
            <JsonPane label="Header" data={decoded.header} />
            <JsonPane label="Payload" data={decoded.payload} />
          </div>

          {/* alg:none */}
          <Collapsible label="alg:none forged token">
            <div className="flex items-start gap-2">
              <pre className="flex-1 text-xs font-mono text-yellow-300 bg-bg-surface rounded p-2 overflow-auto max-h-20 whitespace-pre-wrap break-all">
                {decoded.alg_none_token}
              </pre>
              <CopyButton text={decoded.alg_none_token} />
            </div>
          </Collapsible>

          {/* Role escalation */}
          <Collapsible label={`Role escalation variants (${decoded.role_tokens.length})`}>
            <div className="flex flex-col gap-1 max-h-48 overflow-auto">
              {decoded.role_tokens.map((t, i) => (
                <div key={i} className="flex items-center gap-2">
                  <pre className="flex-1 text-xs font-mono text-zinc-300 truncate">{t.substring(0, 80)}…</pre>
                  <CopyButton text={t} />
                </div>
              ))}
            </div>
          </Collapsible>

          {/* Kid injection */}
          <Collapsible label={`kid injection payloads (${decoded.kid_tokens.length})`}>
            <div className="flex flex-col gap-1 max-h-48 overflow-auto">
              {decoded.kid_tokens.map((t, i) => (
                <div key={i} className="flex items-center gap-2">
                  <pre className="flex-1 text-xs font-mono text-zinc-300 truncate">{t.substring(0, 80)}…</pre>
                  <CopyButton text={t} />
                </div>
              ))}
            </div>
          </Collapsible>

          {/* Brute force */}
          <div className="bg-bg-surface rounded-lg border border-bg-border p-4 flex flex-col gap-3">
            <p className="text-sm font-medium text-zinc-300">HMAC Secret Brute-Force</p>
            <div className="flex items-center gap-3">
              <button
                onClick={() => bruteMutation.mutate()}
                disabled={bruteMutation.isPending || !latestTestId}
                className="px-4 py-1.5 bg-orange-600 hover:bg-orange-500 disabled:opacity-50 rounded text-sm text-white transition-colors"
              >
                {bruteMutation.isPending ? 'Starting…' : 'Start Brute Force'}
              </button>
              {bruteProgress.count > 0 && !bruteProgress.done && (
                <span className="text-xs text-zinc-400">Tested: {bruteProgress.count.toLocaleString()}</span>
              )}
            </div>
            {bruteProgress.done && (
              bruteProgress.found ? (
                <div className="p-3 bg-green-900/40 rounded text-sm text-green-300">
                  Secret found: <span className="font-mono font-bold">{bruteProgress.found}</span>
                  {' '}(tested {bruteProgress.count.toLocaleString()})
                </div>
              ) : (
                <p className="text-xs text-zinc-500">Not found in wordlist ({bruteProgress.count.toLocaleString()} tested).</p>
              )
            )}
          </div>
        </div>
      )}
    </div>
  )
}

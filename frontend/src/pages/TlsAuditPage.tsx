import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Lock, ChevronDown, ChevronRight, Plus, X } from 'lucide-react'
import { clsx } from 'clsx'
import { tlsApi } from '@/api/tls'
import type { TlsAudit, TlsFinding } from '@/types/tls'

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
}

function ProtoBadge({ enabled, label }: { enabled: boolean; label: string }) {
  return (
    <span
      className={clsx(
        'px-2 py-0.5 rounded text-xs font-mono font-medium',
        enabled ? 'bg-red-900/60 text-red-300' : 'bg-bg-elevated text-zinc-600'
      )}
    >
      {label}
    </span>
  )
}

function AuditRow({ audit }: { audit: TlsAudit }) {
  const [open, setOpen] = useState(false)
  const findings: TlsFinding[] = audit.findings_json ? JSON.parse(audit.findings_json) : []
  const weakCiphers: string[] = audit.weak_ciphers ? JSON.parse(audit.weak_ciphers) : []
  const hasIssues = findings.length > 0

  return (
    <div className="border border-bg-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-3 px-4 py-3 bg-bg-surface hover:bg-bg-elevated transition-colors text-left"
      >
        {open ? <ChevronDown size={14} className="shrink-0 text-zinc-400" /> : <ChevronRight size={14} className="shrink-0 text-zinc-400" />}
        <Lock size={14} className={hasIssues ? 'text-orange-400 shrink-0' : 'text-green-400 shrink-0'} />
        <span className="font-mono text-sm text-zinc-200 flex-1">{audit.host}:{audit.port}</span>
        <div className="flex gap-1">
          <ProtoBadge enabled={audit.tls10_enabled} label="TLS1.0" />
          <ProtoBadge enabled={audit.tls11_enabled} label="TLS1.1" />
          <span className={clsx('px-2 py-0.5 rounded text-xs font-mono', audit.tls12_enabled ? 'bg-green-900/60 text-green-300' : 'bg-bg-elevated text-zinc-600')}>TLS1.2</span>
          <span className={clsx('px-2 py-0.5 rounded text-xs font-mono', audit.tls13_enabled ? 'bg-green-900/60 text-green-300' : 'bg-bg-elevated text-zinc-600')}>TLS1.3</span>
        </div>
        {findings.length > 0 && (
          <span className="text-xs px-2 py-0.5 bg-orange-900/40 text-orange-400 rounded">
            {findings.length} issue{findings.length > 1 ? 's' : ''}
          </span>
        )}
      </button>

      {open && (
        <div className="bg-bg-elevated px-6 py-4 space-y-4 text-sm">
          {/* Cert details */}
          <div>
            <p className="text-xs font-medium text-zinc-400 mb-2">Certificate</p>
            <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-xs">
              <span className="text-zinc-500">Subject</span>
              <span className="text-zinc-300 font-mono truncate" title={audit.cert_subject ?? ''}>{audit.cert_subject ?? 'N/A'}</span>
              <span className="text-zinc-500">Issuer</span>
              <span className="text-zinc-300 font-mono truncate" title={audit.cert_issuer ?? ''}>{audit.cert_issuer ?? 'N/A'}</span>
              <span className="text-zinc-500">Expiry</span>
              <span className="text-zinc-300">{audit.cert_expiry ? new Date(audit.cert_expiry).toLocaleDateString() : 'N/A'}</span>
              <span className="text-zinc-500">Self-signed</span>
              <span className={audit.cert_self_signed ? 'text-red-400' : 'text-green-400'}>
                {audit.cert_self_signed === null ? 'N/A' : audit.cert_self_signed ? 'Yes' : 'No'}
              </span>
              <span className="text-zinc-500">HSTS</span>
              <span className={audit.hsts_present ? 'text-green-400' : 'text-yellow-400'}>
                {audit.hsts_present ? 'Present' : 'Missing'}
              </span>
            </div>
          </div>

          {/* Weak ciphers */}
          {weakCiphers.length > 0 && (
            <div>
              <p className="text-xs font-medium text-zinc-400 mb-1">Weak Ciphers</p>
              <div className="flex flex-wrap gap-1">
                {weakCiphers.map((c) => (
                  <span key={c} className="px-2 py-0.5 text-xs font-mono bg-red-900/40 text-red-300 rounded">{c}</span>
                ))}
              </div>
            </div>
          )}

          {/* Findings */}
          {findings.length > 0 && (
            <div>
              <p className="text-xs font-medium text-zinc-400 mb-1">Findings</p>
              <ul className="space-y-1">
                {findings.map((f, i) => (
                  <li key={i} className="flex items-center gap-2 text-xs">
                    <span className={clsx('font-medium w-16 shrink-0', SEV_COLORS[f.severity])}>{f.severity}</span>
                    <span className="text-zinc-300">{f.title}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {audit.error && (
            <p className="text-xs text-red-400">Error: {audit.error}</p>
          )}
        </div>
      )}
    </div>
  )
}

export default function TlsAuditPage() {
  const qc = useQueryClient()
  const [hostInput, setHostInput] = useState('')
  const [hosts, setHosts] = useState<string[]>([])
  const [sessionId, setSessionId] = useState('')

  const { data: audits = [], isLoading } = useQuery({
    queryKey: ['tls-audits'],
    queryFn: () => tlsApi.list(),
  })

  const run = useMutation({
    mutationFn: () =>
      tlsApi.audit({
        hosts,
        session_id: sessionId ? Number(sessionId) : undefined,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tls-audits'] }),
  })

  function addHost() {
    const h = hostInput.trim()
    if (h && !hosts.includes(h)) setHosts((prev) => [...prev, h])
    setHostInput('')
  }

  return (
    <div className="flex flex-col h-full p-6 gap-4">
      <div className="flex items-center gap-3">
        <Lock size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-zinc-100">TLS Audit</h1>
      </div>

      {/* Input form */}
      <div className="bg-bg-surface rounded-lg border border-bg-border p-4 flex flex-col gap-3">
        <div className="flex gap-2">
          <input
            className="flex-1 bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-accent"
            placeholder="hostname (e.g. api.example.com)"
            value={hostInput}
            onChange={(e) => setHostInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addHost()}
          />
          <button onClick={addHost} className="px-3 py-1.5 bg-bg-elevated hover:bg-bg-border rounded text-zinc-300 text-sm flex items-center gap-1">
            <Plus size={13} /> Add
          </button>
        </div>

        {hosts.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {hosts.map((h) => (
              <span key={h} className="flex items-center gap-1 px-2 py-0.5 bg-bg-elevated rounded text-xs text-zinc-300">
                {h}
                <button onClick={() => setHosts((p) => p.filter((x) => x !== h))} className="text-zinc-500 hover:text-red-400">
                  <X size={10} />
                </button>
              </span>
            ))}
          </div>
        )}

        <div className="flex items-center gap-3">
          <input
            className="w-40 bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-accent"
            placeholder="Session ID (opt.)"
            value={sessionId}
            onChange={(e) => setSessionId(e.target.value)}
          />
          <button
            onClick={() => run.mutate()}
            disabled={run.isPending || (hosts.length === 0 && !sessionId)}
            className="px-4 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-sm text-white transition-colors"
          >
            {run.isPending ? 'Auditing…' : 'Run Audit'}
          </button>
        </div>
        {run.isError && <p className="text-xs text-red-400">{(run.error as Error).message}</p>}
      </div>

      {/* Results */}
      {isLoading && <p className="text-zinc-500 text-sm">Loading…</p>}
      <div className="flex flex-col gap-2 overflow-auto">
        {audits.map((a) => <AuditRow key={a.id} audit={a} />)}
      </div>
    </div>
  )
}

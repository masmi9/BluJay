import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
  Network, Loader2, CheckCircle2, XCircle, AlertTriangle,
  Info, Play, Copy, Check, ChevronRight, Shield,
} from 'lucide-react'
import { clsx } from 'clsx'
import { protocolTesterApi } from '@/api/protocolTester'

// ── Shared ─────────────────────────────────────────────────────────────────

const STATUS_STYLE: Record<string, string> = {
  PASS:  'text-green-400 border-green-500/30 bg-green-500/10',
  FAIL:  'text-red-400 border-red-500/30 bg-red-500/10',
  WARN:  'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
  INFO:  'text-zinc-400 border-zinc-600/30 bg-zinc-700/20',
  ERROR: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
}

const STATUS_ICON: Record<string, React.ElementType> = {
  PASS:  CheckCircle2,
  FAIL:  XCircle,
  WARN:  AlertTriangle,
  INFO:  Info,
  ERROR: AlertTriangle,
}

function CheckRow({ label, status, detail }: { label: string; status: string; detail: string }) {
  const Icon = STATUS_ICON[status] ?? Info
  return (
    <div className={clsx('flex items-start gap-3 px-4 py-2.5 rounded-lg border', STATUS_STYLE[status] ?? STATUS_STYLE.INFO)}>
      <Icon size={12} className="mt-0.5 shrink-0" />
      <div className="flex-1">
        <span className="text-xs font-medium">{label}</span>
        <p className="text-[10px] mt-0.5 opacity-80">{detail}</p>
      </div>
      <span className="text-[10px] font-semibold shrink-0">{status}</span>
    </div>
  )
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-bg-border bg-bg-surface overflow-hidden">
      <div className="px-4 py-2.5 border-b border-bg-border bg-bg-elevated text-[10px] font-semibold text-zinc-400 uppercase tracking-wider">
        {title}
      </div>
      <div className="p-4">{children}</div>
    </div>
  )
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
      className="text-zinc-500 hover:text-zinc-200 transition-colors shrink-0">
      {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
    </button>
  )
}

// ── TLS Tab ────────────────────────────────────────────────────────────────

function TLSTab() {
  const [host, setHost]   = useState('')
  const [port, setPort]   = useState(443)
  const [result, setResult] = useState<Record<string, unknown> | null>(null)

  const scan = useMutation({
    mutationFn: () => protocolTesterApi.tlsScan(host, port),
    onSuccess: setResult,
  })

  const cert    = result?.certificate as Record<string, unknown> | null | undefined
  const vChecks = (result?.version_checks as { version: string; supported: boolean; status: string }[]) ?? []
  const vulns   = (result?.vuln_checks as { vuln: string; status: string; detail: string }[]) ?? []
  const cChecks = (result?.cert_checks as { check: string; status: string; detail: string }[]) ?? []

  return (
    <div className="space-y-5">
      <div className="flex gap-2 items-end">
        <div className="flex-1">
          <label className="block text-[10px] text-zinc-500 mb-1">Host</label>
          <input className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="example.com or 10.10.10.1"
            value={host}
            onChange={(e) => setHost(e.target.value)} />
        </div>
        <div className="w-24">
          <label className="block text-[10px] text-zinc-500 mb-1">Port</label>
          <input type="number" className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-accent"
            value={port}
            onChange={(e) => setPort(Number(e.target.value))} />
        </div>
        <button onClick={() => scan.mutate()} disabled={scan.isPending || !host.trim()}
          className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {scan.isPending ? <Loader2 size={11} className="animate-spin" /> : <Shield size={11} />}
          Scan
        </button>
      </div>

      {result && (
        <>
          {/* Connection summary */}
          <Panel title="Connection">
            <div className="flex flex-wrap gap-4 text-xs">
              <span className="text-zinc-400">Protocol: <span className="text-zinc-200 font-mono">{String(result.negotiated_proto ?? '—')}</span></span>
              <span className="text-zinc-400">Cipher: <span className={clsx('font-mono', result.cipher_weak ? 'text-red-400' : 'text-zinc-200')}>{String(result.negotiated_cipher ?? '—')}</span></span>
              {result.cipher_weak && <span className="text-red-400 text-[10px] font-semibold">⚠ WEAK CIPHER</span>}
            </div>
          </Panel>

          {/* Certificate */}
          {cert && (
            <Panel title="Certificate">
              <div className="space-y-1.5 text-xs">
                <div><span className="text-zinc-500">CN: </span><span className="font-mono text-zinc-200">{String(cert.cn)}</span></div>
                <div><span className="text-zinc-500">Issuer: </span><span className="text-zinc-200">{String(cert.issuer)}</span></div>
                <div><span className="text-zinc-500">Expires: </span><span className={clsx('font-mono', (cert.days_left as number) < 30 ? 'text-red-400' : 'text-zinc-200')}>{String(cert.not_after)}</span></div>
                {(cert.san as string[])?.length > 0 && (
                  <div><span className="text-zinc-500">SANs: </span><span className="font-mono text-zinc-300 text-[10px]">{(cert.san as string[]).join(', ')}</span></div>
                )}
                {cert.self_signed && <p className="text-red-400 text-[10px]">⚠ Self-signed certificate</p>}
              </div>
              <div className="mt-3 space-y-1.5">
                {cChecks.map((c, i) => <CheckRow key={i} label={c.check} status={c.status} detail={c.detail} />)}
              </div>
            </Panel>
          )}

          {/* Version support */}
          <Panel title="TLS Version Support">
            <div className="space-y-1.5">
              {vChecks.map((c, i) => (
                <CheckRow key={i}
                  label={c.version}
                  status={c.status}
                  detail={c.supported ? 'Supported' : 'Not supported'} />
              ))}
            </div>
          </Panel>

          {/* Vulnerability checks */}
          <Panel title="Known Vulnerabilities">
            <div className="space-y-1.5">
              {vulns.map((v, i) => <CheckRow key={i} label={v.vuln} status={v.status} detail={v.detail} />)}
            </div>
          </Panel>
        </>
      )}
    </div>
  )
}

// ── Subdomains Tab ─────────────────────────────────────────────────────────

function SubdomainTab() {
  const [domain, setDomain]     = useState('')
  const [useCrtsh, setUseCrtsh] = useState(true)
  const [result, setResult]     = useState<Record<string, unknown> | null>(null)
  const [filter, setFilter]     = useState('')

  const enumerate = useMutation({
    mutationFn: () => protocolTesterApi.subdomainEnum(domain, useCrtsh),
    onSuccess: setResult,
  })

  const subs: { subdomain: string; ip?: string | null; source: string }[] =
    ((result?.results as { subdomain: string; ip?: string | null; source: string }[]) ?? [])
      .filter((r) => !filter || r.subdomain.includes(filter))

  const exportList = () => {
    const text = subs.map((s) => s.subdomain).join('\n')
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="space-y-5">
      <div className="flex gap-2 items-end">
        <div className="flex-1">
          <label className="block text-[10px] text-zinc-500 mb-1">Domain</label>
          <input className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)} />
        </div>
        <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer mb-2">
          <input type="checkbox" checked={useCrtsh} onChange={(e) => setUseCrtsh(e.target.checked)} className="accent-accent" />
          crt.sh
        </label>
        <button onClick={() => enumerate.mutate()} disabled={enumerate.isPending || !domain.trim()}
          className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {enumerate.isPending ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
          Enumerate
        </button>
      </div>

      {enumerate.isPending && (
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <Loader2 size={11} className="animate-spin" /> Running crt.sh lookup + DNS brute force (500 subs)…
        </div>
      )}

      {result && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <span className="text-xs text-zinc-400">
              <span className="text-zinc-200 font-medium">{(result.total as number)}</span> subdomains found
            </span>
            <button onClick={exportList} className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300 border border-bg-border rounded px-2 py-0.5 transition-colors">
              <Copy size={10} /> Copy all
            </button>
          </div>

          <input className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="Filter subdomains…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)} />

          <div className="rounded-xl border border-bg-border overflow-hidden">
            <div className="grid grid-cols-[1fr_8rem_5rem] text-[10px] text-zinc-500 uppercase tracking-wider px-4 py-2 bg-bg-elevated border-b border-bg-border">
              <span>Subdomain</span><span>IP</span><span>Source</span>
            </div>
            <div className="divide-y divide-bg-border/50 max-h-96 overflow-auto">
              {subs.map((s, i) => (
                <div key={i} className="grid grid-cols-[1fr_8rem_5rem] items-center px-4 py-2 bg-bg-surface hover:bg-bg-elevated transition-colors">
                  <span className="text-xs font-mono text-zinc-200 truncate">{s.subdomain}</span>
                  <span className="text-[10px] font-mono text-zinc-500">{s.ip ?? '—'}</span>
                  <span className="text-[10px] text-zinc-600">{s.source}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── LDAP Tab ───────────────────────────────────────────────────────────────

function LDAPTab() {
  const [host, setHost]     = useState('')
  const [port, setPort]     = useState(389)
  const [bindDN, setBindDN] = useState('')
  const [bindPw, setBindPw] = useState('')
  const [baseDN, setBaseDN] = useState('')
  const [result, setResult] = useState<Record<string, unknown> | null>(null)

  const enumerate = useMutation({
    mutationFn: () => protocolTesterApi.ldapEnum(host, port, bindDN, bindPw, baseDN),
    onSuccess: setResult,
  })

  const users: { dn: string; sam: string; cn: string; mail: string }[] =
    (result?.users as { dn: string; sam: string; cn: string; mail: string }[]) ?? []

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-[10px] text-zinc-500 mb-1">Host</label>
          <input className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="10.10.10.1 or ldap.domain.com"
            value={host} onChange={(e) => setHost(e.target.value)} />
        </div>
        <div>
          <label className="block text-[10px] text-zinc-500 mb-1">Port</label>
          <input type="number" className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-accent"
            value={port} onChange={(e) => setPort(Number(e.target.value))} />
        </div>
        <div>
          <label className="block text-[10px] text-zinc-500 mb-1">Bind DN (blank = anonymous)</label>
          <input className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="CN=admin,DC=domain,DC=com"
            value={bindDN} onChange={(e) => setBindDN(e.target.value)} />
        </div>
        <div>
          <label className="block text-[10px] text-zinc-500 mb-1">Password</label>
          <input type="password" className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-accent"
            value={bindPw} onChange={(e) => setBindPw(e.target.value)} />
        </div>
        <div className="col-span-2">
          <label className="block text-[10px] text-zinc-500 mb-1">Base DN (auto-detected if blank)</label>
          <input className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="DC=domain,DC=com"
            value={baseDN} onChange={(e) => setBaseDN(e.target.value)} />
        </div>
      </div>

      <button onClick={() => enumerate.mutate()} disabled={enumerate.isPending || !host.trim()}
        className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
        {enumerate.isPending ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
        Enumerate
      </button>

      {result && (
        <>
          {result.error && (
            <div className="flex items-center gap-2 px-3 py-2 rounded border border-red-500/30 bg-red-500/10 text-xs text-red-400">
              <XCircle size={12} /> {String(result.error)}
            </div>
          )}
          {result.anonymous_bind && (
            <div className="flex items-center gap-2 px-3 py-2 rounded border border-yellow-500/30 bg-yellow-500/10 text-xs text-yellow-400">
              <AlertTriangle size={12} /> Anonymous bind succeeded — LDAP allows unauthenticated enumeration
            </div>
          )}

          {(result.naming_contexts as string[])?.length > 0 && (
            <Panel title="Naming Contexts">
              {(result.naming_contexts as string[]).map((nc, i) => (
                <code key={i} className="block text-[11px] font-mono text-zinc-300">{nc}</code>
              ))}
            </Panel>
          )}

          {Object.keys(result.password_policy as object ?? {}).length > 0 && (
            <Panel title="Password Policy">
              {Object.entries(result.password_policy as Record<string, string>).map(([k, v]) => (
                <div key={k} className="flex gap-2 text-xs">
                  <span className="text-zinc-500 capitalize">{k.replace(/_/g, ' ')}:</span>
                  <span className="text-zinc-200 font-mono">{v}</span>
                </div>
              ))}
            </Panel>
          )}

          {users.length > 0 && (
            <Panel title={`Users (${users.length})`}>
              <div className="rounded-lg border border-bg-border overflow-hidden">
                <div className="grid grid-cols-[1fr_1fr_1fr] text-[10px] text-zinc-500 uppercase tracking-wider px-3 py-2 bg-bg-elevated border-b border-bg-border">
                  <span>sAMAccountName</span><span>CN</span><span>Mail</span>
                </div>
                <div className="divide-y divide-bg-border/50 max-h-60 overflow-auto">
                  {users.map((u, i) => (
                    <div key={i} className="grid grid-cols-[1fr_1fr_1fr] px-3 py-2 text-xs bg-bg-surface hover:bg-bg-elevated transition-colors">
                      <span className="font-mono text-zinc-200 truncate">{u.sam}</span>
                      <span className="text-zinc-400 truncate">{u.cn}</span>
                      <span className="text-zinc-500 truncate">{u.mail}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
          )}
        </>
      )}
    </div>
  )
}

// ── gRPC Tab ───────────────────────────────────────────────────────────────

function GRPCTab() {
  const [host, setHost]       = useState('')
  const [port, setPort]       = useState(50051)
  const [useTLS, setUseTLS]   = useState(false)
  const [services, setServices] = useState<string[]>([])
  const [selectedSvc, setSvc] = useState('')
  const [method, setMethod]   = useState('')
  const [body, setBody]       = useState('{}')
  const [sendResult, setSendResult] = useState<Record<string, unknown> | null>(null)
  const [fuzzResult, setFuzzResult] = useState<Record<string, unknown> | null>(null)
  const [fuzzMode, setFuzzMode] = useState(false)
  const [fieldMap, setFieldMap] = useState('{}')

  const reflect = useMutation({
    mutationFn: () => protocolTesterApi.grpcReflect(host, port, useTLS),
    onSuccess: (data: { services: string[] }) => setServices(data.services),
  })

  const send = useMutation({
    mutationFn: () => {
      const payload = JSON.parse(body)
      return protocolTesterApi.grpcSend(host, port, selectedSvc, method, payload, useTLS)
    },
    onSuccess: setSendResult,
  })

  const fuzz = useMutation({
    mutationFn: () => {
      const fm = JSON.parse(fieldMap)
      return protocolTesterApi.grpcFuzz(host, port, selectedSvc, method, fm, useTLS)
    },
    onSuccess: setFuzzResult,
  })

  const fuzzResults: { payload_name: string; status: string; error?: string; response?: string }[] =
    (fuzzResult?.results as { payload_name: string; status: string; error?: string; response?: string }[]) ?? []

  return (
    <div className="space-y-5">
      <div className="flex gap-2 items-end">
        <div className="flex-1">
          <label className="block text-[10px] text-zinc-500 mb-1">Host</label>
          <input className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="localhost or 10.10.10.1"
            value={host} onChange={(e) => setHost(e.target.value)} />
        </div>
        <div className="w-24">
          <label className="block text-[10px] text-zinc-500 mb-1">Port</label>
          <input type="number" className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-accent"
            value={port} onChange={(e) => setPort(Number(e.target.value))} />
        </div>
        <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer mb-2">
          <input type="checkbox" checked={useTLS} onChange={(e) => setUseTLS(e.target.checked)} className="accent-accent" />
          TLS
        </label>
        <button onClick={() => reflect.mutate()} disabled={reflect.isPending || !host.trim()}
          className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {reflect.isPending ? <Loader2 size={11} className="animate-spin" /> : <Network size={11} />}
          Reflect
        </button>
      </div>

      {services.length > 0 && (
        <Panel title={`Services (${services.length})`}>
          <div className="flex flex-wrap gap-1.5">
            {services.map((svc) => (
              <button key={svc} onClick={() => setSvc(svc)}
                className={clsx('px-2.5 py-1 text-[10px] font-mono rounded border transition-colors',
                  selectedSvc === svc ? 'border-accent bg-accent/10 text-accent' : 'border-bg-border text-zinc-400 hover:text-zinc-200'
                )}>
                {svc.split('.').pop()}
              </button>
            ))}
          </div>
        </Panel>
      )}

      {(services.length > 0 || selectedSvc) && (
        <div className="space-y-3">
          <div className="flex gap-1 mb-2">
            <button onClick={() => setFuzzMode(false)}
              className={clsx('px-3 py-1.5 text-xs rounded border transition-colors',
                !fuzzMode ? 'border-accent bg-accent/10 text-accent' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
              )}>Send</button>
            <button onClick={() => setFuzzMode(true)}
              className={clsx('px-3 py-1.5 text-xs rounded border transition-colors',
                fuzzMode ? 'border-red-500/50 bg-red-500/10 text-red-400' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
              )}>Fuzz</button>
          </div>

          <div>
            <label className="block text-[10px] text-zinc-500 mb-1">Method</label>
            <input className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
              placeholder="SayHello"
              value={method} onChange={(e) => setMethod(e.target.value)} />
          </div>

          {fuzzMode ? (
            <div>
              <label className="block text-[10px] text-zinc-500 mb-1">Field Map (JSON object of field names to types)</label>
              <textarea className="w-full h-20 bg-bg-elevated border border-bg-border rounded p-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent resize-none"
                value={fieldMap} onChange={(e) => setFieldMap(e.target.value)} />
              <button onClick={() => fuzz.mutate()} disabled={fuzz.isPending || !selectedSvc || !method}
                className="mt-2 flex items-center gap-1.5 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
                {fuzz.isPending ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
                Fuzz ({15} payloads)
              </button>
            </div>
          ) : (
            <div>
              <label className="block text-[10px] text-zinc-500 mb-1">Payload (JSON)</label>
              <textarea className="w-full h-28 bg-bg-elevated border border-bg-border rounded p-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent resize-none"
                value={body} onChange={(e) => setBody(e.target.value)} />
              <button onClick={() => send.mutate()} disabled={send.isPending || !selectedSvc || !method}
                className="mt-2 flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
                {send.isPending ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
                Send
              </button>
            </div>
          )}
        </div>
      )}

      {sendResult && (
        <Panel title="Response">
          <pre className="text-[11px] font-mono text-zinc-300 whitespace-pre-wrap break-all">
            {JSON.stringify(sendResult, null, 2)}
          </pre>
        </Panel>
      )}

      {fuzzResult && (
        <Panel title={`Fuzz Results — ${(fuzzResult.errors as number)} errors / ${(fuzzResult.timeouts as number)} timeouts`}>
          <div className="space-y-1.5">
            {fuzzResults.map((r, i) => (
              <div key={i} className={clsx('flex items-center gap-3 px-3 py-2 rounded border',
                r.status === 'error' ? 'border-yellow-500/30 bg-yellow-500/5' :
                r.status === 'timeout' ? 'border-red-500/30 bg-red-500/5' :
                'border-bg-border bg-bg-elevated'
              )}>
                <span className={clsx('text-[10px] font-semibold shrink-0 w-12 text-center',
                  r.status === 'error' ? 'text-yellow-400' :
                  r.status === 'timeout' ? 'text-red-400' :
                  'text-green-400'
                )}>{r.status}</span>
                <span className="text-[10px] text-zinc-400 font-mono shrink-0 w-36">{r.payload_name}</span>
                <span className="text-[10px] text-zinc-500 truncate">{r.error ?? r.response ?? ''}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────

const TABS = [
  { id: 'tls',       label: 'TLS / SSL' },
  { id: 'subdomain', label: 'Subdomains' },
  { id: 'ldap',      label: 'LDAP' },
  { id: 'grpc',      label: 'gRPC' },
]

export default function ProtocolTesterPage() {
  const [tab, setTab] = useState('tls')

  return (
    <div className="h-full overflow-auto p-6">
      <div className="max-w-4xl space-y-5">
        <div className="flex items-center gap-2">
          <Network size={18} className="text-accent" />
          <h1 className="text-base font-semibold text-zinc-100">Protocol Tester</h1>
        </div>
        <p className="text-xs text-zinc-500">TLS/SSL analysis · subdomain enumeration · LDAP enumeration · gRPC fuzzing</p>

        <div className="flex gap-1 border-b border-bg-border">
          {TABS.map(({ id, label }) => (
            <button key={id} onClick={() => setTab(id)}
              className={clsx('px-4 py-2 text-xs font-medium rounded-t transition-colors border-b-2 -mb-px',
                tab === id ? 'border-accent text-accent bg-accent/5' : 'border-transparent text-zinc-500 hover:text-zinc-300'
              )}>
              {label}
            </button>
          ))}
        </div>

        <div className="pt-1">
          {tab === 'tls'       && <TLSTab />}
          {tab === 'subdomain' && <SubdomainTab />}
          {tab === 'ldap'      && <LDAPTab />}
          {tab === 'grpc'      && <GRPCTab />}
        </div>
      </div>
    </div>
  )
}

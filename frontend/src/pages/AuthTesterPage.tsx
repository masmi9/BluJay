import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
  KeyRound, Loader2, AlertTriangle, CheckCircle2, XCircle,
  Info, ChevronDown, ChevronRight, Copy, Check, Zap, Shield,
  Lock, FileCode,
} from 'lucide-react'
import { clsx } from 'clsx'
import { authTesterApi } from '@/api/authTester'

// ── Shared helpers ─────────────────────────────────────────────────────────

type FindingStatus = 'PASS' | 'FAIL' | 'WARN' | 'INFO' | 'CRITICAL'

const STATUS_STYLE: Record<FindingStatus, string> = {
  CRITICAL: 'bg-red-600 text-white',
  FAIL:     'bg-red-500/20 text-red-400 border border-red-500/30',
  WARN:     'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30',
  PASS:     'bg-green-500/20 text-green-400 border border-green-500/30',
  INFO:     'bg-zinc-700/50 text-zinc-400 border border-zinc-600/30',
}

const STATUS_ICON: Record<FindingStatus, React.ElementType> = {
  CRITICAL: XCircle,
  FAIL:     XCircle,
  WARN:     AlertTriangle,
  PASS:     CheckCircle2,
  INFO:     Info,
}

function FindingRow({ check, status, detail }: { check: string; status: string; detail: string }) {
  const s = status as FindingStatus
  const Icon = STATUS_ICON[s] ?? Info
  return (
    <div className="flex items-start gap-3 py-2 border-b border-bg-border/50 last:border-0">
      <span className={clsx('shrink-0 text-[10px] px-1.5 py-0.5 rounded font-medium mt-0.5 min-w-[3.5rem] text-center', STATUS_STYLE[s] ?? STATUS_STYLE.INFO)}>
        {status}
      </span>
      <Icon size={12} className={clsx('mt-0.5 shrink-0',
        s === 'PASS' ? 'text-green-400' : s === 'FAIL' || s === 'CRITICAL' ? 'text-red-400' : s === 'WARN' ? 'text-yellow-400' : 'text-zinc-500'
      )} />
      <div className="flex-1 min-w-0">
        <span className="text-xs font-medium text-zinc-300">{check}</span>
        <p className="text-[10px] text-zinc-500 mt-0.5 leading-relaxed">{detail}</p>
      </div>
    </div>
  )
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
      className="text-zinc-500 hover:text-zinc-200 transition-colors">
      {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
    </button>
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

function JSONTree({ data }: { data: Record<string, unknown> }) {
  return (
    <pre className="text-[11px] font-mono text-zinc-300 whitespace-pre-wrap leading-relaxed">
      {JSON.stringify(data, null, 2)}
    </pre>
  )
}

// ── JWT Tab ────────────────────────────────────────────────────────────────

function JWTTab() {
  const [token, setToken]     = useState('')
  const [attack, setAttack]   = useState('none')
  const [secret, setSecret]   = useState('')
  const [kidPayload, setKid]  = useState("' OR '1'='1")
  const [verifyAlg, setAlg]   = useState('HS256')
  const [decoded, setDecoded] = useState<Record<string, unknown> | null>(null)
  const [forged, setForged]   = useState<Record<string, unknown> | null>(null)
  const [verified, setVerified] = useState<Record<string, unknown> | null>(null)

  const decodeMut = useMutation({ mutationFn: () => authTesterApi.jwtDecode(token), onSuccess: setDecoded })
  const forgeMut  = useMutation({ mutationFn: () => authTesterApi.jwtForge(token, attack, secret, kidPayload), onSuccess: setForged })
  const verifyMut = useMutation({ mutationFn: () => authTesterApi.jwtVerify(token, secret, verifyAlg), onSuccess: setVerified })

  const warnings: string[] = (decoded as { warnings?: string[] })?.warnings ?? []

  return (
    <div className="space-y-5">
      <Panel title="Token Input">
        <textarea
          className="w-full h-24 bg-bg-elevated border border-bg-border rounded p-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent resize-none leading-relaxed placeholder-zinc-600"
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
          value={token}
          onChange={(e) => { setToken(e.target.value); setDecoded(null); setForged(null); setVerified(null) }}
        />
        <button onClick={() => decodeMut.mutate()} disabled={decodeMut.isPending || !token.trim()}
          className="mt-2 flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {decodeMut.isPending ? <Loader2 size={11} className="animate-spin" /> : <Zap size={11} />}
          Decode & Inspect
        </button>
      </Panel>

      {decoded && (
        <>
          {warnings.length > 0 && (
            <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-3 space-y-1.5">
              <div className="flex items-center gap-1.5 text-[10px] font-semibold text-yellow-400 uppercase tracking-wider mb-2">
                <AlertTriangle size={10} /> Security Warnings
              </div>
              {warnings.map((w, i) => (
                <p key={i} className="text-xs text-yellow-300/80 flex items-start gap-2">
                  <span className="shrink-0 mt-0.5">▸</span>{w}
                </p>
              ))}
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <Panel title="Header"><JSONTree data={(decoded as { header: Record<string, unknown> }).header} /></Panel>
            <Panel title="Payload"><JSONTree data={(decoded as { payload: Record<string, unknown> }).payload} /></Panel>
          </div>
        </>
      )}

      <Panel title="Attack — Forge Token">
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            {[
              { value: 'none',           label: 'alg: none' },
              { value: 'hs256_confusion', label: 'RS256 → HS256' },
              { value: 'kid_sqli',       label: 'kid SQL Injection' },
              { value: 'kid_traversal',  label: 'kid Path Traversal' },
            ].map((a) => (
              <button key={a.value} onClick={() => setAttack(a.value)}
                className={clsx('px-3 py-1.5 text-xs rounded border transition-colors',
                  attack === a.value ? 'border-red-500/50 bg-red-500/10 text-red-400' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
                )}>
                {a.label}
              </button>
            ))}
          </div>

          {(attack === 'hs256_confusion') && (
            <div>
              <label className="block text-[10px] text-zinc-500 mb-1">RSA Public Key (PEM) used as HMAC secret</label>
              <textarea
                className="w-full h-24 bg-bg-elevated border border-bg-border rounded p-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent resize-none"
                placeholder="-----BEGIN PUBLIC KEY-----&#10;..."
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
            </div>
          )}

          {attack === 'kid_sqli' && (
            <div>
              <label className="block text-[10px] text-zinc-500 mb-1">kid SQL payload</label>
              <input
                className="w-full bg-bg-elevated border border-bg-border rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent"
                value={kidPayload}
                onChange={(e) => setKid(e.target.value)}
              />
            </div>
          )}

          <button onClick={() => forgeMut.mutate()} disabled={forgeMut.isPending || !token.trim()}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
            {forgeMut.isPending ? <Loader2 size={11} className="animate-spin" /> : <Zap size={11} />}
            Forge Token
          </button>

          {forged && (
            <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-3 space-y-2">
              <p className="text-[10px] text-zinc-400">{(forged as { description: string }).description}</p>
              <div className="flex items-start gap-2">
                <code className="flex-1 text-[11px] font-mono text-red-300 break-all leading-relaxed">
                  {(forged as { forged_token: string }).forged_token}
                </code>
                <CopyBtn text={(forged as { forged_token: string }).forged_token} />
              </div>
            </div>
          )}
        </div>
      </Panel>

      <Panel title="Verify Signature">
        <div className="space-y-3">
          <div className="flex gap-2">
            <input
              className="flex-1 bg-bg-elevated border border-bg-border rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
              placeholder="HMAC secret or RSA public key"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
            <select aria-label="Algorithm" value={verifyAlg} onChange={(e) => setAlg(e.target.value)}
              className="bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent">
              {['HS256','HS384','HS512','RS256','RS384','RS512','ES256'].map((a) => (
                <option key={a} value={a}>{a}</option>
              ))}
            </select>
          </div>
          <button onClick={() => verifyMut.mutate()} disabled={verifyMut.isPending || !token.trim() || !secret.trim()}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
            {verifyMut.isPending ? <Loader2 size={11} className="animate-spin" /> : <Shield size={11} />}
            Verify
          </button>
          {verified && (
            <div className={clsx('rounded-lg border p-3 text-xs',
              (verified as { valid: boolean }).valid
                ? 'border-green-500/30 bg-green-500/5 text-green-400'
                : 'border-red-500/30 bg-red-500/5 text-red-400'
            )}>
              {(verified as { valid: boolean }).valid
                ? '✓ Signature is valid'
                : `✗ Invalid: ${(verified as { error?: string }).error}`}
            </div>
          )}
        </div>
      </Panel>
    </div>
  )
}

// ── OAuth Tab ──────────────────────────────────────────────────────────────

function OAuthTab() {
  const [url, setUrl]   = useState('')
  const [result, setResult] = useState<Record<string, unknown> | null>(null)

  const audit = useMutation({ mutationFn: () => authTesterApi.oauthAudit(url), onSuccess: setResult })

  const findings: { check: string; status: string; detail: string }[] = (result as { findings?: { check: string; status: string; detail: string }[] })?.findings ?? []
  const failCount = findings.filter((f) => f.status === 'FAIL' || f.status === 'WARN').length

  return (
    <div className="space-y-5">
      <Panel title="Authorization URL">
        <textarea
          className="w-full h-24 bg-bg-elevated border border-bg-border rounded p-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent resize-none placeholder-zinc-600"
          placeholder="https://auth.example.com/oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=..."
          value={url}
          onChange={(e) => { setUrl(e.target.value); setResult(null) }}
        />
        <button onClick={() => audit.mutate()} disabled={audit.isPending || !url.trim()}
          className="mt-2 flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {audit.isPending ? <Loader2 size={11} className="animate-spin" /> : <Shield size={11} />}
          Audit URL
        </button>
      </Panel>

      {result && (
        <Panel title={`Findings${failCount > 0 ? ` — ${failCount} issue${failCount !== 1 ? 's' : ''}` : ' — All checks passed'}`}>
          <div className="divide-y divide-bg-border/30">
            {findings.map((f, i) => <FindingRow key={i} {...f} />)}
          </div>
        </Panel>
      )}

      {result && (result as { params?: Record<string, string> }).params && (
        <Panel title="Parsed Parameters">
          <JSONTree data={(result as { params: Record<string, unknown> }).params} />
        </Panel>
      )}
    </div>
  )
}

// ── Session/Cookie Tab ─────────────────────────────────────────────────────

function SessionTab() {
  const [rawHeaders, setRaw] = useState('')
  const [result, setResult]  = useState<Record<string, unknown> | null>(null)

  const analyze = useMutation({
    mutationFn: () => {
      const headers = rawHeaders.split('\n').map((s) => s.trim()).filter(Boolean)
      return authTesterApi.sessionAnalyze(headers)
    },
    onSuccess: setResult,
  })

  const cookies: { name: string; value: string; findings: { flag: string; status: string; detail: string }[] }[] =
    (result as { cookies?: { name: string; value: string; findings: { flag: string; status: string; detail: string }[] }[] })?.cookies ?? []

  return (
    <div className="space-y-5">
      <Panel title="Set-Cookie Headers (one per line)">
        <textarea
          className="w-full h-32 bg-bg-elevated border border-bg-border rounded p-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent resize-none placeholder-zinc-600"
          placeholder={`session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/\nsecret=xyz; Path=/`}
          value={rawHeaders}
          onChange={(e) => { setRaw(e.target.value); setResult(null) }}
        />
        <button onClick={() => analyze.mutate()} disabled={analyze.isPending || !rawHeaders.trim()}
          className="mt-2 flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {analyze.isPending ? <Loader2 size={11} className="animate-spin" /> : <Lock size={11} />}
          Analyze Cookies
        </button>
      </Panel>

      {cookies.map((c) => (
        <Panel key={c.name} title={`Cookie: ${c.name}`}>
          <div className="mb-3">
            <span className="text-[10px] text-zinc-500">Value (truncated): </span>
            <code className="text-[11px] font-mono text-zinc-300">{c.value}</code>
          </div>
          <div className="divide-y divide-bg-border/30">
            {c.findings.map((f, i) => <FindingRow key={i} check={f.flag} status={f.status} detail={f.detail} />)}
          </div>
        </Panel>
      ))}
    </div>
  )
}

// ── SAML Tab ───────────────────────────────────────────────────────────────

function SAMLTab() {
  const [input, setInput]       = useState('')
  const [isResponse, setIsResp] = useState(false)
  const [result, setResult]     = useState<Record<string, unknown> | null>(null)
  const [showXml, setShowXml]   = useState(false)

  const decode = useMutation({ mutationFn: () => authTesterApi.samlDecode(input, isResponse), onSuccess: setResult })

  const findings: { check: string; status: string; detail: string }[] = (result as { findings?: { check: string; status: string; detail: string }[] })?.findings ?? []

  return (
    <div className="space-y-5">
      <Panel title="Encoded SAML Message">
        <div className="flex items-center gap-3 mb-2">
          <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer">
            <input type="checkbox" checked={isResponse} onChange={(e) => setIsResp(e.target.checked)} className="accent-accent" />
            Is SAMLResponse (vs SAMLRequest)
          </label>
        </div>
        <textarea
          className="w-full h-28 bg-bg-elevated border border-bg-border rounded p-2.5 text-xs font-mono text-zinc-300 focus:outline-none focus:border-accent resize-none placeholder-zinc-600"
          placeholder="Paste base64-encoded SAMLRequest or SAMLResponse here…"
          value={input}
          onChange={(e) => { setInput(e.target.value); setResult(null) }}
        />
        <button onClick={() => decode.mutate()} disabled={decode.isPending || !input.trim()}
          className="mt-2 flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {decode.isPending ? <Loader2 size={11} className="animate-spin" /> : <FileCode size={11} />}
          Decode & Inspect
        </button>
      </Panel>

      {result && (
        <>
          <Panel title={`Security Findings (${findings.length})`}>
            <div className="divide-y divide-bg-border/30">
              {findings.map((f, i) => <FindingRow key={i} {...f} />)}
            </div>
          </Panel>
          <div className="rounded-xl border border-bg-border overflow-hidden">
            <button onClick={() => setShowXml((v) => !v)}
              className="w-full flex items-center gap-2 px-4 py-2.5 bg-bg-elevated hover:bg-bg-surface text-left transition-colors">
              {showXml ? <ChevronDown size={12} className="text-zinc-500" /> : <ChevronRight size={12} className="text-zinc-500" />}
              <span className="text-[10px] font-semibold text-zinc-400 uppercase tracking-wider">Decoded XML</span>
              <span className="text-[10px] text-zinc-600 ml-1">({(result as { length: number }).length} chars)</span>
              <div className="flex-1" />
              <CopyBtn text={(result as { xml: string }).xml} />
            </button>
            {showXml && (
              <div className="p-4 bg-bg-surface overflow-auto max-h-96">
                <pre className="text-[11px] font-mono text-zinc-300 whitespace-pre-wrap leading-relaxed">
                  {(result as { xml: string }).xml}
                </pre>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────

const TABS = [
  { id: 'jwt',     label: 'JWT',          icon: KeyRound },
  { id: 'oauth',   label: 'OAuth / OIDC', icon: Shield },
  { id: 'session', label: 'Session / Cookie', icon: Lock },
  { id: 'saml',    label: 'SAML',         icon: FileCode },
]

export default function AuthTesterPage() {
  const [tab, setTab] = useState('jwt')

  return (
    <div className="h-full overflow-auto p-6">
      <div className="max-w-4xl space-y-5">
        <div className="flex items-center gap-2 mb-1">
          <KeyRound size={18} className="text-accent" />
          <h1 className="text-base font-semibold text-zinc-100">Auth &amp; Session Tester</h1>
        </div>
        <p className="text-xs text-zinc-500">JWT analysis &amp; forgery · OAuth 2.0 / OIDC audit · Cookie security · SAML decoder</p>

        <div className="flex gap-1 border-b border-bg-border pb-0">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setTab(id)}
              className={clsx(
                'flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-t transition-colors border-b-2 -mb-px',
                tab === id
                  ? 'border-accent text-accent bg-accent/5'
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              )}>
              <Icon size={12} />{label}
            </button>
          ))}
        </div>

        <div className="pt-1">
          {tab === 'jwt'     && <JWTTab />}
          {tab === 'oauth'   && <OAuthTab />}
          {tab === 'session' && <SessionTab />}
          {tab === 'saml'    && <SAMLTab />}
        </div>
      </div>
    </div>
  )
}

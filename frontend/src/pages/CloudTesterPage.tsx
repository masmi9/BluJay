import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
  Cloud, Loader2, AlertTriangle, CheckCircle2, XCircle,
  Copy, Check, Shield, Key, Database,
} from 'lucide-react'
import { clsx } from 'clsx'
import { cloudTesterApi } from '@/api/cloudTester'

// ── Shared ─────────────────────────────────────────────────────────────────

const CHECK_STYLE: Record<string, string> = {
  VULNERABLE: 'text-red-400 border-red-500/30 bg-red-500/10',
  CRITICAL:   'text-red-400 border-red-500/30 bg-red-500/10',
  SECURE:     'text-green-400 border-green-500/30 bg-green-500/10',
  INFO:       'text-zinc-400 border-zinc-600/30 bg-zinc-700/20',
  ERROR:      'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
}

const CHECK_ICON: Record<string, React.ElementType> = {
  VULNERABLE: XCircle,
  CRITICAL:   XCircle,
  SECURE:     CheckCircle2,
  INFO:       Shield,
  ERROR:      AlertTriangle,
}

function CheckRow({ check, status, detail }: { check: string; status: string; detail: string }) {
  const Icon = CHECK_ICON[status] ?? Shield
  const style = CHECK_STYLE[status] ?? CHECK_STYLE.INFO
  return (
    <div className={clsx('flex items-start gap-3 px-4 py-2.5 rounded-lg border', style)}>
      <Icon size={13} className="mt-0.5 shrink-0" />
      <div className="flex-1">
        <span className="text-xs font-medium">{check}</span>
        <p className="text-[10px] mt-0.5 opacity-80">{detail}</p>
      </div>
      <span className="text-[10px] font-semibold shrink-0">{status}</span>
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

// ── IMDS / SSRF Tab ────────────────────────────────────────────────────────

const ALL_PROVIDERS = ['aws', 'gcp', 'azure', 'do']

function IMDSTab() {
  const [mode, setMode]           = useState<'direct' | 'ssrf'>('direct')
  const [target, setTarget]       = useState('')
  const [callbackUrl, setCallback] = useState('')
  const [providers, setProviders] = useState(['aws', 'gcp', 'azure', 'do'])
  const [result, setResult]       = useState<Record<string, unknown> | null>(null)
  const [ssrfResult, setSsrfResult] = useState<Record<string, unknown> | null>(null)

  const toggleProvider = (p: string) => setProviders((prev) =>
    prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p])

  const probe = useMutation({
    mutationFn: () => cloudTesterApi.imdsProbe(target.trim() || null, providers),
    onSuccess: setResult,
  })

  const generateSsrf = useMutation({
    mutationFn: () => cloudTesterApi.ssrfGenerate(callbackUrl.trim(), providers),
    onSuccess: setSsrfResult,
  })

  const providerResults = (result as { providers?: Record<string, { label: string; url: string; reachable: boolean; sensitive?: boolean; status?: number; body?: string; error?: string }[]> })?.providers ?? {}

  return (
    <div className="space-y-5">
      <div className="flex gap-1">
        {(['direct', 'ssrf'] as const).map((m) => (
          <button key={m} onClick={() => setMode(m)}
            className={clsx('px-3 py-1.5 text-xs rounded border transition-colors',
              mode === m ? 'border-accent bg-accent/10 text-accent' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
            )}>
            {m === 'direct' ? 'Direct Probe' : 'SSRF Payload Generator'}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        <p className="text-[10px] text-zinc-500">Cloud Providers</p>
        <div className="flex gap-2">
          {ALL_PROVIDERS.map((p) => (
            <button key={p} onClick={() => toggleProvider(p)}
              className={clsx('px-3 py-1 text-[10px] rounded border transition-colors uppercase',
                providers.includes(p) ? 'border-accent bg-accent/10 text-accent' : 'border-bg-border text-zinc-500 hover:text-zinc-300'
              )}>
              {p}
            </button>
          ))}
        </div>
      </div>

      {mode === 'direct' ? (
        <div className="space-y-3">
          <div>
            <label className="block text-[10px] text-zinc-500 mb-1">Target Host (optional — blank = probe IMDS IPs directly)</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
              placeholder="10.10.10.1 or blank for direct probe"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <button onClick={() => probe.mutate()} disabled={probe.isPending}
            className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
            {probe.isPending ? <Loader2 size={11} className="animate-spin" /> : <Shield size={11} />}
            Probe IMDS
          </button>

          {result && (
            <div className="space-y-4">
              <div className="flex gap-4 text-xs">
                <span className="text-zinc-400">
                  <span className="text-zinc-200 font-medium">{(result as { reachable_count: number }).reachable_count}</span> reachable
                </span>
                {(result as { sensitive_count: number }).sensitive_count > 0 && (
                  <span className="text-red-400 font-medium">
                    {(result as { sensitive_count: number }).sensitive_count} sensitive responses!
                  </span>
                )}
              </div>

              {Object.entries(providerResults).map(([prov, endpoints]) => (
                <Panel key={prov} title={prov.toUpperCase()}>
                  <div className="space-y-2">
                    {endpoints.map((ep, i) => (
                      <div key={i} className={clsx('rounded-lg border p-3 space-y-1',
                        ep.sensitive ? 'border-red-500/30 bg-red-500/5' :
                        ep.reachable ? 'border-green-500/20 bg-green-500/5' :
                        'border-bg-border bg-bg-elevated'
                      )}>
                        <div className="flex items-center gap-2">
                          {ep.reachable
                            ? <CheckCircle2 size={11} className={ep.sensitive ? 'text-red-400' : 'text-green-400'} />
                            : <XCircle size={11} className="text-zinc-600" />}
                          <span className="text-xs font-medium text-zinc-300">{ep.label}</span>
                          {ep.status && <span className="text-[10px] text-zinc-500 ml-auto">{ep.status}</span>}
                          {ep.sensitive && <span className="text-[10px] text-red-400 font-semibold">CREDENTIALS FOUND</span>}
                        </div>
                        <p className="text-[10px] font-mono text-zinc-600 pl-5">{ep.url}</p>
                        {ep.reachable && ep.body && (
                          <div className="flex items-start gap-2 pl-5 mt-1">
                            <pre className="text-[10px] text-zinc-400 whitespace-pre-wrap break-all flex-1 max-h-24 overflow-auto">
                              {ep.body.slice(0, 500)}
                            </pre>
                            <CopyBtn text={ep.body} />
                          </div>
                        )}
                        {ep.error && <p className="text-[10px] text-zinc-600 pl-5">{ep.error}</p>}
                      </div>
                    ))}
                  </div>
                </Panel>
              ))}
            </div>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <div>
            <label className="block text-[10px] text-zinc-500 mb-1">Callback / SSRF target URL (optional)</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
              placeholder="https://vulnerable-app.com/fetch?url="
              value={callbackUrl}
              onChange={(e) => setCallback(e.target.value)}
            />
          </div>
          <button onClick={() => generateSsrf.mutate()} disabled={generateSsrf.isPending}
            className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
            {generateSsrf.isPending ? <Loader2 size={11} className="animate-spin" /> : <Shield size={11} />}
            Generate Payloads
          </button>

          {ssrfResult && (
            <div className="space-y-4">
              {Object.entries((ssrfResult as { payloads: Record<string, { direct: string[]; encoded: string[]; wrapped: string[] }> }).payloads).map(([prov, data]) => (
                <Panel key={prov} title={`${prov.toUpperCase()} Payloads`}>
                  {(['direct', 'encoded', 'wrapped'] as const).filter((k) => data[k].length > 0).map((kind) => (
                    <div key={kind} className="mb-3">
                      <p className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1.5 capitalize">{kind}</p>
                      <div className="space-y-1">
                        {data[kind].map((payload, i) => (
                          <div key={i} className="flex items-center gap-2 bg-bg-elevated rounded px-2.5 py-1.5">
                            <code className="text-[10px] font-mono text-zinc-300 flex-1 break-all">{payload}</code>
                            <CopyBtn text={payload} />
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </Panel>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Bucket Audit Tab ───────────────────────────────────────────────────────

function BucketTab() {
  const [bucket, setBucket]     = useState('')
  const [provider, setProvider] = useState('aws')
  const [region, setRegion]     = useState('us-east-1')
  const [result, setResult]     = useState<Record<string, unknown> | null>(null)

  const check = useMutation({
    mutationFn: () => cloudTesterApi.bucketCheck(bucket, provider, region),
    onSuccess: setResult,
  })

  const checks: { check: string; status: string; detail: string }[] = (result as { checks?: { check: string; status: string; detail: string }[] })?.checks ?? []

  return (
    <div className="space-y-5">
      <div className="flex gap-2 flex-wrap">
        <input
          className="flex-1 bg-bg-elevated border border-bg-border rounded px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600 min-w-48"
          placeholder="bucket-name (AWS/GCP) or account/container (Azure)"
          value={bucket}
          onChange={(e) => setBucket(e.target.value)}
        />
        <select aria-label="Cloud provider" value={provider} onChange={(e) => setProvider(e.target.value)}
          className="bg-bg-elevated border border-bg-border rounded px-2.5 py-2 text-xs text-zinc-200 focus:outline-none focus:border-accent">
          <option value="aws">AWS S3</option>
          <option value="gcp">GCP GCS</option>
          <option value="azure">Azure Blob</option>
        </select>
        {provider === 'aws' && (
          <input
            className="w-32 bg-bg-elevated border border-bg-border rounded px-2.5 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent"
            placeholder="us-east-1"
            value={region}
            onChange={(e) => setRegion(e.target.value)}
          />
        )}
        <button onClick={() => check.mutate()} disabled={check.isPending || !bucket.trim()}
          className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {check.isPending ? <Loader2 size={11} className="animate-spin" /> : <Database size={11} />}
          Check Bucket
        </button>
      </div>

      {result && (
        <div className="space-y-2">
          <p className="text-[10px] text-zinc-500">
            {provider.toUpperCase()} — <span className="font-mono text-zinc-300">{bucket}</span>
          </p>
          {checks.map((c, i) => <CheckRow key={i} {...c} />)}
        </div>
      )}
    </div>
  )
}

// ── Credential Scanner Tab ─────────────────────────────────────────────────

const CONF_STYLE: Record<string, string> = {
  HIGH:   'bg-red-500/20 text-red-400 border border-red-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  LOW:    'bg-zinc-700/50 text-zinc-400 border border-zinc-600/30',
}

function CredScanTab() {
  const [text, setText]         = useState('')
  const [accessKey, setAK]      = useState('')
  const [secretKey, setSK]      = useState('')
  const [sessionTok, setSession] = useState('')
  const [scanResult, setScanResult] = useState<Record<string, unknown> | null>(null)
  const [validateResult, setValidateResult] = useState<Record<string, unknown> | null>(null)

  const scan = useMutation({
    mutationFn: () => cloudTesterApi.credsScan(text),
    onSuccess: setScanResult,
  })

  const validate = useMutation({
    mutationFn: () => cloudTesterApi.credsValidate(accessKey, secretKey, sessionTok || undefined),
    onSuccess: setValidateResult,
  })

  const findings: { type: string; name: string; confidence: string; redacted: string; line: number }[] =
    (scanResult as { findings?: { type: string; name: string; confidence: string; redacted: string; line: number }[] })?.findings ?? []

  return (
    <div className="space-y-5">
      <Panel title="Scan Text for Credentials">
        <textarea
          className="w-full h-32 bg-bg-elevated border border-bg-border rounded p-2.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent resize-none placeholder-zinc-600"
          placeholder="Paste source code, config files, environment exports, or any text to scan for cloud credentials…"
          value={text}
          onChange={(e) => { setText(e.target.value); setScanResult(null) }}
        />
        <button onClick={() => scan.mutate()} disabled={scan.isPending || !text.trim()}
          className="mt-2 flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
          {scan.isPending ? <Loader2 size={11} className="animate-spin" /> : <Key size={11} />}
          Scan for Credentials
        </button>
      </Panel>

      {scanResult && (
        <Panel title={`Found ${(scanResult as { total: number }).total} credential pattern${(scanResult as { total: number }).total !== 1 ? 's' : ''}`}>
          {findings.length === 0 ? (
            <p className="text-xs text-zinc-600">No credential patterns found</p>
          ) : (
            <div className="space-y-2">
              {findings.map((f, i) => (
                <div key={i} className="flex items-start gap-3 p-3 rounded-lg border border-bg-border bg-bg-elevated">
                  <span className={clsx('text-[10px] px-1.5 py-0.5 rounded font-semibold shrink-0', CONF_STYLE[f.confidence] ?? CONF_STYLE.LOW)}>
                    {f.confidence}
                  </span>
                  <div className="flex-1">
                    <p className="text-xs font-medium text-zinc-200">{f.name}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <code className="text-[10px] font-mono text-zinc-400">{f.redacted}</code>
                      <span className="text-[10px] text-zinc-600">line {f.line}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      )}

      <Panel title="Validate AWS Credentials (sts:GetCallerIdentity)">
        <div className="space-y-2">
          <input className="w-full bg-bg-elevated border border-bg-border rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="AKIA... (Access Key ID)"
            value={accessKey}
            onChange={(e) => setAK(e.target.value)} />
          <input className="w-full bg-bg-elevated border border-bg-border rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="Secret Access Key"
            type="password"
            value={secretKey}
            onChange={(e) => setSK(e.target.value)} />
          <input className="w-full bg-bg-elevated border border-bg-border rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-accent placeholder-zinc-600"
            placeholder="Session Token (optional)"
            value={sessionTok}
            onChange={(e) => setSession(e.target.value)} />
          <button onClick={() => validate.mutate()} disabled={validate.isPending || !accessKey.trim() || !secretKey.trim()}
            className="flex items-center gap-1.5 px-4 py-2 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors">
            {validate.isPending ? <Loader2 size={11} className="animate-spin" /> : <Shield size={11} />}
            Validate
          </button>
        </div>

        {validateResult && (
          <div className={clsx('mt-3 rounded-lg border p-3 space-y-1',
            (validateResult as { valid: boolean }).valid
              ? 'border-red-500/30 bg-red-500/5 text-red-300'
              : 'border-zinc-600/30 bg-zinc-700/20 text-zinc-400'
          )}>
            {(validateResult as { valid: boolean }).valid ? (
              <>
                <p className="text-xs font-semibold text-red-400">⚠ Valid credentials — active AWS account!</p>
                <p className="text-[10px]">Account: <span className="font-mono">{String((validateResult as { account?: string }).account)}</span></p>
                <p className="text-[10px]">ARN: <span className="font-mono">{String((validateResult as { arn?: string }).arn)}</span></p>
                <p className="text-[10px]">User ID: <span className="font-mono">{String((validateResult as { user_id?: string }).user_id)}</span></p>
              </>
            ) : (
              <p className="text-xs">{String((validateResult as { error?: string }).error)}</p>
            )}
          </div>
        )}
      </Panel>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────

const TABS = [
  { id: 'imds',    label: 'IMDS / SSRF',        icon: Shield },
  { id: 'bucket',  label: 'Bucket Audit',        icon: Database },
  { id: 'creds',   label: 'Credential Scanner',  icon: Key },
]

export default function CloudTesterPage() {
  const [tab, setTab] = useState('imds')

  return (
    <div className="h-full overflow-auto p-6">
      <div className="max-w-4xl space-y-5">
        <div className="flex items-center gap-2">
          <Cloud size={18} className="text-accent" />
          <h1 className="text-base font-semibold text-zinc-100">Cloud Tester</h1>
        </div>
        <p className="text-xs text-zinc-500">IMDS probing (AWS/GCP/Azure/DO) · SSRF payloads · bucket audit · credential scanning &amp; validation</p>

        <div className="flex gap-1 border-b border-bg-border">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setTab(id)}
              className={clsx('flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-t transition-colors border-b-2 -mb-px',
                tab === id ? 'border-accent text-accent bg-accent/5' : 'border-transparent text-zinc-500 hover:text-zinc-300'
              )}>
              <Icon size={12} />{label}
            </button>
          ))}
        </div>

        <div className="pt-1">
          {tab === 'imds'   && <IMDSTab />}
          {tab === 'bucket' && <BucketTab />}
          {tab === 'creds'  && <CredScanTab />}
        </div>
      </div>
    </div>
  )
}

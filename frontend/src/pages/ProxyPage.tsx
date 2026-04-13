import React, { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Virtuoso } from 'react-virtuoso'
import { Play, Square, Trash2, Download, RefreshCw, Smartphone, X, Plus, Send, ChevronDown, Clipboard, Check, Apple, Radio } from 'lucide-react'
import { clsx } from 'clsx'
import { proxyApi } from '@/api/proxy'
import { iosApi } from '@/api/ios'
import { Badge } from '@/components/common/Badge'
import { SplitPane } from '@/components/common/SplitPane'
import { CodeBlock } from '@/components/common/CodeBlock'
import { useProxyStore } from '@/store/proxyStore'
import { useDeviceStore } from '@/store/deviceStore'
import { useProxyFlows } from '@/hooks/useProxyFlows'
import type { ProxyFlow, ProxyFlowDetail, RepeaterTab } from '@/types/proxy'
import type { IosDeviceInfo } from '@/types/adb'

let repeaterCounter = 1

function makeTab(overrides: Partial<RepeaterTab> = {}): RepeaterTab {
  return {
    id: crypto.randomUUID(),
    label: `Request ${repeaterCounter++}`,
    method: 'GET',
    url: '',
    headers: [{ key: 'Content-Type', value: 'application/json' }],
    body: '',
    response: null,
    loading: false,
    ...overrides,
  }
}

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']

export default function ProxyPage() {
  const { flows, selectedFlowId, selectFlow, sessionId, setSessionId, clearFlows, isRunning: running, setIsRunning: setRunning } = useProxyStore()
  const { activeSession, devices } = useDeviceStore()
  const [configuring, setConfiguring] = useState(false)
  const [configStatus, setConfigStatus] = useState<{ ok: boolean; msg: string } | null>(null)
  const [pageTab, setPageTab] = useState<'history' | 'repeater'>('history')
  const [repeaterTabs, setRepeaterTabs] = useState<RepeaterTab[]>([makeTab()])
  const [activeRepeaterId, setActiveRepeaterId] = useState<string>(repeaterTabs[0].id)
  const statusTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const [iosSetupOpen, setIosSetupOpen] = useState(false)

  const connectedSerial = devices.find((d) => d.state === 'device')?.serial ?? null
  const proxyPort = activeSession?.proxy_port ?? 8080
  const effectiveSessionId = sessionId ?? 0

  const { data: iosDevices = [] } = useQuery<IosDeviceInfo[]>({
    queryKey: ['ios-devices'],
    queryFn: iosApi.listDevices,
    refetchInterval: 5000,
  })

  const { data: localIpData } = useQuery({
    queryKey: ['local-ip'],
    queryFn: proxyApi.getLocalIp,
    staleTime: Infinity,
  })
  const localIp = localIpData?.local_ip ?? '…'
  const allIps = localIpData?.all_ips ?? []

  useProxyFlows(running ? effectiveSessionId : null)

  const { data: flowDetail } = useQuery({
    queryKey: ['flow', selectedFlowId],
    queryFn: () => proxyApi.getFlow(selectedFlowId!),
    enabled: !!selectedFlowId,
  })

  useEffect(() => {
    if (activeSession && !sessionId) setSessionId(activeSession.id)
  }, [activeSession, sessionId, setSessionId])

  const startProxy = async () => {
    try {
      await proxyApi.start(effectiveSessionId, proxyPort)
      setRunning(true)
    } catch (e: any) {
      showStatus(false, e?.response?.data?.detail ?? 'Failed to start proxy')
    }
  }

  const stopProxy = async () => {
    try { await proxyApi.stop(effectiveSessionId) } catch { /* ignore */ }
    setRunning(false)
  }

  const showStatus = (ok: boolean, msg: string) => {
    if (statusTimer.current) clearTimeout(statusTimer.current)
    setConfigStatus({ ok, msg })
    statusTimer.current = setTimeout(() => setConfigStatus(null), 5000)
  }

  const configureDevice = async () => {
    if (!connectedSerial) return
    if (!running) { showStatus(false, 'Start the proxy first so the CA cert is generated, then configure the device.'); return }
    setConfiguring(true)
    try {
      const result = await proxyApi.configureDevice(connectedSerial, '127.0.0.1', proxyPort)
      if (result.cert?.pushed) {
        showStatus(true, `Proxy set to 127.0.0.1:${proxyPort}. Cert pushed to ${result.cert.remote_path} — install via Settings → Security → Install certificate → CA certificate.`)
      } else {
        showStatus(true, `Proxy set to 127.0.0.1:${proxyPort}.`)
      }
    } catch (e: any) {
      showStatus(false, e?.response?.data?.detail ?? 'Failed to configure device proxy')
    } finally {
      setConfiguring(false)
    }
  }

  const unconfigureDevice = async () => {
    if (!connectedSerial) return
    try { await proxyApi.unconfigureDevice(connectedSerial); showStatus(true, 'Device proxy cleared') }
    catch { showStatus(false, 'Failed to clear device proxy') }
  }

  // Send the selected captured flow to a new Repeater tab
  const sendToRepeater = (flow: ProxyFlowDetail) => {
    const rawHeaders: Record<string, string> = JSON.parse(flow.request_headers || '{}')
    const headers = Object.entries(rawHeaders).map(([key, value]) => ({ key, value }))

    let body = ''
    if (flow.request_body) {
      try { body = typeof flow.request_body === 'string' ? flow.request_body : new TextDecoder().decode(flow.request_body as unknown as Uint8Array) }
      catch { body = String(flow.request_body) }
    }

    const tab = makeTab({
      label: `${flow.method} ${flow.path.slice(0, 24)}`,
      method: flow.method,
      url: flow.url,
      headers,
      body,
    })
    setRepeaterTabs((prev) => [...prev, tab])
    setActiveRepeaterId(tab.id)
    setPageTab('repeater')
  }

  // Mutate a single repeater tab
  const updateTab = (id: string, patch: Partial<RepeaterTab>) =>
    setRepeaterTabs((prev) => prev.map((t) => (t.id === id ? { ...t, ...patch } : t)))

  const addRepeaterTab = () => {
    const tab = makeTab()
    setRepeaterTabs((prev) => [...prev, tab])
    setActiveRepeaterId(tab.id)
  }

  const closeRepeaterTab = (id: string) => {
    setRepeaterTabs((prev) => {
      const next = prev.filter((t) => t.id !== id)
      if (next.length === 0) {
        const fresh = makeTab()
        setActiveRepeaterId(fresh.id)
        return [fresh]
      }
      if (activeRepeaterId === id) setActiveRepeaterId(next[next.length - 1].id)
      return next
    })
  }

  const sendRepeaterRequest = async (tab: RepeaterTab) => {
    if (!tab.url) return
    updateTab(tab.id, { loading: true, response: null })
    try {
      const headersObj = Object.fromEntries(
        tab.headers.filter((h) => h.key.trim()).map((h) => [h.key.trim(), h.value])
      )
      const response = await proxyApi.repeater(tab.method, tab.url, headersObj, tab.body)
      updateTab(tab.id, { loading: false, response })
    } catch (e: any) {
      updateTab(tab.id, {
        loading: false,
        response: {
          status_code: 0,
          headers: {},
          body: e?.response?.data?.detail ?? e?.message ?? 'Request failed',
          duration_ms: 0,
        },
      })
    }
  }

  const activeRepeaterTab = repeaterTabs.find((t) => t.id === activeRepeaterId) ?? repeaterTabs[0]

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-bg-border bg-bg-surface shrink-0 flex-wrap">
        <button
          onClick={running ? stopProxy : startProxy}
          className={clsx('flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors',
            running ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30' : 'bg-accent/20 text-accent hover:bg-accent/30')}
        >
          {running ? <><Square size={12} /> Stop</> : <><Play size={12} /> Start</>}
        </button>

        {running && (
          <span className="text-xs text-green-400 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            Capturing on port {proxyPort}
          </span>
        )}

        {connectedSerial && (
          <>
            <button onClick={configureDevice} disabled={configuring}
              title={running ? `Set proxy 127.0.0.1:${proxyPort} on device and push CA cert` : 'Start the proxy first'}
              className={clsx('flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-bg-elevated disabled:opacity-40 transition-colors',
                running ? 'text-zinc-400 hover:text-zinc-200' : 'text-zinc-600 cursor-not-allowed')}>
              <Smartphone size={12} />
              {configuring ? 'Configuring...' : 'Configure Device'}
            </button>
            <button onClick={unconfigureDevice}
              className="flex items-center gap-1 px-2 py-1 text-xs text-zinc-500 hover:text-zinc-300 rounded hover:bg-bg-elevated">
              <X size={12} /> Clear Proxy
            </button>
          </>
        )}

        {iosDevices.length > 0 && (
          <button
            onClick={() => setIosSetupOpen((v) => !v)}
            className={clsx(
              'flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-bg-elevated transition-colors',
              iosSetupOpen ? 'text-blue-400 bg-blue-500/10' : 'text-zinc-400 hover:text-zinc-200'
            )}
          >
            <Apple size={12} /> iOS Setup
          </button>
        )}

        <div className="flex-1" />

        {configStatus && (
          <span className={clsx('text-xs px-2 py-1 rounded', configStatus.ok ? 'text-green-400' : 'text-red-400')}>
            {configStatus.msg}
          </span>
        )}

        <span className="text-xs text-zinc-500">{flows.length} requests</span>

        <a href="/api/v1/proxy/cert" download="mitmproxy-ca-cert.pem"
          className="flex items-center gap-1 px-2 py-1 text-xs text-zinc-400 hover:text-zinc-200 rounded hover:bg-bg-elevated">
          <Download size={12} /> CA Cert
        </a>
        <button onClick={clearFlows} className="p-1.5 text-zinc-500 hover:text-zinc-200 rounded hover:bg-bg-elevated">
          <Trash2 size={14} />
        </button>
      </div>

      {/* iOS Setup guide */}
      {iosSetupOpen && (
        <IosSetupPanel
          iosDevices={iosDevices}
          localIp={localIp}
          allIps={allIps}
          proxyPort={proxyPort}
          proxyRunning={running}
          onClose={() => setIosSetupOpen(false)}
        />
      )}

      {/* Page tab bar */}
      <div className="flex border-b border-bg-border bg-bg-surface shrink-0">
        {(['history', 'repeater'] as const).map((t) => (
          <button key={t} onClick={() => setPageTab(t)}
            className={clsx('px-5 py-2 text-xs font-medium capitalize transition-colors',
              pageTab === t ? 'text-zinc-200 border-b-2 border-accent' : 'text-zinc-500 hover:text-zinc-300')}>
            {t}
          </button>
        ))}
      </div>

      {/* History tab */}
      {pageTab === 'history' && (
        <SplitPane
          direction="vertical"
          defaultSplit={45}
          className="flex-1"
          left={<FlowTable flows={flows} selectedId={selectedFlowId} onSelect={selectFlow} />}
          right={
            <FlowDetailPanel
              flow={flowDetail ?? null}
              onSendToRepeater={flowDetail ? () => sendToRepeater(flowDetail) : undefined}
            />
          }
        />
      )}

      {/* Repeater tab */}
      {pageTab === 'repeater' && (
        <div className="flex flex-col flex-1 overflow-hidden">
          {/* Repeater tab bar */}
          <div className="flex items-center gap-0 border-b border-bg-border bg-bg-surface shrink-0 overflow-x-auto">
            {repeaterTabs.map((tab) => (
              <div key={tab.id}
                className={clsx('group flex items-center gap-1.5 px-3 py-2 text-xs font-mono border-r border-bg-border cursor-pointer shrink-0 transition-colors',
                  activeRepeaterId === tab.id ? 'bg-bg-elevated text-zinc-200' : 'text-zinc-500 hover:text-zinc-300 hover:bg-bg-elevated/50')}
                onClick={() => setActiveRepeaterId(tab.id)}>
                <span className="max-w-[140px] truncate">{tab.label}</span>
                <button onClick={(e) => { e.stopPropagation(); closeRepeaterTab(tab.id) }}
                  className="opacity-0 group-hover:opacity-100 text-zinc-600 hover:text-zinc-300 transition-opacity">
                  <X size={10} />
                </button>
              </div>
            ))}
            <button onClick={addRepeaterTab}
              className="px-3 py-2 text-zinc-600 hover:text-zinc-300 shrink-0 transition-colors">
              <Plus size={13} />
            </button>
          </div>

          {/* Repeater content */}
          {activeRepeaterTab && (
            <RepeaterPanel
              tab={activeRepeaterTab}
              onChange={(patch) => updateTab(activeRepeaterTab.id, patch)}
              onSend={() => sendRepeaterRequest(activeRepeaterTab)}
            />
          )}
        </div>
      )}
    </div>
  )
}

// ─── iOS setup panel ─────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <button onClick={copy} className="ml-1.5 text-zinc-600 hover:text-zinc-300 transition-colors shrink-0" title="Copy">
      {copied ? <Check size={11} className="text-green-400" /> : <Clipboard size={11} />}
    </button>
  )
}

function IosSetupPanel({ iosDevices, localIp, allIps, proxyPort, proxyRunning, onClose }: {
  iosDevices: IosDeviceInfo[]
  localIp: string
  allIps: string[]
  proxyPort: number
  proxyRunning: boolean
  onClose: () => void
}) {
  const [certServerRunning, setCertServerRunning] = useState(false)
  const [certServerPort, setCertServerPort] = useState(8888)
  const [certServerError, setCertServerError] = useState<string | null>(null)
  const [selectedIp, setSelectedIp] = useState(localIp)

  // Sync selectedIp when localIp loads (async query)
  useEffect(() => {
    if (localIp && localIp !== '…') setSelectedIp(localIp)
  }, [localIp])

  const certLanUrl = certServerRunning ? `http://${selectedIp}:${certServerPort}/cert` : null
  const anyJailbroken = iosDevices.some((d) => d.jailbroken)

  const startCertServer = async () => {
    setCertServerError(null)
    try {
      const res = await proxyApi.startCertServer(certServerPort)
      setCertServerRunning(res.running)
    } catch (e: any) {
      // Show the specific backend message if present, otherwise the raw error
      const detail = e?.response?.data?.detail
      const status = e?.response?.status
      if (detail) {
        setCertServerError(`${detail}`)
      } else if (status) {
        setCertServerError(`Server returned ${status} — check the backend console`)
      } else {
        setCertServerError(e?.message ?? 'Request failed — is the backend running?')
      }
    }
  }

  const stopCertServer = async () => {
    await proxyApi.stopCertServer()
    setCertServerRunning(false)
  }

  // Dynamically import QRCode to avoid issues if pkg not yet available
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [QRCode, setQRCode] = useState<React.ComponentType<any> | null>(null)
  useEffect(() => {
    import('react-qr-code').then((m) => setQRCode(() => m.default)).catch(() => {})
  }, [])

  return (
    <div className="border-b border-bg-border bg-bg-surface shrink-0">
      <div className="px-4 py-3 space-y-3 max-w-4xl">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Apple size={13} className="text-blue-400" />
            <span className="text-xs font-semibold text-zinc-200">iOS Proxy Setup</span>
            {iosDevices.map((d) => (
              <span key={d.udid} className="text-xs text-zinc-500 font-mono">
                {d.name || d.model || d.udid.slice(0, 12) + '…'}
                {d.jailbroken && <span className="ml-1 text-yellow-400">⚡</span>}
              </span>
            ))}
          </div>
          <button onClick={onClose} className="text-zinc-600 hover:text-zinc-300 transition-colors">
            <X size={13} />
          </button>
        </div>

        <div className="grid grid-cols-3 gap-4">

          {/* Step 1: Cert server + QR */}
          <div className="space-y-2">
            <p className="text-xs font-medium text-zinc-300">
              <span className="text-blue-400 mr-1.5">1</span>Install CA Certificate
            </p>
            {!certServerRunning ? (
              <>
                {!proxyRunning && (
                  <div className="bg-yellow-500/10 border border-yellow-500/20 rounded px-2 py-1.5">
                    <p className="text-xs text-yellow-400">⚠ Start the proxy first — the CA cert is generated when mitmproxy starts.</p>
                  </div>
                )}
                <p className="text-xs text-zinc-500">
                  Start a LAN cert server so your iPhone can download the cert directly over Wi-Fi.
                </p>
                {allIps.length > 1 && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-zinc-600 shrink-0">Interface</span>
                    <select
                      className="flex-1 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-300 focus:outline-none focus:border-accent"
                      value={selectedIp}
                      onChange={(e) => setSelectedIp(e.target.value)}
                    >
                      {allIps.map((ip) => (
                        <option key={ip} value={ip}>{ip}</option>
                      ))}
                    </select>
                  </div>
                )}
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    className="w-20 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-300 focus:outline-none focus:border-accent"
                    value={certServerPort}
                    onChange={(e) => setCertServerPort(Number(e.target.value))}
                  />
                  <button
                    onClick={startCertServer}
                    disabled={!proxyRunning}
                    className="flex items-center gap-1 px-2 py-1 text-xs bg-blue-500/20 text-blue-400 hover:bg-blue-500/30 rounded transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <Radio size={11} /> Start Cert Server
                  </button>
                </div>
                {certServerError && <p className="text-xs text-red-400">{certServerError}</p>}
              </>
            ) : (
              <>
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse shrink-0" />
                  <span className="text-xs text-green-400">Cert server running</span>
                  <button onClick={stopCertServer} className="ml-auto text-zinc-600 hover:text-red-400 transition-colors">
                    <X size={11} />
                  </button>
                </div>
                {/* QR code */}
                {certLanUrl && (
                  <div className="flex flex-col items-center gap-2">
                    {QRCode ? (
                      <div className="p-2 bg-white rounded">
                        <QRCode value={certLanUrl} size={120} bgColor="#ffffff" fgColor="#000000" />
                      </div>
                    ) : (
                      <div className="w-[136px] h-[136px] bg-bg-elevated rounded flex items-center justify-center text-zinc-600 text-xs">QR unavailable</div>
                    )}
                    <p className="text-xs text-zinc-500 text-center">Scan with iPhone camera</p>
                    <div className="flex items-center gap-1 bg-bg-elevated border border-bg-border rounded px-2 py-1 w-full">
                      <span className="text-xs font-mono text-zinc-300 flex-1 truncate">{certLanUrl}</span>
                      <CopyButton text={certLanUrl} />
                    </div>
                  </div>
                )}
                <ol className="text-xs text-zinc-500 space-y-0.5 list-decimal list-inside">
                  <li>Scan QR or open URL in Safari</li>
                  <li>Settings → General → VPN &amp; Device Management → install</li>
                  <li>Settings → General → About → Certificate Trust Settings → enable full trust</li>
                </ol>
              </>
            )}
          </div>

          {/* Step 2: Wi-Fi proxy */}
          <div className="space-y-2">
            <p className="text-xs font-medium text-zinc-300">
              <span className="text-blue-400 mr-1.5">2</span>Configure Wi-Fi Proxy
            </p>
            <p className="text-xs text-zinc-500">
              Settings → Wi-Fi → [your network] → Configure Proxy → <strong className="text-zinc-400">Manual</strong>
            </p>
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-xs text-zinc-600 w-12 shrink-0">Server</span>
                <div className="flex items-center gap-1 bg-bg-elevated border border-bg-border rounded px-2 py-1 flex-1">
                  <span className="text-xs font-mono text-zinc-300">{selectedIp}</span>
                  <CopyButton text={selectedIp} />
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-zinc-600 w-12 shrink-0">Port</span>
                <div className="flex items-center gap-1 bg-bg-elevated border border-bg-border rounded px-2 py-1 flex-1">
                  <span className="text-xs font-mono text-zinc-300">{proxyPort}</span>
                  <CopyButton text={String(proxyPort)} />
                </div>
              </div>
            </div>
          </div>

          {/* Step 3: Frida */}
          <div className="space-y-2">
            <p className="text-xs font-medium text-zinc-300">
              <span className="text-blue-400 mr-1.5">3</span>Attach Frida
            </p>
            <p className="text-xs text-zinc-500">
              Go to the <strong className="text-zinc-400">Frida page</strong>, select this iPhone, attach to your target app, then load:
            </p>
            <div className="bg-bg-elevated border border-bg-border rounded px-2 py-1.5">
              <span className="text-xs font-mono text-yellow-400">iOS SSL Pinning Bypass</span>
            </div>
            <p className="text-xs text-zinc-500">
              This hooks <code className="text-zinc-400">SecTrustEvaluate</code> so the app accepts the mitmproxy cert.
            </p>
            {anyJailbroken && (
              <p className="text-xs text-yellow-500/80">
                ⚡ Jailbroken device detected — Frida should attach without issues.
              </p>
            )}
          </div>

        </div>
      </div>
    </div>
  )
}

// ─── Flow table ───────────────────────────────────────────────────────────────

function FlowTable({ flows, selectedId, onSelect }: {
  flows: ProxyFlow[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex text-xs text-zinc-600 px-3 py-1.5 border-b border-bg-border bg-bg-surface font-mono">
        <span className="w-6 mr-2">#</span>
        <span className="w-16">Method</span>
        <span className="w-32">Host</span>
        <span className="flex-1">Path</span>
        <span className="w-12 text-right">Status</span>
        <span className="w-20 text-right">Duration</span>
      </div>
      <div className="flex-1">
        {flows.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-zinc-600 text-sm">No traffic captured yet</div>
        ) : (
          <Virtuoso
            style={{ height: '100%' }}
            data={flows}
            itemContent={(index, flow: ProxyFlow) => (
              <div
                className={clsx(
                  'flex items-center px-3 py-1 text-xs font-mono cursor-pointer hover:bg-bg-elevated',
                  selectedId === flow.id ? 'bg-accent/10 border-l-2 border-accent' : 'border-l-2 border-transparent'
                )}
                onClick={() => onSelect(flow.id)}
              >
                <span className="w-6 mr-2 text-zinc-600">{flows.length - index}</span>
                <span className="w-16"><Badge variant="method" value={flow.method} /></span>
                <span className="w-32 text-zinc-400 truncate">{flow.host}</span>
                <span className="flex-1 text-zinc-300 truncate">{flow.path}</span>
                <span className="w-12 text-right">
                  {flow.response_status && <Badge variant="status" value={String(flow.response_status)} />}
                </span>
                <span className="w-20 text-right text-zinc-600">
                  {flow.duration_ms ? `${flow.duration_ms.toFixed(0)}ms` : ''}
                </span>
              </div>
            )}
          />
        )}
      </div>
    </div>
  )
}

// ─── Flow detail panel ────────────────────────────────────────────────────────

function FlowDetailPanel({ flow, onSendToRepeater }: {
  flow: ProxyFlowDetail | null
  onSendToRepeater?: () => void
}) {
  const [view, setView] = useState<'request' | 'response'>('request')

  if (!flow) return <div className="flex items-center justify-center h-full text-zinc-600 text-sm">Select a request</div>

  const headers = view === 'request'
    ? JSON.parse(flow.request_headers || '{}')
    : JSON.parse(flow.response_headers || '{}')

  const body = view === 'request' ? flow.request_body : flow.response_body
  const isJson = (flow.content_type || '').includes('json')

  let bodyDisplay = ''
  if (body) {
    try {
      bodyDisplay = typeof body === 'string' ? body : new TextDecoder().decode(body as unknown as Uint8Array)
      if (isJson) bodyDisplay = JSON.stringify(JSON.parse(bodyDisplay), null, 2)
    } catch { bodyDisplay = String(body) }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-bg-border bg-bg-surface shrink-0">
        <span className="text-xs font-mono text-zinc-400 flex-1 truncate">{flow.url}</span>
        {onSendToRepeater && (
          <button onClick={onSendToRepeater}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-accent/20 text-accent hover:bg-accent/30 rounded transition-colors"
            title="Open in Repeater to edit and resend">
            <Send size={11} /> Send to Repeater
          </button>
        )}
        <button onClick={() => setView('request')}
          className={clsx('text-xs px-2 py-1 rounded', view === 'request' ? 'bg-accent text-white' : 'text-zinc-500 hover:text-zinc-200')}>
          Request
        </button>
        <button onClick={() => setView('response')}
          className={clsx('text-xs px-2 py-1 rounded', view === 'response' ? 'bg-accent text-white' : 'text-zinc-500 hover:text-zinc-200')}>
          Response
        </button>
      </div>
      <div className="flex-1 overflow-auto">
        <SplitPane direction="horizontal" defaultSplit={40} className="h-full"
          left={
            <div className="p-3 space-y-1">
              <p className="text-xs text-zinc-600 mb-2 uppercase tracking-wide">Headers</p>
              {Object.entries(headers).map(([k, v]) => (
                <div key={k} className="flex gap-2 text-xs font-mono">
                  <span className="text-zinc-500 shrink-0">{k}:</span>
                  <span className="text-zinc-300 break-all">{String(v)}</span>
                </div>
              ))}
            </div>
          }
          right={
            <div className="h-full">
              {bodyDisplay ? (
                <CodeBlock code={bodyDisplay} language={isJson ? 'json' : 'markup'} className="h-full rounded-none" />
              ) : (
                <div className="p-4 text-zinc-600 text-xs">No body</div>
              )}
            </div>
          }
        />
      </div>
    </div>
  )
}

// ─── Repeater panel ───────────────────────────────────────────────────────────

function RepeaterPanel({ tab, onChange, onSend }: {
  tab: RepeaterTab
  onChange: (patch: Partial<RepeaterTab>) => void
  onSend: () => void
}) {
  const addHeader = () => onChange({ headers: [...tab.headers, { key: '', value: '' }] })
  const removeHeader = (i: number) => onChange({ headers: tab.headers.filter((_, idx) => idx !== i) })
  const updateHeader = (i: number, field: 'key' | 'value', val: string) => {
    const next = tab.headers.map((h, idx) => idx === i ? { ...h, [field]: val } : h)
    onChange({ headers: next })
  }

  const resp = tab.response
  const respIsJson = resp ? (resp.headers['content-type'] ?? '').includes('json') : false
  let respBody = resp?.body ?? ''
  if (respIsJson) {
    try { respBody = JSON.stringify(JSON.parse(respBody), null, 2) } catch { /* leave as-is */ }
  }

  const statusColor = !resp ? '' :
    resp.status_code === 0 ? 'text-red-400' :
    resp.status_code >= 500 ? 'text-red-400' :
    resp.status_code >= 400 ? 'text-orange-400' :
    resp.status_code >= 300 ? 'text-yellow-400' : 'text-green-400'

  const requestEditor = (
    <div className="flex flex-col h-full overflow-hidden">
      {/* URL bar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-bg-border bg-bg-surface shrink-0">
        <div className="relative">
          <select
            value={tab.method}
            onChange={(e) => onChange({ method: e.target.value })}
            className="appearance-none bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs font-mono text-zinc-200 pr-6 focus:outline-none focus:border-accent"
          >
            {METHODS.map((m) => <option key={m}>{m}</option>)}
          </select>
          <ChevronDown size={10} className="absolute right-1.5 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
        </div>
        <input
          className="flex-1 bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
          placeholder="https://api.example.com/endpoint"
          value={tab.url}
          onChange={(e) => onChange({ url: e.target.value })}
          onKeyDown={(e) => e.key === 'Enter' && onSend()}
        />
        <button
          onClick={onSend}
          disabled={tab.loading || !tab.url}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-accent/20 text-accent hover:bg-accent/30 disabled:opacity-40 transition-colors"
        >
          <Send size={12} />
          {tab.loading ? 'Sending…' : 'Send'}
        </button>
      </div>

      {/* Headers + body */}
      <SplitPane
        direction="horizontal"
        defaultSplit={40}
        className="flex-1"
        left={
          <div className="flex flex-col h-full overflow-hidden">
            <div className="flex items-center justify-between px-3 py-1.5 border-b border-bg-border shrink-0">
              <span className="text-xs text-zinc-600 uppercase tracking-wide">Headers</span>
              <button onClick={addHeader} className="text-zinc-600 hover:text-zinc-300 transition-colors">
                <Plus size={12} />
              </button>
            </div>
            <div className="flex-1 overflow-auto p-2 space-y-1">
              {tab.headers.map((h, i) => (
                <div key={i} className="flex items-center gap-1">
                  <input
                    className="w-36 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-300 placeholder-zinc-600 focus:outline-none focus:border-accent"
                    placeholder="Header-Name"
                    value={h.key}
                    onChange={(e) => updateHeader(i, 'key', e.target.value)}
                  />
                  <span className="text-zinc-600 text-xs">:</span>
                  <input
                    className="flex-1 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-300 placeholder-zinc-600 focus:outline-none focus:border-accent"
                    placeholder="value"
                    value={h.value}
                    onChange={(e) => updateHeader(i, 'value', e.target.value)}
                  />
                  <button onClick={() => removeHeader(i)} className="text-zinc-700 hover:text-red-400 transition-colors shrink-0">
                    <X size={11} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        }
        right={
          <div className="flex flex-col h-full overflow-hidden">
            <div className="px-3 py-1.5 border-b border-bg-border shrink-0">
              <span className="text-xs text-zinc-600 uppercase tracking-wide">Body</span>
            </div>
            <textarea
              className="flex-1 bg-transparent px-3 py-2 text-xs font-mono text-zinc-300 placeholder-zinc-600 resize-none focus:outline-none"
              placeholder="Request body…"
              value={tab.body}
              onChange={(e) => onChange({ body: e.target.value })}
              spellCheck={false}
            />
          </div>
        }
      />
    </div>
  )

  const responsePanel = (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center gap-3 px-3 py-1.5 border-b border-bg-border bg-bg-surface shrink-0">
        <span className="text-xs text-zinc-600 uppercase tracking-wide">Response</span>
        {resp && resp.status_code !== 0 && (
          <>
            <span className={clsx('text-xs font-mono font-semibold', statusColor)}>{resp.status_code}</span>
            <span className="text-xs text-zinc-600">{resp.duration_ms.toFixed(0)}ms</span>
          </>
        )}
      </div>

      {!resp && !tab.loading && (
        <div className="flex items-center justify-center flex-1 text-zinc-600 text-sm">
          Send a request to see the response
        </div>
      )}

      {tab.loading && (
        <div className="flex items-center justify-center flex-1 text-zinc-500 text-sm gap-2">
          <RefreshCw size={14} className="animate-spin" /> Sending…
        </div>
      )}

      {resp && !tab.loading && (
        <SplitPane
          direction="horizontal"
          defaultSplit={40}
          className="flex-1"
          left={
            <div className="p-3 overflow-auto space-y-1">
              <p className="text-xs text-zinc-600 mb-2 uppercase tracking-wide">Headers</p>
              {Object.entries(resp.headers).map(([k, v]) => (
                <div key={k} className="flex gap-2 text-xs font-mono">
                  <span className="text-zinc-500 shrink-0">{k}:</span>
                  <span className="text-zinc-300 break-all">{v}</span>
                </div>
              ))}
            </div>
          }
          right={
            <div className="h-full">
              {respBody ? (
                <CodeBlock code={respBody} language={respIsJson ? 'json' : 'markup'} className="h-full rounded-none" />
              ) : (
                <div className="p-4 text-zinc-600 text-xs">No body</div>
              )}
            </div>
          }
        />
      )}
    </div>
  )

  return (
    <SplitPane
      direction="vertical"
      defaultSplit={50}
      className="flex-1"
      left={requestEditor}
      right={responsePanel}
    />
  )
}

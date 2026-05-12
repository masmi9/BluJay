import React, { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Virtuoso } from 'react-virtuoso'
import { Play, Square, Trash2, Download, Smartphone, X, Send, Clipboard, Check, Apple, Radio, Filter, ShieldAlert } from 'lucide-react'
import { clsx } from 'clsx'
import { proxyApi } from '@/api/proxy'
import { addScannerUrl } from '@/pages/ScannerPage'
import { iosApi } from '@/api/ios'
import { Badge } from '@/components/common/Badge'
import { SplitPane } from '@/components/common/SplitPane'
import { CodeBlock } from '@/components/common/CodeBlock'
import { useProxyStore } from '@/store/proxyStore'
import { useDeviceStore } from '@/store/deviceStore'
import { useProxyFlows } from '@/hooks/useProxyFlows'
import type { ProxyFlow, ProxyFlowDetail } from '@/types/proxy'
import type { IosDeviceInfo } from '@/types/adb'

export default function ProxyPage() {
  const { flows, selectedFlowId, selectFlow, sessionId, setSessionId, clearFlows, isRunning: running, setIsRunning: setRunning } = useProxyStore()
  const { activeSession, devices } = useDeviceStore()
  const navigate = useNavigate()
  const [configuring, setConfiguring] = useState(false)
  const [configStatus, setConfigStatus] = useState<{ ok: boolean; msg: string } | null>(null)
  const statusTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const [iosSetupOpen, setIosSetupOpen] = useState(false)
  const [selectedAndroidIp, setSelectedAndroidIp] = useState<string | null>(null)

  const connectedSerial = devices.find((d) => d.state === 'device')?.serial ?? null
  const [customPort, setCustomPort] = useState(8080)
  const proxyPort = activeSession?.proxy_port ?? customPort

  const { data: settingsData } = useQuery({
    queryKey: ['settings'],
    queryFn: () => import('axios').then((ax) => ax.default.get('/api/v1/settings').then((r) => r.data)),
    staleTime: 60_000,
  })

  useEffect(() => {
    if (settingsData?.proxy_port) setCustomPort(settingsData.proxy_port)
  }, [settingsData?.proxy_port])
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
  const localIp = localIpData?.local_ip ?? 'â€¦'
  const allIps = localIpData?.all_ips ?? []

  const androidIp = selectedAndroidIp ?? localIp

  const [blockedHosts, setBlockedHosts] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem('proxy-blocked-hosts') || '[]') } catch { return [] }
  })
  const [filterOpen, setFilterOpen] = useState(false)
  const [filterInput, setFilterInput] = useState('')

  const addBlockedHost = (host: string) => {
    const h = host.trim()
    if (!h || blockedHosts.includes(h)) return
    const next = [...blockedHosts, h]
    setBlockedHosts(next)
    localStorage.setItem('proxy-blocked-hosts', JSON.stringify(next))
    setFilterInput('')
  }

  const removeBlockedHost = (host: string) => {
    const next = blockedHosts.filter((h) => h !== host)
    setBlockedHosts(next)
    localStorage.setItem('proxy-blocked-hosts', JSON.stringify(next))
  }

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
      const result = await proxyApi.configureDevice(connectedSerial, androidIp, proxyPort)
      if (result.cert?.pushed) {
        showStatus(true, `Proxy set to ${androidIp}:${proxyPort}. Cert pushed to ${result.cert.remote_path} â€” install via Settings â†’ Security â†’ Install certificate â†’ CA certificate.`)
      } else {
        showStatus(true, `Proxy set to ${androidIp}:${proxyPort}.`)
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

  // Send the selected captured flow to the standalone Repeater page
  const sendToRepeater = (flow: ProxyFlowDetail) => {
    const headers: Record<string, string> = (() => { try { return JSON.parse(flow.request_headers || '{}') } catch { return {} } })()

    let body: string | null = null
    if (flow.request_body) {
      try { body = typeof flow.request_body === 'string' ? flow.request_body : new TextDecoder().decode(flow.request_body as unknown as Uint8Array) }
      catch { body = String(flow.request_body) }
    }

    sessionStorage.setItem('repeater-preload', JSON.stringify({ method: flow.method, url: flow.url, headers, body }))
    navigate('/repeater')
  }

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

        {!running && (
          <input
            type="number"
            min={1024} max={65535}
            value={customPort}
            onChange={(e) => setCustomPort(Number(e.target.value))}
            className="w-20 bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-300 focus:outline-none focus:border-accent"
            title="Proxy port"
          />
        )}

        {running && (
          <span className="text-xs text-green-400 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            Capturing on port {proxyPort}
          </span>
        )}

        {connectedSerial && (
          <>
            {allIps.length > 1 && (
              <select
                value={selectedAndroidIp ?? localIp}
                onChange={(e) => setSelectedAndroidIp(e.target.value)}
                className="bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs font-mono text-zinc-300 focus:outline-none focus:border-accent"
                title="Select the network interface your Android device can reach"
              >
                {allIps.map((ip) => (
                  <option key={ip} value={ip}>{ip}</option>
                ))}
              </select>
            )}
            <button onClick={configureDevice} disabled={configuring}
              title={running ? `Set proxy ${androidIp}:${proxyPort} on device and push CA cert` : 'Start the proxy first'}
              className={clsx('flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-bg-elevated disabled:opacity-40 transition-colors',
                running ? 'text-zinc-400 hover:text-zinc-200' : 'text-zinc-600 cursor-not-allowed')}>
              <Smartphone size={12} />
              {configuring ? 'Configuring...' : 'Configure Device'}
            </button>
            <button onClick={unconfigureDevice}
              className="flex items-center gap-1 px-2 py-1 text-xs text-zinc-500 hover:text-zinc-300 rounded hover:bg-bg-elevated">
              <Smartphone size={12} /> Remove Device
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

        <button
          onClick={() => setFilterOpen((v) => !v)}
          className={clsx('flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors',
            filterOpen || blockedHosts.length > 0
              ? 'text-amber-400 bg-amber-500/10 hover:bg-amber-500/20'
              : 'text-zinc-500 hover:text-zinc-200 hover:bg-bg-elevated')}
          title="Filter hosts"
        >
          <Filter size={12} />
          {blockedHosts.length > 0 && <span>{blockedHosts.length}</span>}
        </button>

        <span className="text-xs text-zinc-500">{flows.length} requests</span>

        <a href="/api/v1/proxy/cert" download="mitmproxy-ca-cert.pem"
          className="flex items-center gap-1 px-2 py-1 text-xs text-zinc-400 hover:text-zinc-200 rounded hover:bg-bg-elevated">
          <Download size={12} /> CA Cert
        </a>
        <button
          onClick={async () => {
            try { await proxyApi.clearFlows(effectiveSessionId) } catch { /* ignore */ }
            clearFlows()
          }}
          title="Clear all captured traffic"
          aria-label="Clear all captured traffic"
          className="p-1.5 text-zinc-500 hover:text-zinc-200 rounded hover:bg-bg-elevated"
        >
          <Trash2 size={14} />
        </button>
      </div>

      {/* Host filter panel */}
      {filterOpen && (
        <div className="border-b border-bg-border bg-bg-surface px-4 py-2 shrink-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-zinc-500 shrink-0">Hidden hosts:</span>
            {blockedHosts.map((h) => (
              <span key={h} className="flex items-center gap-1 px-2 py-0.5 bg-amber-500/10 border border-amber-500/20 rounded text-xs font-mono text-amber-300">
                {h}
                <button onClick={() => removeBlockedHost(h)} title={`Remove ${h}`} aria-label={`Remove ${h}`} className="text-amber-500 hover:text-amber-200 transition-colors">
                  <X size={10} />
                </button>
              </span>
            ))}
            <form onSubmit={(e) => { e.preventDefault(); addBlockedHost(filterInput) }} className="flex items-center gap-1">
              <input
                className="bg-bg-elevated border border-bg-border rounded px-2 py-0.5 text-xs font-mono text-zinc-300 placeholder-zinc-600 focus:outline-none focus:border-amber-500/50 w-48"
                placeholder="fonts.gstatic.com"
                value={filterInput}
                onChange={(e) => setFilterInput(e.target.value)}
              />
              <button type="submit" className="px-2 py-0.5 text-xs bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 rounded transition-colors">
                Hide
              </button>
            </form>
          </div>
        </div>
      )}

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

      <SplitPane
        direction="vertical"
        defaultSplit={45}
        className="flex-1"
        left={<FlowTable
          flows={blockedHosts.length > 0 ? flows.filter((f) => !blockedHosts.some((b) => f.host?.includes(b))) : flows}
          selectedId={selectedFlowId}
          onSelect={selectFlow}
        />}
        right={
          <FlowDetailPanel
            flow={flowDetail ?? null}
            onSendToRepeater={flowDetail ? () => sendToRepeater(flowDetail) : undefined}
          />
        }
      />
    </div>
  )
}

// â”€â”€â”€ iOS setup panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
    if (localIp && localIp !== 'â€¦') setSelectedIp(localIp)
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
        setCertServerError(`Server returned ${status} â€” check the backend console`)
      } else {
        setCertServerError(e?.message ?? 'Request failed â€” is the backend running?')
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
                {d.name || d.model || d.udid.slice(0, 12) + 'â€¦'}
                {d.jailbroken && <span className="ml-1 text-yellow-400">âš¡</span>}
              </span>
            ))}
          </div>
          <button onClick={onClose} title="Close iOS setup" aria-label="Close iOS setup" className="text-zinc-600 hover:text-zinc-300 transition-colors">
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
                    <p className="text-xs text-yellow-400">âš  Start the proxy first â€” the CA cert is generated when mitmproxy starts.</p>
                  </div>
                )}
                <p className="text-xs text-zinc-500">
                  Start a LAN cert server so your iPhone can download the cert directly over Wi-Fi.
                </p>
                {allIps.length > 1 && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-zinc-600 shrink-0">Interface</span>
                    <select
                      aria-label="Network interface"
                      title="Network interface"
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
                    title="Cert server port"
                    aria-label="Cert server port"
                    placeholder="8888"
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
                  <button onClick={stopCertServer} title="Stop cert server" aria-label="Stop cert server" className="ml-auto text-zinc-600 hover:text-red-400 transition-colors">
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
                  <li>Settings â†’ General â†’ VPN &amp; Device Management â†’ install</li>
                  <li>Settings â†’ General â†’ About â†’ Certificate Trust Settings â†’ enable full trust</li>
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
              Settings â†’ Wi-Fi â†’ [your network] â†’ Configure Proxy â†’ <strong className="text-zinc-400">Manual</strong>
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
                âš¡ Jailbroken device detected â€” Frida should attach without issues.
              </p>
            )}
          </div>

        </div>
      </div>
    </div>
  )
}

// â”€â”€â”€ Flow table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

type DisplayFlow = ProxyFlow & { _count: number }

function deduplicateFlows(flows: ProxyFlow[]): DisplayFlow[] {
  const result: DisplayFlow[] = []
  for (const flow of flows) {
    const last = result[result.length - 1]
    if (
      last &&
      last.method === flow.method &&
      last.host === flow.host &&
      last.path === flow.path &&
      last.url === flow.url &&
      last.request_headers === flow.request_headers
    ) {
      last._count++
    } else {
      result.push({ ...flow, _count: 1 })
    }
  }
  return result
}

function FlowTable({ flows, selectedId, onSelect }: {
  flows: ProxyFlow[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  const displayFlows = deduplicateFlows(flows)

  return (
    <div className="flex flex-col h-full">
      <div className="flex text-xs text-zinc-600 px-3 py-1.5 border-b border-bg-border bg-bg-surface font-mono">
        <span className="w-6 mr-2">#</span>
        <span className="w-20">Method</span>
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
            data={displayFlows}
            itemContent={(index, flow: DisplayFlow) => (
              <div
                className={clsx(
                  'flex items-center px-3 py-1 text-xs font-mono cursor-pointer hover:bg-bg-elevated',
                  selectedId === flow.id ? 'bg-accent/10 border-l-2 border-accent' : 'border-l-2 border-transparent'
                )}
                onClick={() => onSelect(flow.id)}
              >
                <span className="w-6 mr-2 text-zinc-600">{displayFlows.length - index}</span>
                <span className="w-20 flex items-center gap-1.5">
                  <Badge variant="method" value={flow.method} />
                  {flow._count > 1 && (
                    <span className="text-[10px] text-zinc-500 font-mono">Ã—{flow._count}</span>
                  )}
                </span>
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

// â”€â”€â”€ Flow detail panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function parseBody(raw: string | null | undefined, headers: Record<string, string>, fallbackContentType?: string) {
  if (!raw) return { display: '', isJson: false }
  let display = typeof raw === 'string' ? raw : String(raw)
  const ct = Object.entries(headers).find(([k]) => k.toLowerCase() === 'content-type')?.[1]
    ?? fallbackContentType ?? ''
  try {
    if (ct.includes('json') || display.trimStart().startsWith('{') || display.trimStart().startsWith('[')) {
      display = JSON.stringify(JSON.parse(display), null, 2)
      return { display, isJson: true }
    }
  } catch { /* leave as-is */ }
  return { display, isJson: false }
}

function FlowPane({ title, headers, body, isJson, statusLine }: {
  title: string
  headers: Record<string, string>
  body: string
  isJson: boolean
  statusLine?: string
}) {
  return (
    <div className="flex flex-col h-full min-w-0">
      <div className="px-3 py-1.5 border-b border-bg-border bg-bg-surface shrink-0 flex items-center gap-2">
        <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">{title}</span>
        {statusLine && <span className="text-xs font-mono text-zinc-500 ml-auto">{statusLine}</span>}
      </div>
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Headers */}
        <div className="overflow-y-auto border-b border-bg-border p-3 space-y-0.5" style={{ maxHeight: '40%' }}>
          {Object.entries(headers).map(([k, v]) => (
            <div key={k} className="flex gap-2 text-xs font-mono leading-relaxed">
              <span className="text-zinc-500 shrink-0">{k}:</span>
              <span className="text-zinc-300 break-all">{String(v)}</span>
            </div>
          ))}
        </div>
        {/* Body */}
        <div className="flex-1 overflow-hidden">
          {body ? (
            <CodeBlock code={body} language={isJson ? 'json' : 'markup'} className="h-full rounded-none" />
          ) : (
            <div className="p-4 text-zinc-600 text-xs">No body</div>
          )}
        </div>
      </div>
    </div>
  )
}

function FlowDetailPanel({ flow, onSendToRepeater }: {
  flow: ProxyFlowDetail | null
  onSendToRepeater?: () => void
}) {
  if (!flow) return <div className="flex items-center justify-center h-full text-zinc-600 text-sm">Select a request</div>

  const reqHeaders: Record<string, string> = (() => { try { return JSON.parse(flow.request_headers || '{}') } catch { return {} } })()
  const respHeaders: Record<string, string> = (() => { try { return JSON.parse(flow.response_headers || '{}') } catch { return {} } })()

  const req = parseBody(flow.request_body, reqHeaders)
  const resp = parseBody(flow.response_body, respHeaders, flow.content_type ?? undefined)

  return (
    <div className="flex flex-col h-full">
      {/* URL bar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-bg-border bg-bg-surface shrink-0">
        <span className="text-xs font-mono text-zinc-400 flex-1 truncate">{flow.url}</span>
        <button
          onClick={() => addScannerUrl(flow.url)}
          className="flex items-center gap-1 px-2 py-1 text-xs bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 rounded transition-colors"
          title="Add this URL to the Scanner target list">
          <ShieldAlert size={11} /> Send to Scanner
        </button>
        {onSendToRepeater && (
          <button onClick={onSendToRepeater}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-accent/20 text-accent hover:bg-accent/30 rounded transition-colors"
            title="Open in Repeater to edit and resend">
            <Send size={11} /> Send to Repeater
          </button>
        )}
      </div>
      {/* Side-by-side request / response */}
      <div className="flex flex-1 overflow-hidden divide-x divide-bg-border">
        <div className="flex-1 overflow-hidden">
          <FlowPane
            title="Request"
            headers={reqHeaders}
            body={req.display}
            isJson={req.isJson}
            statusLine={`${flow.method}`}
          />
        </div>
        <div className="flex-1 overflow-hidden">
          <FlowPane
            title="Response"
            headers={respHeaders}
            body={resp.display}
            isJson={resp.isJson}
            statusLine={flow.response_status ? `${flow.response_status}${flow.duration_ms ? ` Â· ${flow.duration_ms.toFixed(0)}ms` : ''}` : undefined}
          />
        </div>
      </div>
    </div>
  )
}


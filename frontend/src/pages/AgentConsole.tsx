import { useState, useEffect, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Terminal, Play, Trash2, ChevronDown, ChevronRight, Loader2,
  AlertCircle, CheckCircle2, XCircle, RefreshCw, Zap, Download,
  Hammer, ChevronUp, Power
} from 'lucide-react'
import { clsx } from 'clsx'
import { agentApi } from '@/api/agent'
import { useDeviceStore } from '@/store/deviceStore'
import { AGENT_COMMANDS } from '@/types/agent'
import type { AgentCommandResult } from '@/types/agent'

export default function AgentConsole() {
  const navigate = useNavigate()
  const { devices } = useDeviceStore()
  const connected = devices.filter((d) => d.state === 'device')
  const [serial, setSerial] = useState(connected[0]?.serial ?? '')
  const [command, setCommand] = useState<string>(AGENT_COMMANDS[0].value)
  const [args, setArgs] = useState<Record<string, string>>({})
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const qc = useQueryClient()

  // Setup state
  const [apkPath, setApkPath] = useState('')
  const [installing, setInstalling] = useState(false)
  const [setupMsg, setSetupMsg] = useState<string | null>(null)
  const [setupOk, setSetupOk] = useState<boolean | null>(null)
  const [startingSvc, setStartingSvc] = useState(false)

  // Build state
  const [building, setBuilding] = useState(false)
  const [buildLogOpen, setBuildLogOpen] = useState(false)
  const [buildLog, setBuildLog] = useState<string[]>([])
  const [buildLineIdx, setBuildLineIdx] = useState(0)
  const [buildStatus, setBuildStatus] = useState<'idle' | 'building' | 'success' | 'failed'>('idle')
  const [buildError, setBuildError] = useState<string | null>(null)
  const buildPollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const logEndRef = useRef<HTMLDivElement>(null)

  const selectedCmd = AGENT_COMMANDS.find((c) => c.value === command)!

  const { data: history = [], isLoading } = useQuery({
    queryKey: ['agent-history', serial],
    queryFn: () => agentApi.history(serial),
    enabled: !!serial,
    refetchInterval: 5000,
  })

  const { data: status, refetch: refetchStatus } = useQuery({
    queryKey: ['agent-status', serial],
    queryFn: () => agentApi.status(serial),
    enabled: !!serial,
    refetchInterval: 30000,  // Poll every 30s — ping now sends a real command, avoid collisions
    retry: false,
  })

  // Reset setup feedback when device changes
  useEffect(() => {
    setSetupMsg(null)
    setSetupOk(null)
  }, [serial])

  // Poll build status while building
  useEffect(() => {
    if (!building) return
    let idx = buildLineIdx
    buildPollRef.current = setInterval(async () => {
      try {
        const data = await agentApi.buildStatus(idx)
        if (data.new_lines.length > 0) {
          setBuildLog((prev) => [...prev, ...data.new_lines])
          idx += data.new_lines.length
          setBuildLineIdx(idx)
          // Auto-scroll
          setTimeout(() => logEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50)
        }
        if (data.status === 'success' || data.status === 'failed') {
          setBuildStatus(data.status)
          setBuildError(data.error)
          setBuilding(false)
          clearInterval(buildPollRef.current!)
          refetchStatus()
        }
      } catch { /* ignore poll errors */ }
    }, 1500)
    return () => clearInterval(buildPollRef.current!)
  }, [building])

  const handleBuild = async () => {
    setBuildLog([])
    setBuildLineIdx(0)
    setBuildStatus('building')
    setBuildError(null)
    setBuildLogOpen(true)
    try {
      await agentApi.buildApk()
      setBuilding(true)
    } catch (e: any) {
      const msg = e?.response?.data?.detail ?? e?.message ?? 'Build failed to start'
      setBuildLog([msg])
      setBuildStatus('failed')
      setBuildError(msg)
    }
  }

  const handleStartService = async () => {
    if (!serial) return
    setStartingSvc(true)
    setSetupMsg(null)
    setSetupOk(null)
    try {
      const result = await agentApi.startService(serial)
      setSetupOk(result.reachable)
      setSetupMsg(result.reachable
        ? 'Service started — agent reachable'
        : 'Service start attempted — not yet reachable. Try opening the app on device.'
      )
      refetchStatus()
    } catch (e: any) {
      setSetupOk(false)
      setSetupMsg(e?.response?.data?.detail ?? e?.message ?? 'Start service failed')
    } finally {
      setStartingSvc(false)
    }
  }

  const handleInstall = async () => {
    if (!serial) return
    setInstalling(true)
    setSetupMsg(null)
    setSetupOk(null)
    try {
      const result = await agentApi.setup(serial, apkPath || undefined)
      setSetupOk(result.ok)
      const lines = Object.entries(result.steps).map(([k, v]) => `${k}: ${v}`).join(' · ')
      setSetupMsg(lines)
      refetchStatus()
    } catch (e: any) {
      setSetupOk(false)
      setSetupMsg(e?.response?.data?.detail ?? e?.message ?? 'Setup failed')
    } finally {
      setInstalling(false)
    }
  }

  const handleRun = async () => {
    if (!serial) return
    setRunning(true)
    setError(null)
    try {
      await agentApi.run(serial, command, args)
      qc.invalidateQueries({ queryKey: ['agent-history', serial] })
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? e?.message ?? 'Command failed')
    } finally {
      setRunning(false)
    }
  }

  const clearHistory = async () => {
    if (!serial) return
    await agentApi.clearHistory(serial)
    qc.invalidateQueries({ queryKey: ['agent-history', serial] })
  }

  return (
    <div className="flex h-full overflow-hidden">
      {/* Left — setup + command builder */}
      <div className="w-80 shrink-0 border-r border-bg-border flex flex-col bg-bg-surface overflow-auto">

        {/* Header */}
        <div className="p-4 border-b border-bg-border">
          <div className="flex items-center gap-2 mb-4">
            <Terminal size={16} className="text-accent" />
            <h2 className="text-sm font-semibold text-zinc-200">Agent Console</h2>
          </div>

          {/* Device selector */}
          <label className="block text-xs text-zinc-500 mb-1">Device</label>
          {connected.length === 0 ? (
            <p className="text-xs text-zinc-600">No device connected</p>
          ) : (
            <select
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 mb-3"
              value={serial}
              onChange={(e) => setSerial(e.target.value)}
            >
              {connected.map((d) => (
                <option key={d.serial} value={d.serial}>{d.model || d.serial}</option>
              ))}
            </select>
          )}
        </div>

        {/* ── Build APK Section ── */}
        <div className="p-4 border-b border-bg-border space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold text-zinc-300">Build APK</p>
            {buildLog.length > 0 && (
              <button
                onClick={() => setBuildLogOpen((o) => !o)}
                className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300"
              >
                {buildLogOpen ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                {buildLogOpen ? 'Hide log' : 'Show log'}
              </button>
            )}
          </div>

          <p className="text-[10px] text-zinc-600 leading-relaxed">
            Runs <span className="font-mono">gradlew assembleDebug</span> in the MobileMorphAgent project.
            Requires Android SDK + Java on PATH.
          </p>

          <button
            onClick={handleBuild}
            disabled={building}
            className={clsx(
              'w-full flex items-center justify-center gap-2 py-2 text-xs font-medium rounded transition-colors disabled:opacity-40',
              buildStatus === 'success'
                ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                : buildStatus === 'failed'
                ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
                : 'bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700'
            )}
          >
            {building
              ? <Loader2 size={12} className="animate-spin" />
              : <Hammer size={12} />}
            {building
              ? 'Building…'
              : buildStatus === 'success'
              ? 'Rebuild APK'
              : buildStatus === 'failed'
              ? 'Retry Build'
              : 'Build APK'}
          </button>

          {/* Status badge */}
          {buildStatus !== 'idle' && !building && (
            <div className={clsx(
              'flex items-center gap-2 text-xs px-2 py-1.5 rounded border',
              buildStatus === 'success'
                ? 'bg-green-500/10 border-green-500/30 text-green-400'
                : 'bg-red-500/10 border-red-500/30 text-red-400'
            )}>
              {buildStatus === 'success'
                ? <CheckCircle2 size={12} />
                : <XCircle size={12} />}
              {buildStatus === 'success' ? 'Build succeeded — APK ready' : buildError ?? 'Build failed'}
            </div>
          )}

          {/* Live log */}
          {buildLogOpen && buildLog.length > 0 && (
            <div className="bg-bg-base rounded border border-bg-border max-h-48 overflow-auto">
              <div className="p-2 space-y-0.5">
                {buildLog.map((line, i) => (
                  <p key={i} className={clsx(
                    'text-[10px] font-mono leading-relaxed whitespace-pre-wrap break-all',
                    line.includes('BUILD SUCCESSFUL') || line.startsWith('✓')
                      ? 'text-green-400'
                      : line.includes('FAILED') || line.startsWith('✗') || line.includes('error:')
                      ? 'text-red-400'
                      : line.includes('warning:') || line.includes('Warning')
                      ? 'text-yellow-400'
                      : 'text-zinc-500'
                  )}>
                    {line || ' '}
                  </p>
                ))}
                <div ref={logEndRef} />
              </div>
            </div>
          )}
        </div>

        {/* ── Agent Setup Section ── */}
        <div className="p-4 border-b border-bg-border space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs font-semibold text-zinc-300">Agent Setup</p>
              <button
                onClick={() => refetchStatus()}
                className="p-0.5 rounded text-zinc-500 hover:text-zinc-200 hover:bg-bg-elevated"
                title="Refresh status"
              >
                <RefreshCw size={12} />
              </button>
            </div>

            {/* Status chips */}
            {serial ? (
              <div className="flex gap-2 flex-wrap">
                <StatusChip label="Installed" ok={status?.installed} />
                <StatusChip label="Forwarded" ok={status?.forwarded} />
                <StatusChip label="Reachable" ok={status?.reachable} />
              </div>
            ) : (
              <p className="text-[10px] text-zinc-600">Select a device above to see status</p>
            )}

            {/* Start Service — fastest path when APK is already installed */}
            {serial && status?.installed && !status?.reachable && (
              <button
                onClick={handleStartService}
                disabled={startingSvc || !serial}
                className="w-full flex items-center justify-center gap-2 py-1.5 text-xs font-medium bg-yellow-500/20 text-yellow-400 rounded hover:bg-yellow-500/30 disabled:opacity-40 transition-colors"
              >
                {startingSvc ? <Loader2 size={12} className="animate-spin" /> : <Power size={12} />}
                {startingSvc ? 'Starting service…' : 'Start Service (no reinstall)'}
              </button>
            )}

            {/* Rebuild hint */}
            {serial && status?.installed && !status?.reachable && (
              <p className="text-[10px] text-zinc-600 leading-relaxed">
                If "Start Service" fails, rebuild the APK above then use "Install & Forward" to push the updated APK.
              </p>
            )}

            {/* APK path override */}
            <div>
              <label className="block text-[10px] text-zinc-500 mb-1">APK path (leave blank to use config default)</label>
              <input
                className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 font-mono focus:outline-none focus:border-accent"
                placeholder="C:\...\app-debug.apk"
                value={apkPath}
                onChange={(e) => setApkPath(e.target.value)}
              />
            </div>

            <button
              onClick={handleInstall}
              disabled={installing || !serial}
              className="w-full flex items-center justify-center gap-2 py-2 text-xs font-medium bg-accent/20 text-accent rounded hover:bg-accent/30 disabled:opacity-40 transition-colors"
            >
              {installing
                ? <Loader2 size={12} className="animate-spin" />
                : <Download size={12} />}
              {installing ? 'Installing…' : status?.installed ? 'Re-install & Forward' : 'Install & Forward Port'}
            </button>

            {/* Setup result */}
            {setupMsg && (
              <div className={clsx(
                'flex items-start gap-2 p-2 rounded text-xs border',
                setupOk
                  ? 'bg-green-500/10 border-green-500/30 text-green-400'
                  : 'bg-red-500/10 border-red-500/30 text-red-400'
              )}>
                {setupOk
                  ? <CheckCircle2 size={12} className="mt-0.5 shrink-0" />
                  : <AlertCircle size={12} className="mt-0.5 shrink-0" />}
                <span className="break-all">{setupMsg}</span>
              </div>
            )}

            {/* Open Frida shortcut */}
            <button
              onClick={() => navigate('/frida')}
              className="w-full flex items-center justify-center gap-2 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 border border-bg-border rounded hover:bg-bg-elevated transition-colors"
            >
              <Zap size={12} className="text-yellow-400" />
              Open Frida — hook processes on this device
            </button>
          </div>

        {/* ── Command Builder ── */}
        <div className="p-4 border-b border-bg-border">
          <p className="text-xs font-semibold text-zinc-300 mb-3">Run Command</p>

          <label className="block text-xs text-zinc-500 mb-1">Command</label>
          <select
            className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 mb-2"
            value={command}
            onChange={(e) => { setCommand(e.target.value); setArgs({}) }}
          >
            {AGENT_COMMANDS.map((c) => (
              <option key={c.value} value={c.value}>{c.label}</option>
            ))}
          </select>
          <p className="text-xs text-zinc-600 mb-3">{selectedCmd.description}</p>

          {selectedCmd.args.filter((a) => !a.endsWith('?')).map((arg) => (
            <div key={arg} className="mb-2">
              <label className="block text-xs text-zinc-500 mb-1">{arg}</label>
              <input
                className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent font-mono"
                placeholder={arg}
                value={args[arg] ?? ''}
                onChange={(e) => setArgs((p) => ({ ...p, [arg]: e.target.value }))}
              />
            </div>
          ))}

          {error && (
            <div className="flex items-start gap-2 mt-2 p-2 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
              <AlertCircle size={12} className="mt-0.5 shrink-0" />
              {error}
            </div>
          )}

          <button
            onClick={handleRun}
            disabled={running || !serial || !status?.reachable}
            className="w-full mt-3 flex items-center justify-center gap-2 py-2 text-xs font-medium bg-accent/20 text-accent rounded hover:bg-accent/30 disabled:opacity-40 transition-colors"
            title={!status?.reachable ? 'Agent not reachable — run Install & Forward first' : undefined}
          >
            {running ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
            {running ? 'Running...' : 'Run'}
          </button>

          {serial && status && !status.reachable && (
            <p className="text-[10px] text-zinc-600 mt-2 text-center">
              Agent not reachable — install & forward port first
            </p>
          )}
        </div>

        {/* Setup hint */}
        <div className="p-4 text-xs text-zinc-600 space-y-1">
          <p className="text-zinc-500 font-medium">Manual setup (alternative):</p>
          <p>1. Install MobileMorphAgent APK</p>
          <p>2. Launch app and start the service</p>
          <p className="text-zinc-700 font-mono mt-1">adb forward tcp:31415 tcp:31415</p>
        </div>
      </div>

      {/* Right — output */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 border-b border-bg-border bg-bg-surface shrink-0">
          <span className="text-xs text-zinc-400">{history.length} commands</span>
          <button
            onClick={clearHistory}
            className="flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-200 px-2 py-1 rounded hover:bg-bg-elevated"
          >
            <Trash2 size={12} /> Clear
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4 space-y-2">
          {isLoading && <div className="flex justify-center pt-8"><Loader2 className="animate-spin text-accent" /></div>}
          {!isLoading && history.length === 0 && (
            <div className="flex flex-col items-center justify-center h-48 text-zinc-600 text-sm gap-2">
              <Terminal size={24} />
              <p>No commands yet — select a command and run it</p>
            </div>
          )}
          {history.map((cmd) => (
            <CommandCard
              key={cmd.id}
              cmd={cmd}
              expanded={expandedId === cmd.id}
              onToggle={() => setExpandedId(expandedId === cmd.id ? null : cmd.id)}
            />
          ))}
        </div>
      </div>
    </div>
  )
}

/* ── Status chip ── */
function StatusChip({ label, ok }: { label: string; ok?: boolean }) {
  if (ok === undefined) {
    return (
      <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border border-bg-border text-zinc-600">
        <Loader2 size={9} className="animate-spin" /> {label}
      </span>
    )
  }
  return (
    <span className={clsx(
      'flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border',
      ok
        ? 'text-green-400 bg-green-500/10 border-green-500/30'
        : 'text-red-400 bg-red-500/10 border-red-500/30'
    )}>
      {ok
        ? <CheckCircle2 size={9} />
        : <XCircle size={9} />}
      {label}
    </span>
  )
}

/* ── Command history card ── */
function CommandCard({ cmd, expanded, onToggle }: { cmd: AgentCommandResult; expanded: boolean; onToggle: () => void }) {
  const statusColor = cmd.status === 'complete' ? 'text-green-400' : cmd.status === 'error' ? 'text-red-400' : 'text-yellow-400'
  const label = AGENT_COMMANDS.find((c) => c.value === cmd.command_type)?.label ?? cmd.command_type

  let resultStr = ''
  try {
    resultStr = typeof cmd.result === 'string' ? cmd.result : JSON.stringify(cmd.result, null, 2)
  } catch { resultStr = String(cmd.result) }

  return (
    <div className="bg-bg-surface rounded border border-bg-border overflow-hidden">
      <div
        className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-bg-elevated"
        onClick={onToggle}
      >
        <span className={clsx('text-xs font-mono shrink-0', statusColor)}>●</span>
        <span className="text-xs font-medium text-zinc-200 flex-1">{label}</span>
        {cmd.args && Object.keys(cmd.args).length > 0 && (
          <span className="text-xs font-mono text-zinc-500 truncate max-w-32">
            {Object.values(cmd.args).join(' ')}
          </span>
        )}
        {cmd.duration_ms && (
          <span className="text-xs text-zinc-600 shrink-0">{cmd.duration_ms.toFixed(0)}ms</span>
        )}
        {expanded ? <ChevronDown size={12} className="text-zinc-500 shrink-0" /> : <ChevronRight size={12} className="text-zinc-500 shrink-0" />}
      </div>
      {expanded && (
        <div className="border-t border-bg-border">
          {cmd.error && (
            <div className="px-3 py-2 text-xs text-red-400 bg-red-500/5">{cmd.error}</div>
          )}
          {resultStr && (
            <pre className="px-3 py-3 text-xs font-mono text-zinc-300 whitespace-pre-wrap break-all bg-bg-base max-h-96 overflow-auto">
              {resultStr}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}

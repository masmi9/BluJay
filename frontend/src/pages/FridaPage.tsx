import { useState, useMemo, useEffect, useRef, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Virtuoso } from 'react-virtuoso'
import { Zap, Play, Square, Trash2, ChevronDown, ChevronRight, Save, X, BookOpen, RefreshCw, Search, Terminal, StopCircle, Send } from 'lucide-react'
import { clsx } from 'clsx'
import Editor from '@monaco-editor/react'
import { fridaApi } from '@/api/frida'
import { iosApi } from '@/api/ios'
import { objectionApi } from '@/api/objection'
import { useDeviceStore } from '@/store/deviceStore'
import { useFridaStore } from '@/store/fridaStore'
import { useFridaEvents } from '@/hooks/useFridaEvents'
import type { FridaScriptInfo, FridaEvent, FridaProcess } from '@/types/frida'

// Standalone session id — used when attaching without a DynamicSession
const STANDALONE_SESSION = 0

const STORAGE_KEY = 'frida_saved_scripts'

interface SavedScript {
  id: string
  name: string
  source: string
  savedAt: string
}

function loadSaved(): SavedScript[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]')
  } catch {
    return []
  }
}

function persistSaved(scripts: SavedScript[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(scripts))
}

// Strip ANSI escape codes for plain-text display
function stripAnsi(str: string): string {
  return str.replace(/\x1b\[[0-9;]*[mGKHF]/g, '')
}

// ─── Objection Panel ────────────────────────────────────────────────────────

function ObjectionPanel({ serial }: { serial: string }) {
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [gadget, setGadget] = useState('')
  // Serial is optional — leave blank to let frida auto-detect the USB device
  const [deviceSerial, setDeviceSerial] = useState('')
  const [lines, setLines] = useState<string[]>([])
  const [input, setInput] = useState('')
  const [history, setHistory] = useState<string[]>([])
  const [histIdx, setHistIdx] = useState(-1)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const outputRef = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const apiBase = (window as any).__API_BASE__ ?? ''
  const wsBase = apiBase.replace(/^http/, 'ws')

  const appendLine = useCallback((text: string) => {
    setLines((prev) => [...prev, stripAnsi(text)])
  }, [])

  // Auto-scroll to bottom on new output
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [lines])

  // Connect WebSocket when session starts
  useEffect(() => {
    if (!sessionId) return

    const ws = new WebSocket(`${wsBase}/ws/objection/${sessionId}`)
    wsRef.current = ws

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.type === 'output' && msg.data) appendLine(msg.data)
        if (msg.type === 'exit' && msg.data) {
          appendLine(msg.data)
          setSessionId(null)
        }
      } catch {}
    }
    ws.onerror = () => appendLine('\n[WebSocket error — connection lost]\n')
    ws.onclose = () => {}

    return () => {
      ws.close()
      wsRef.current = null
    }
  }, [sessionId, wsBase, appendLine])

  const startSession = async () => {
    if (!gadget.trim()) return
    setStarting(true)
    setError(null)
    setLines([])
    try {
      const sess = await objectionApi.start(gadget.trim(), deviceSerial.trim() || undefined)
      setSessionId(sess.session_id)
      appendLine(`[objection] starting session for ${gadget}${deviceSerial.trim() ? ` on device ${deviceSerial.trim()}` : ' (auto-detect device)'}\n`)
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? e?.message ?? 'Failed to start objection')
    } finally {
      setStarting(false)
    }
  }

  const stopSession = async () => {
    if (!sessionId) return
    wsRef.current?.close()
    await objectionApi.stop(sessionId)
    setSessionId(null)
    appendLine('\n[session stopped]\n')
  }

  const sendCommand = () => {
    if (!input.trim() || !sessionId || !wsRef.current) return
    const cmd = input.trim()
    // Echo the command locally
    appendLine(`objection> ${cmd}\n`)
    wsRef.current.send(JSON.stringify({ type: 'input', data: cmd }))
    setHistory((h) => [cmd, ...h.slice(0, 99)])
    setHistIdx(-1)
    setInput('')
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') { sendCommand(); return }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      const next = Math.min(histIdx + 1, history.length - 1)
      setHistIdx(next)
      setInput(history[next] ?? '')
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      const next = Math.max(histIdx - 1, -1)
      setHistIdx(next)
      setInput(next === -1 ? '' : history[next] ?? '')
    }
  }

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-bg-border bg-bg-surface shrink-0 flex-wrap">
        <Terminal size={14} className={sessionId ? 'text-green-400' : 'text-zinc-500'} />
        <span className="text-xs font-semibold text-zinc-300">Objection</span>
        {sessionId && (
          <span className="text-xs text-zinc-400 font-mono">attached → {gadget}</span>
        )}
        <div className="flex-1" />
        {!sessionId ? (
          <>
            <input
              className="bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 w-56 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
              placeholder="Bundle ID / package name"
              value={gadget}
              onChange={(e) => setGadget(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') startSession() }}
            />
            <input
              className="bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 w-40 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
              placeholder="Device serial (optional)"
              value={deviceSerial}
              onChange={(e) => setDeviceSerial(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') startSession() }}
              title="Leave blank to auto-detect USB device"
            />
            <button
              onClick={startSession}
              disabled={!gadget.trim() || starting}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-green-500/20 text-green-400 hover:bg-green-500/30 disabled:opacity-40 transition-colors"
            >
              <Play size={12} /> {starting ? 'Starting…' : 'Start'}
            </button>
          </>
        ) : (
          <button
            onClick={stopSession}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
          >
            <StopCircle size={12} /> Stop
          </button>
        )}
        <button
          onClick={() => setLines([])}
          className="p-1.5 text-zinc-500 hover:text-zinc-200 rounded hover:bg-bg-elevated"
          title="Clear output"
        >
          <Trash2 size={13} />
        </button>
      </div>

      {error && (
        <div className="px-4 py-2 text-xs text-red-400 bg-red-500/10 border-b border-red-500/20 shrink-0">
          {error}
        </div>
      )}

      {/* Terminal output */}
      <div
        ref={outputRef}
        className="flex-1 overflow-auto bg-bg-base font-mono text-xs text-zinc-300 p-3 whitespace-pre-wrap break-all"
        onClick={() => inputRef.current?.focus()}
      >
        {lines.length === 0 ? (
          <span className="text-zinc-600">
            {sessionId
              ? 'Waiting for objection output…'
              : 'Enter a bundle ID or package name above and click Start to launch an objection session.'}
          </span>
        ) : (
          lines.map((line, i) => (
            <span
              key={i}
              className={
                line.startsWith('objection>')
                  ? 'text-yellow-400'
                  : line.startsWith('[objection]') || line.startsWith('[session')
                  ? 'text-zinc-500'
                  : 'text-zinc-300'
              }
            >
              {line}
            </span>
          ))
        )}
      </div>

      {/* Command input */}
      <div className="flex items-center gap-2 px-3 py-2 border-t border-bg-border bg-bg-surface shrink-0">
        <span className="text-xs text-yellow-400 font-mono shrink-0">objection&gt;</span>
        <input
          ref={inputRef}
          className="flex-1 bg-transparent text-xs font-mono text-zinc-200 outline-none placeholder-zinc-600"
          placeholder={sessionId ? 'Type a command…' : 'Start a session first'}
          value={input}
          disabled={!sessionId}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
        />
        <button
          onClick={sendCommand}
          disabled={!sessionId || !input.trim()}
          className="p-1 text-zinc-500 hover:text-zinc-200 disabled:opacity-30"
          title="Send (Enter)"
        >
          <Send size={13} />
        </button>
      </div>

      {/* Quick command palette */}
      {sessionId && (
        <div className="flex flex-wrap gap-1 px-3 py-2 border-t border-bg-border bg-bg-surface shrink-0">
          {QUICK_COMMANDS.map((qc) => (
            <button
              key={qc.label}
              onClick={() => {
                appendLine(`objection> ${qc.cmd}\n`)
                wsRef.current?.send(JSON.stringify({ type: 'input', data: qc.cmd }))
              }}
              className="text-[10px] font-mono px-2 py-0.5 rounded border border-bg-border text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 transition-colors"
              title={qc.description}
            >
              {qc.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

const QUICK_COMMANDS = [
  { label: 'ios ssl disable',       cmd: 'ios sslpinning disable',              description: 'Disable SSL pinning (iOS)' },
  { label: 'ios jb disable',        cmd: 'ios jailbreak disable',               description: 'Disable jailbreak detection (iOS)' },
  { label: 'ios keychain dump',     cmd: 'ios keychain dump',                   description: 'Dump iOS keychain entries' },
  { label: 'ios userdefaults',      cmd: 'ios nsuserdefaults get',              description: 'Dump NSUserDefaults' },
  { label: 'ios cookies',           cmd: 'ios cookies get',                     description: 'Dump cookies (iOS)' },
  { label: 'ios pasteboard',        cmd: 'ios pasteboard monitor',              description: 'Monitor iOS pasteboard' },
  { label: 'ios bundles',           cmd: 'ios bundles list_bundles',            description: 'List loaded bundles (iOS)' },
  { label: 'env',                   cmd: 'env',                                 description: 'Show app environment & paths' },
  { label: 'jobs list',             cmd: 'jobs list',                           description: 'List active hooks/jobs' },
  { label: 'memory list modules',   cmd: 'memory list modules',                 description: 'List loaded modules in memory' },
  { label: 'android ssl disable',   cmd: 'android sslpinning disable',          description: 'Disable SSL pinning (Android)' },
  { label: 'android root disable',  cmd: 'android root disable',               description: 'Disable root detection (Android)' },
  { label: 'android intent launch', cmd: 'android intent launch_activity',     description: 'Launch activity (Android)' },
]

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function FridaPage() {
  const { devices, activeSession } = useDeviceStore()
  const connected = devices.filter((d) => d.state === 'device')

  const { data: iosDevices = [] } = useQuery({
    queryKey: ['ios-devices'],
    queryFn: iosApi.listDevices,
    refetchInterval: 5000,
  })

  // Device + process selection (independent of DynamicSession)
  const [selectedSerial, setSelectedSerial] = useState(connected[0]?.serial ?? '')
  const [processFilter, setProcessFilter] = useState('')
  const [selectedProcess, setSelectedProcess] = useState('')

  const sessionId = activeSession?.id ?? STANDALONE_SESSION
  const { attached, setAttached: setFridaAttached, detach: fridaDetach } = useFridaStore()
  const [customScript, setCustomScript] = useState('// Your Frida script here\nJava.perform(function() {\n  // ...\n});\n')
  const [activeTab, setActiveTab] = useState<'library' | 'editor'>('library')
  const [expandedEvent, setExpandedEvent] = useState<number | null>(null)
  const [savedScripts, setSavedScripts] = useState<SavedScript[]>(loadSaved)
  const [saveDialogOpen, setSaveDialogOpen] = useState(false)
  const [saveName, setSaveName] = useState('')
  const [attachError, setAttachError] = useState<string | null>(null)

  const { events, clear } = useFridaEvents(attached ? sessionId : null)

  const { data: scripts = [] } = useQuery({
    queryKey: ['frida-scripts'],
    queryFn: fridaApi.listScripts,
  })

  const { data: processes = [], refetch: refetchProcesses, isFetching: fetchingProcs, error: processError } = useQuery({
    queryKey: ['frida-processes', selectedSerial],
    queryFn: () => fridaApi.processes(selectedSerial),
    enabled: !!selectedSerial,
    retry: false,
    staleTime: 10_000,
  })

  // Auto-select the first available device when device lists load
  useEffect(() => {
    if (selectedSerial) return
    if (connected.length > 0) {
      setSelectedSerial(connected[0].serial)
    } else if (iosDevices.length > 0) {
      setSelectedSerial(iosDevices[0].udid)
    }
  }, [connected, iosDevices, selectedSerial])

  const filteredProcesses = useMemo(() => {
    if (!processFilter) return processes
    const q = processFilter.toLowerCase()
    return processes.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.identifier ?? '').toLowerCase().includes(q) ||
        (p.pid != null && String(p.pid).includes(q))
    )
  }, [processes, processFilter])

  // Resolve the serial + package to attach to
  const attachSerial = activeSession?.device_serial ?? selectedSerial
  const attachPackage = activeSession?.package_name ?? selectedProcess

  const attach = async () => {
    if (!attachSerial || !attachPackage) return
    setAttachError(null)
    try {
      await fridaApi.attach(sessionId, attachSerial, attachPackage)
      setFridaAttached(true, attachPackage, attachSerial, sessionId)
    } catch (e: any) {
      setAttachError(e?.response?.data?.detail ?? e?.message ?? 'Attach failed')
    }
  }

  const detach = async () => {
    await fridaApi.detach(sessionId)
    fridaDetach()
  }

  const loadBuiltin = async (name: string) => {
    if (!attached) return
    const key = name.replace('.js', '').replace(/-/g, '_')
    await fridaApi.loadBuiltin(sessionId, key)
  }

  const runCustom = async () => {
    if (!attached) return
    await fridaApi.loadCustom(sessionId, customScript)
  }

  const saveScript = () => {
    if (!saveName.trim()) return
    const newScript: SavedScript = {
      id: Date.now().toString(),
      name: saveName.trim(),
      source: customScript,
      savedAt: new Date().toISOString(),
    }
    const updated = [newScript, ...savedScripts]
    setSavedScripts(updated)
    persistSaved(updated)
    setSaveDialogOpen(false)
    setSaveName('')
  }

  const deleteSaved = (id: string) => {
    const updated = savedScripts.filter((s) => s.id !== id)
    setSavedScripts(updated)
    persistSaved(updated)
  }

  const loadSavedIntoEditor = (script: SavedScript) => {
    setCustomScript(script.source)
    setActiveTab('editor')
  }

  const [pageTab, setPageTab] = useState<'frida' | 'objection'>('frida')

  return (
    <div className="flex flex-col h-full">
      {/* Page-level tab bar */}
      <div className="flex border-b border-bg-border bg-bg-surface shrink-0">
        <button
          onClick={() => setPageTab('frida')}
          className={clsx(
            'flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors',
            pageTab === 'frida'
              ? 'border-yellow-400 text-yellow-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-300'
          )}
        >
          <Zap size={12} /> Frida
        </button>
        <button
          onClick={() => setPageTab('objection')}
          className={clsx(
            'flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors',
            pageTab === 'objection'
              ? 'border-green-400 text-green-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-300'
          )}
        >
          <Terminal size={12} /> Objection
        </button>
      </div>

      {/* Objection tab */}
      {pageTab === 'objection' && (
        <ObjectionPanel serial={selectedSerial} />
      )}

      {/* Frida tab */}
      {pageTab === 'frida' && <div className="flex flex-col flex-1 overflow-hidden">

      {/* Toolbar */}
      <div className="flex flex-col gap-2 px-4 py-3 border-b border-bg-border bg-bg-surface shrink-0">
        <div className="flex items-center gap-2">
          <Zap size={14} className={attached ? 'text-yellow-400' : 'text-zinc-500'} />
          <span className="text-xs font-semibold text-zinc-300">Frida</span>
          {attached && (
            <span className="text-xs text-zinc-400 font-mono">
              attached → {attachPackage}
            </span>
          )}
          <div className="flex-1" />
          <button onClick={clear} className="p-1.5 text-zinc-500 hover:text-zinc-200 rounded hover:bg-bg-elevated" title="Clear events">
            <Trash2 size={14} />
          </button>
        </div>

        {/* Device + process picker */}
        {!attached && (
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              {/* Device selector */}
              {!activeSession && (
                <select
                  className="bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 w-52"
                  value={selectedSerial}
                  onChange={(e) => { setSelectedSerial(e.target.value); setSelectedProcess('') }}
                >
                  {connected.length === 0 && iosDevices.length === 0 && (
                    <option value="">No device</option>
                  )}
                  {connected.length > 0 && (
                    <optgroup label="Android (ADB)">
                      {connected.map((d) => (
                        <option key={d.serial} value={d.serial}>
                          {d.model || d.serial}
                        </option>
                      ))}
                    </optgroup>
                  )}
                  {iosDevices.length > 0 && (
                    <optgroup label="iOS (USB)">
                      {iosDevices.map((d) => (
                        <option key={d.udid} value={d.udid}>
                          {d.name || d.model || d.udid.slice(0, 16) + '…'}
                          {d.jailbroken ? ' ⚡' : ''}
                        </option>
                      ))}
                    </optgroup>
                  )}
                </select>
              )}
              {activeSession && (
                <span className="text-xs text-zinc-400 bg-bg-elevated border border-bg-border rounded px-2 py-1.5">
                  Session: {activeSession.package_name}
                </span>
              )}

              {/* Process search */}
              {!activeSession && (
                <div className="flex items-center gap-1 bg-bg-elevated border border-bg-border rounded px-2 py-1.5 flex-1">
                  <Search size={11} className="text-zinc-500 shrink-0" />
                  <input
                    className="bg-transparent text-xs text-zinc-200 outline-none w-full placeholder-zinc-600"
                    placeholder="Filter processes…"
                    value={processFilter}
                    onChange={(e) => setProcessFilter(e.target.value)}
                  />
                </div>
              )}
              {!activeSession && (
                <button
                  onClick={() => refetchProcesses()}
                  disabled={fetchingProcs}
                  className="p-1.5 text-zinc-500 hover:text-zinc-200 rounded hover:bg-bg-elevated disabled:opacity-40"
                  title="Refresh process list"
                >
                  <RefreshCw size={13} className={fetchingProcs ? 'animate-spin' : ''} />
                </button>
              )}
            </div>

            {/* Process list error */}
            {!activeSession && processError && (
              <p className="text-[10px] text-red-400 font-mono px-1">
                {(processError as any)?.response?.data?.detail ?? 'Failed to list processes — is frida-server running on the device?'}
              </p>
            )}

            {/* Process list */}
            {!activeSession && filteredProcesses.length > 0 && (
              <div className="flex flex-wrap gap-1 max-h-20 overflow-auto">
                {filteredProcesses.map((p, i) => {
                  // Frida attaches by bundle ID (iOS) or process name — prefer identifier
                  const attachTarget = p.identifier || p.name
                  return (
                    <button
                      key={`${p.identifier || ''}-${p.name}-${p.pid ?? i}`}
                      onClick={() => setSelectedProcess(attachTarget)}
                      className={clsx(
                        'text-[10px] font-mono px-2 py-0.5 rounded border transition-colors',
                        selectedProcess === attachTarget
                          ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                          : 'text-zinc-400 border-bg-border hover:border-zinc-500 hover:text-zinc-200'
                      )}
                    >
                      {p.name}
                      {p.identifier && p.identifier !== p.name && (
                        <span className="text-zinc-600 ml-1">({p.identifier})</span>
                      )}
                      {p.running && p.pid != null && (
                        <span className="text-zinc-600 ml-1">pid:{p.pid}</span>
                      )}
                    </button>
                  )
                })}
              </div>
            )}
            {!activeSession && !fetchingProcs && processes.length === 0 && selectedSerial && (
              <p className="text-[10px] text-zinc-600">
                No processes — is frida-server running on the device?
              </p>
            )}

            <div className="flex items-center gap-2">
              <button
                onClick={attach}
                disabled={!attachSerial || !attachPackage}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30 disabled:opacity-40 transition-colors"
              >
                <Zap size={12} /> Attach to {attachPackage || '…'}
              </button>
              {attachError && (
                <span className="text-xs text-red-400">{attachError}</span>
              )}
            </div>
          </div>
        )}

        {attached && (
          <button
            onClick={detach}
            className="self-start flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
          >
            <Square size={12} /> Detach
          </button>
        )}
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left panel — scripts */}
        <div className="w-72 shrink-0 border-r border-bg-border flex flex-col">
          <div className="flex border-b border-bg-border">
            {(['library', 'editor'] as const).map((t) => (
              <button key={t} onClick={() => setActiveTab(t)}
                className={clsx('flex-1 py-2 text-xs capitalize', activeTab === t ? 'bg-bg-elevated text-zinc-200' : 'text-zinc-500 hover:text-zinc-300')}>
                {t}
              </button>
            ))}
          </div>

          {activeTab === 'library' ? (
            <div className="flex-1 overflow-auto p-3 space-y-4">
              {/* Built-in scripts */}
              <div className="space-y-2">
                <p className="text-xs text-zinc-600 uppercase tracking-wide">Built-in</p>
                {scripts.map((s: FridaScriptInfo) => (
                  <ScriptCard key={s.filename} script={s} attached={attached}
                    onLoad={() => loadBuiltin(s.filename)} />
                ))}
              </div>

              {/* Saved scripts */}
              {savedScripts.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs text-zinc-600 uppercase tracking-wide">My Scripts</p>
                  {savedScripts.map((s) => (
                    <SavedScriptCard
                      key={s.id}
                      script={s}
                      attached={attached}
                      onLoad={() => { setCustomScript(s.source); setActiveTab('editor') }}
                      onRun={async () => {
                        if (sessionId == null || !attached) return
                        await fridaApi.loadCustom(sessionId, s.source)
                      }}
                      onDelete={() => deleteSaved(s.id)}
                    />
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col flex-1 overflow-hidden p-2 gap-2">
              <Editor
                height="100%"
                defaultLanguage="javascript"
                theme="vs-dark"
                value={customScript}
                onChange={(v) => setCustomScript(v ?? '')}
                options={{ minimap: { enabled: false }, fontSize: 12, lineNumbers: 'on' }}
              />
              <div className="flex gap-2">
                <button
                  onClick={runCustom}
                  disabled={!attached}
                  className="flex-1 flex items-center justify-center gap-1.5 py-1.5 text-xs bg-accent/20 text-accent rounded hover:bg-accent/30 disabled:opacity-40"
                >
                  <Play size={12} /> Run
                </button>
                <button
                  onClick={() => { setSaveName(''); setSaveDialogOpen(true) }}
                  className="flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs bg-bg-elevated text-zinc-400 rounded hover:bg-bg-border hover:text-zinc-200"
                >
                  <Save size={12} /> Save
                </button>
              </div>

              {/* Save dialog */}
              {saveDialogOpen && (
                <div className="bg-bg-surface border border-bg-border rounded p-3 space-y-2">
                  <p className="text-xs text-zinc-400">Script name</p>
                  <input
                    autoFocus
                    className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent"
                    placeholder="e.g. My SSL bypass"
                    value={saveName}
                    onChange={(e) => setSaveName(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') saveScript(); if (e.key === 'Escape') setSaveDialogOpen(false) }}
                  />
                  <div className="flex gap-2">
                    <button onClick={saveScript} disabled={!saveName.trim()}
                      className="flex-1 py-1 text-xs bg-accent/20 text-accent rounded hover:bg-accent/30 disabled:opacity-40">
                      Save
                    </button>
                    <button onClick={() => setSaveDialogOpen(false)}
                      className="px-3 py-1 text-xs text-zinc-500 hover:text-zinc-300">
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right panel — event stream */}
        <div className="flex-1 overflow-hidden flex flex-col">
          <div className="px-4 py-2 border-b border-bg-border text-xs text-zinc-500">
            {events.length} events
          </div>
          {events.length === 0 ? (
            <div className="flex items-center justify-center flex-1 text-zinc-600 text-sm">
              {attached ? 'Waiting for hook events...' : 'Attach Frida to see events'}
            </div>
          ) : (
            <Virtuoso
              style={{ flex: 1 }}
              data={events}
              itemContent={(_, event: FridaEvent) => (
                <EventRow event={event} expanded={expandedEvent === event.id}
                  onToggle={() => setExpandedEvent(expandedEvent === event.id ? null : event.id)} />
              )}
            />
          )}
        </div>
      </div>
      </div>} {/* end Frida tab */}
    </div>
  )
}

function ScriptCard({ script, attached, onLoad }: { script: FridaScriptInfo; attached: boolean; onLoad: () => void }) {
  return (
    <div className="bg-bg-surface rounded-lg border border-bg-border p-3 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium text-zinc-200">{script.name}</p>
        <button
          onClick={onLoad}
          disabled={!attached}
          className="shrink-0 px-2 py-0.5 text-xs bg-accent/20 text-accent rounded hover:bg-accent/30 disabled:opacity-40"
        >
          Load
        </button>
      </div>
      <p className="text-xs text-zinc-500">{script.description}</p>
      <div className="flex flex-wrap gap-1">
        {script.hooks.map((h) => (
          <span key={h} className="text-xs bg-bg-elevated text-zinc-400 px-1.5 py-0.5 rounded font-mono">{h}</span>
        ))}
      </div>
    </div>
  )
}

function SavedScriptCard({
  script, attached, onLoad, onRun, onDelete,
}: {
  script: SavedScript
  attached: boolean
  onLoad: () => void
  onRun: () => void
  onDelete: () => void
}) {
  return (
    <div className="bg-bg-surface rounded-lg border border-bg-border p-3 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium text-zinc-200 flex-1 truncate">{script.name}</p>
        <div className="flex gap-1 shrink-0">
          <button
            onClick={onLoad}
            title="Open in editor"
            className="px-1.5 py-0.5 text-xs text-zinc-500 hover:text-zinc-200 rounded hover:bg-bg-elevated"
          >
            <BookOpen size={11} />
          </button>
          <button
            onClick={onRun}
            disabled={!attached}
            title="Run on device"
            className="px-2 py-0.5 text-xs bg-accent/20 text-accent rounded hover:bg-accent/30 disabled:opacity-40"
          >
            Run
          </button>
          <button
            onClick={onDelete}
            title="Delete script"
            className="px-1.5 py-0.5 text-xs text-zinc-600 hover:text-red-400 rounded hover:bg-bg-elevated"
          >
            <X size={11} />
          </button>
        </div>
      </div>
      <p className="text-xs text-zinc-600 font-mono truncate">{script.source.split('\n')[0]}</p>
    </div>
  )
}

function EventRow({ event, expanded, onToggle }: { event: FridaEvent; expanded: boolean; onToggle: () => void }) {
  const typeColor = event.event_type === 'error' ? 'text-red-400' : event.event_type === 'send' ? 'text-green-400' : 'text-blue-400'
  let payload: object | null = null
  try { payload = JSON.parse(event.payload) } catch {}

  return (
    <div className="border-b border-bg-border hover:bg-bg-elevated">
      <div className="flex items-center gap-3 px-4 py-2 cursor-pointer" onClick={onToggle}>
        <span className={clsx('text-xs font-mono', typeColor)}>{event.event_type}</span>
        {event.script_name && <span className="text-xs text-zinc-500">{event.script_name}</span>}
        <span className="flex-1 text-xs font-mono text-zinc-400 truncate">
          {payload ? JSON.stringify(payload).slice(0, 120) : event.payload.slice(0, 120)}
        </span>
        <span className="text-xs text-zinc-600 shrink-0">{new Date(event.timestamp).toLocaleTimeString()}</span>
        {expanded ? <ChevronDown size={12} className="text-zinc-500 shrink-0" /> : <ChevronRight size={12} className="text-zinc-500 shrink-0" />}
      </div>
      {expanded && (
        <pre className="px-4 pb-3 text-xs font-mono text-zinc-300 whitespace-pre-wrap break-all bg-bg-base">
          {JSON.stringify(payload ?? event.payload, null, 2)}
        </pre>
      )}
    </div>
  )
}

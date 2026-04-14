import { useCallback, useEffect, useRef, useState, type RefObject } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Wifi, Play, Trash2, Upload, Plus, ChevronRight, ChevronDown,
  AlertTriangle, Loader2, CheckCircle2, XCircle, Clock,
  Zap, Shield, RefreshCw, Terminal, ArrowRight, Crosshair,
} from 'lucide-react'
import { clsx } from 'clsx'
import { Badge } from '@/components/common/Badge'
import { apiTestingApi } from '@/api/api_testing'
import { fuzzingApi } from '@/api/fuzzing'
import { useWebSocket } from '@/hooks/useWebSocket'
import type {
  ApiTest, ApiTestResult, ApiTestSuite,
  SuggestedTest, WsTestEvent,
} from '@/types/api_testing'
import type { FuzzJob, FuzzJobDetail, FuzzResult } from '@/types/fuzzing'

// ── Constants ────────────────────────────────────────────────────────────────

const TEST_TYPE_COLORS: Record<string, string> = {
  idor_sweep:     'text-orange-400 bg-orange-400/10 border-orange-400/20',
  auth_strip:     'text-red-400 bg-red-400/10 border-red-400/20',
  token_replay:   'text-purple-400 bg-purple-400/10 border-purple-400/20',
  cross_user_auth:'text-blue-400 bg-blue-400/10 border-blue-400/20',
}

const TEST_TYPE_LABELS: Record<string, string> = {
  idor_sweep:     'IDOR Sweep',
  auth_strip:     'Auth Strip',
  token_replay:   'Token Replay',
  cross_user_auth:'Cross-User Auth',
}

const STATUS_STYLES: Record<string, string> = {
  pending:  'text-zinc-400',
  running:  'text-blue-400 animate-pulse',
  complete: 'text-green-400',
  failed:   'text-red-400',
}

function statusIcon(status: string) {
  if (status === 'running')  return <Loader2 size={11} className="animate-spin text-blue-400" />
  if (status === 'complete') return <CheckCircle2 size={11} className="text-green-400" />
  if (status === 'failed')   return <XCircle size={11} className="text-red-400" />
  return <Clock size={11} className="text-zinc-500" />
}

function httpStatusColor(code: number | null) {
  if (!code) return 'text-zinc-500'
  if (code < 300) return 'text-green-400'
  if (code < 400) return 'text-yellow-400'
  if (code < 500) return 'text-red-400'
  return 'text-orange-400'
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function ApiTesting() {
  const [searchParams] = useSearchParams()
  const sessionParam = searchParams.get('session')
  const activeSessionId = sessionParam ? Number(sessionParam) : null

  const [selectedSuiteId, setSelectedSuiteId] = useState<number | null>(null)
  const [selectedTestId, setSelectedTestId] = useState<number | null>(null)
  const [activeTab, setActiveTab] = useState<'tests' | 'results' | 'fuzzer'>('tests')
  const [showNewSuite, setShowNewSuite] = useState(false)
  const [newSuiteName, setNewSuiteName] = useState('')
  const [suggestedTests, setSuggestedTests] = useState<SuggestedTest[]>([])
  const [wsLogs, setWsLogs] = useState<WsTestEvent[]>([])
  const [wsWaiting, setWsWaiting] = useState(false)
  const [expandedResultId, setExpandedResultId] = useState<number | null>(null)
  const [showNewTest, setShowNewTest] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const logsEndRef = useRef<HTMLDivElement | null>(null)
  const qc = useQueryClient()

  // ── Queries ──────────────────────────────────────────────────────────────

  const { data: suites = [] } = useQuery({
    queryKey: ['api-testing-suites'],
    queryFn: () => apiTestingApi.listSuites(),
    refetchInterval: 5000,
  })

  const selectedSuite = suites.find(s => s.id === selectedSuiteId) ?? null

  const { data: tests = [] } = useQuery({
    queryKey: ['api-testing-tests', selectedSuiteId],
    queryFn: () => apiTestingApi.listTests(selectedSuiteId!),
    enabled: !!selectedSuiteId,
    refetchInterval: (q) => {
      const items = q.state.data as ApiTest[] | undefined
      return items?.some(t => t.status === 'running') ? 1500 : 5000
    },
  })

  const selectedTest = tests.find(t => t.id === selectedTestId) ?? null

  const { data: results = [], refetch: refetchResults } = useQuery({
    queryKey: ['api-testing-results', selectedTestId],
    queryFn: () => apiTestingApi.getResults(selectedSuiteId!, selectedTestId!),
    enabled: !!selectedTestId && !!selectedSuiteId,
  })

  // ── Mutations ────────────────────────────────────────────────────────────

  const createSuite = useMutation({
    mutationFn: (name: string) =>
      apiTestingApi.createSuite({
        name,
        session_id: activeSessionId,
        platform: 'ios',
      }),
    onSuccess: (suite) => {
      qc.invalidateQueries({ queryKey: ['api-testing-suites'] })
      setSelectedSuiteId(suite.id)
      setShowNewSuite(false)
      setNewSuiteName('')
    },
  })

  const importFlows = useMutation({
    mutationFn: () => apiTestingApi.importFlows(selectedSuiteId!),
    onSuccess: (data) => {
      setSuggestedTests(data.suggested_tests)
      qc.invalidateQueries({ queryKey: ['api-testing-suites'] })
    },
  })

  const bulkAdd = useMutation({
    mutationFn: (tests: SuggestedTest[]) =>
      apiTestingApi.bulkCreateTests(selectedSuiteId!, tests),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-testing-tests', selectedSuiteId] })
      setSuggestedTests([])
    },
  })

  const addOne = useMutation({
    mutationFn: (t: SuggestedTest) =>
      apiTestingApi.createTest(selectedSuiteId!, {
        ...t,
        headers: t.headers as Record<string, string>,
        config: t.config as Record<string, unknown>,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-testing-tests', selectedSuiteId] })
    },
  })

  const runTest = useMutation({
    mutationFn: (testId: number) =>
      apiTestingApi.runTest(selectedSuiteId!, testId),
    onSuccess: (_, testId) => {
      setSelectedTestId(testId)
      setActiveTab('results')
      setWsLogs([])
      setWsWaiting(false)
      startWs(testId)
      qc.invalidateQueries({ queryKey: ['api-testing-tests', selectedSuiteId] })
    },
  })

  const clearResults = useMutation({
    mutationFn: (testId: number) =>
      apiTestingApi.clearResults(selectedSuiteId!, testId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-testing-tests', selectedSuiteId] })
      qc.invalidateQueries({ queryKey: ['api-testing-results', selectedTestId] })
    },
  })

  const exportFinding = useMutation({
    mutationFn: (testId: number) =>
      apiTestingApi.exportFinding(selectedSuiteId!, testId),
  })

  const fuzzSuite = useMutation({
    mutationFn: () => apiTestingApi.fuzzSuite(selectedSuiteId!),
  })

  // ── New test form state ──────────────────────────────────────────────────

  const [newTest, setNewTest] = useState({
    test_type: 'auth_strip',
    name: '',
    method: 'GET',
    url: '',
    headers: '{}',
    config: '{}',
  })

  const submitNewTest = useMutation({
    mutationFn: () => {
      let headers: Record<string, string> = {}
      let config: Record<string, unknown> = {}
      try { headers = JSON.parse(newTest.headers) } catch {}
      try { config = JSON.parse(newTest.config) } catch {}
      return apiTestingApi.createTest(selectedSuiteId!, {
        test_type: newTest.test_type,
        name: newTest.name,
        method: newTest.method,
        url: newTest.url,
        headers,
        config,
      })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-testing-tests', selectedSuiteId] })
      setShowNewTest(false)
      setNewTest({ test_type: 'auth_strip', name: '', method: 'GET', url: '', headers: '{}', config: '{}' })
    },
  })

  // ── WebSocket ─────────────────────────────────────────────────────────────

  const startWs = useCallback((testId: number) => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/api-testing/${testId}`)
    ws.onmessage = (e) => {
      try {
        const msg: WsTestEvent = JSON.parse(e.data)
        if (msg.type === 'ping') return
        if (msg.type === 'waiting') setWsWaiting(true)
        if (msg.type === 'done') {
          setWsWaiting(false)
          refetchResults()
          qc.invalidateQueries({ queryKey: ['api-testing-tests', selectedSuiteId] })
        }
        setWsLogs(prev => [...prev.slice(-200), msg])
      } catch {}
    }
    ws.onclose = () => {
      refetchResults()
      qc.invalidateQueries({ queryKey: ['api-testing-tests', selectedSuiteId] })
    }
    wsRef.current = ws
  }, [refetchResults, qc, selectedSuiteId])

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [wsLogs])

  useEffect(() => () => { wsRef.current?.close() }, [])

  // ── Auto-select first suite ───────────────────────────────────────────────

  useEffect(() => {
    if (!selectedSuiteId && suites.length > 0) {
      setSelectedSuiteId(suites[0].id)
    }
  }, [suites, selectedSuiteId])

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex h-full overflow-hidden">
      {/* ── Left panel ── */}
      <aside className="w-72 shrink-0 border-r border-bg-border flex flex-col overflow-hidden bg-bg-surface">
        <LeftPanel
          suites={suites}
          selectedSuiteId={selectedSuiteId}
          selectedSuite={selectedSuite}
          activeSessionId={activeSessionId}
          showNewSuite={showNewSuite}
          newSuiteName={newSuiteName}
          suggestedTests={suggestedTests}
          isImporting={importFlows.isPending}
          isBulkAdding={bulkAdd.isPending}
          onSelectSuite={(id) => { setSelectedSuiteId(id); setSuggestedTests([]) }}
          onShowNewSuite={() => setShowNewSuite(true)}
          onCancelNewSuite={() => { setShowNewSuite(false); setNewSuiteName('') }}
          onNewSuiteNameChange={setNewSuiteName}
          onCreateSuite={() => newSuiteName.trim() && createSuite.mutate(newSuiteName.trim())}
          onImportFlows={() => importFlows.mutate()}
          onAddOneSuggested={(t) => addOne.mutate(t)}
          onAddAllSuggested={() => bulkAdd.mutate(suggestedTests)}
          onFuzzSuite={() => fuzzSuite.mutate()}
          isFuzzing={fuzzSuite.isPending}
          fuzzJobId={fuzzSuite.data?.fuzz_job_id ?? null}
        />
      </aside>

      {/* ── Right panel ── */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {!selectedSuite ? (
          <EmptyState onCreateSuite={() => setShowNewSuite(true)} />
        ) : (
          <>
            {/* Tab bar */}
            <div className="flex gap-1 px-4 pt-3 pb-0 border-b border-bg-border bg-bg-base shrink-0">
              {(['tests', 'results', 'fuzzer'] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setActiveTab(t)}
                  className={clsx(
                    'px-3 py-1.5 text-xs rounded-t-md transition-colors capitalize',
                    activeTab === t
                      ? 'bg-bg-base text-zinc-200 border-t border-x border-bg-border'
                      : 'text-zinc-500 hover:text-zinc-300',
                  )}
                >
                  {t}
                  {t === 'results' && selectedTest && (
                    <span className="ml-1.5 text-zinc-600">— {selectedTest.name.slice(0, 20)}</span>
                  )}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-auto p-4">
              {activeTab === 'tests' && (
                <TestsTab
                  suiteId={selectedSuiteId!}
                  tests={tests}
                  selectedTestId={selectedTestId}
                  showNewTest={showNewTest}
                  newTest={newTest}
                  isSubmitting={submitNewTest.isPending}
                  onShowNewTest={() => setShowNewTest(true)}
                  onCancelNewTest={() => setShowNewTest(false)}
                  onNewTestChange={(k, v) => setNewTest(prev => ({ ...prev, [k]: v }))}
                  onSubmitNewTest={() => submitNewTest.mutate()}
                  onSelectTest={(id) => { setSelectedTestId(id); setActiveTab('results') }}
                  onRun={(id) => runTest.mutate(id)}
                  onClear={(id) => clearResults.mutate(id)}
                  onExport={(id) => exportFinding.mutate(id)}
                  isRunning={runTest.isPending}
                />
              )}

              {activeTab === 'results' && (
                <ResultsTab
                  test={selectedTest}
                  results={results}
                  wsLogs={wsLogs}
                  wsWaiting={wsWaiting}
                  expandedResultId={expandedResultId}
                  logsEndRef={logsEndRef}
                  onRerun={() => selectedTestId && runTest.mutate(selectedTestId)}
                  onExpandResult={(id) => setExpandedResultId(prev => prev === id ? null : id)}
                />
              )}

              {activeTab === 'fuzzer' && (
                <FuzzerTab
                  defaultSessionId={selectedSuite?.session_id ?? null}
                  defaultAnalysisId={selectedSuite?.analysis_id ?? null}
                />
              )}
            </div>
          </>
        )}
      </main>
    </div>
  )
}

// ── Left panel component ──────────────────────────────────────────────────────

function LeftPanel({
  suites, selectedSuiteId, selectedSuite, activeSessionId,
  showNewSuite, newSuiteName, suggestedTests,
  isImporting, isBulkAdding,
  onSelectSuite, onShowNewSuite, onCancelNewSuite, onNewSuiteNameChange,
  onCreateSuite, onImportFlows, onAddOneSuggested, onAddAllSuggested,
  onFuzzSuite, isFuzzing, fuzzJobId,
}: {
  suites: ApiTestSuite[]
  selectedSuiteId: number | null
  selectedSuite: ApiTestSuite | null
  activeSessionId: number | null
  showNewSuite: boolean
  newSuiteName: string
  suggestedTests: SuggestedTest[]
  isImporting: boolean
  isBulkAdding: boolean
  onSelectSuite: (id: number) => void
  onShowNewSuite: () => void
  onCancelNewSuite: () => void
  onNewSuiteNameChange: (v: string) => void
  onCreateSuite: () => void
  onImportFlows: () => void
  onAddOneSuggested: (t: SuggestedTest) => void
  onAddAllSuggested: () => void
  onFuzzSuite: () => void
  isFuzzing: boolean
  fuzzJobId: number | null
}) {
  return (
    <div className="flex flex-col h-full overflow-y-auto">
      {/* Header */}
      <div className="px-3 py-3 border-b border-bg-border shrink-0">
        {activeSessionId && (
          <div className="flex items-center gap-1.5 mb-2 px-2 py-1 bg-green-500/10 rounded border border-green-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse shrink-0" />
            <span className="text-xs text-green-400 truncate">Session #{activeSessionId} active</span>
          </div>
        )}
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase tracking-wide text-zinc-500 font-medium">API Testing</span>
          <button
            onClick={onShowNewSuite}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-accent text-white rounded hover:opacity-90 transition-opacity"
          >
            <Plus size={10} />
            New Suite
          </button>
        </div>

        {showNewSuite && (
          <div className="mt-2 space-y-1.5">
            <input
              autoFocus
              value={newSuiteName}
              onChange={e => onNewSuiteNameChange(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') onCreateSuite(); if (e.key === 'Escape') onCancelNewSuite() }}
              placeholder="Suite name…"
              className="w-full px-2 py-1 text-xs bg-bg-elevated border border-bg-border rounded text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-accent"
            />
            <div className="flex gap-1">
              <button onClick={onCreateSuite}
                className="flex-1 px-2 py-1 text-xs bg-accent text-white rounded hover:opacity-90">
                Create
              </button>
              <button onClick={onCancelNewSuite}
                className="flex-1 px-2 py-1 text-xs bg-bg-elevated text-zinc-400 rounded hover:text-zinc-200">
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Suite list */}
      <div className="shrink-0">
        {suites.map((s) => (
          <button
            key={s.id}
            onClick={() => onSelectSuite(s.id)}
            className={clsx(
              'w-full text-left px-3 py-2 border-b border-bg-border transition-colors flex items-start gap-2',
              selectedSuiteId === s.id
                ? 'border-l-2 border-l-accent bg-bg-elevated pl-[10px]'
                : 'hover:bg-bg-elevated',
            )}
          >
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs text-zinc-200 truncate">{s.name}</span>
                {s.status === 'building' && <Loader2 size={10} className="animate-spin text-zinc-500 shrink-0" />}
              </div>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className={clsx(
                  'text-xs px-1 rounded',
                  s.platform === 'ios' ? 'text-blue-400 bg-blue-400/10' : 'text-green-400 bg-green-400/10',
                )}>
                  {s.platform}
                </span>
                {s.target_app && (
                  <span className="text-xs text-zinc-600 truncate">{s.target_app}</span>
                )}
              </div>
            </div>
            <span className="text-xs text-zinc-600 shrink-0 mt-0.5">{s.test_count}t</span>
          </button>
        ))}
      </div>

      {/* Suite context */}
      {selectedSuite && (
        <div className="px-3 py-3 space-y-3 flex-1">
          {/* Stats row */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1 text-xs text-zinc-500">
              <Wifi size={11} />
              <span>{selectedSuite.flow_count} flows</span>
            </div>
            <div className="flex items-center gap-1 text-xs text-zinc-500">
              <Shield size={11} />
              <span>{selectedSuite.auth_contexts.length} token{selectedSuite.auth_contexts.length !== 1 ? 's' : ''}</span>
            </div>
          </div>

          {/* Auth tokens */}
          {selectedSuite.auth_contexts.length > 0 && (
            <div>
              <p className="text-xs text-zinc-600 uppercase tracking-wide mb-1">Auth Contexts</p>
              <div className="space-y-1">
                {selectedSuite.auth_contexts.map((ctx) => (
                  <div key={ctx.id} className="flex items-center gap-2 px-2 py-1.5 bg-bg-elevated rounded border border-bg-border">
                    <div className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0" />
                    <div className="min-w-0">
                      <p className="text-xs text-zinc-300">{ctx.label}</p>
                      <p className="text-xs text-zinc-600 font-mono truncate">{ctx.header_name}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Collected IDs summary */}
          {Object.keys(selectedSuite.collected_ids).length > 0 && (
            <div>
              <p className="text-xs text-zinc-600 uppercase tracking-wide mb-1">Collected IDs</p>
              {Object.entries(selectedSuite.collected_ids).slice(0, 4).map(([pattern, params]) => (
                <div key={pattern} className="px-2 py-1 bg-bg-elevated rounded border border-bg-border mb-1">
                  <p className="text-xs text-zinc-500 font-mono truncate">{pattern.split('/').slice(-2).join('/')}</p>
                  {Object.entries(params).map(([pname, vals]) => (
                    <p key={pname} className="text-xs text-zinc-600">
                      <span className="text-zinc-400">{pname}</span>: {vals.length} value{vals.length !== 1 ? 's' : ''}
                    </p>
                  ))}
                </div>
              ))}
            </div>
          )}

          {/* Build button */}
          <button
            onClick={onImportFlows}
            disabled={isImporting}
            className="w-full flex items-center justify-center gap-1.5 px-2 py-1.5 text-xs border border-bg-border rounded hover:border-accent hover:text-accent text-zinc-400 transition-colors disabled:opacity-50"
          >
            {isImporting ? <Loader2 size={11} className="animate-spin" /> : <RefreshCw size={11} />}
            {isImporting ? 'Building context…' : 'Build from Proxy Flows'}
          </button>

          {/* Fuzz suite */}
          <button
            onClick={onFuzzSuite}
            disabled={isFuzzing || selectedSuite.flow_count === 0}
            className="w-full flex items-center justify-center gap-1.5 px-2 py-1.5 text-xs border border-bg-border rounded hover:border-yellow-500/50 hover:text-yellow-400 text-zinc-400 transition-colors disabled:opacity-50"
          >
            {isFuzzing ? <Loader2 size={11} className="animate-spin" /> : <Zap size={11} />}
            {isFuzzing ? 'Fuzzing…' : fuzzJobId ? `Fuzz job #${fuzzJobId}` : 'Run API Fuzzer'}
          </button>

          {/* Suggested tests */}
          {suggestedTests.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-xs text-zinc-400 uppercase tracking-wide">
                  {suggestedTests.length} Suggested Test{suggestedTests.length !== 1 ? 's' : ''}
                </p>
                <button
                  onClick={onAddAllSuggested}
                  disabled={isBulkAdding}
                  className="text-xs text-accent hover:underline disabled:opacity-50"
                >
                  {isBulkAdding ? 'Adding…' : 'Add All'}
                </button>
              </div>
              <div className="space-y-1 max-h-64 overflow-y-auto">
                {suggestedTests.map((t, i) => (
                  <div key={i} className="flex items-start gap-2 px-2 py-1.5 bg-bg-elevated rounded border border-bg-border group">
                    <div className="flex-1 min-w-0">
                      <p className={clsx(
                        'text-xs font-mono px-1 rounded border inline-block mb-0.5',
                        TEST_TYPE_COLORS[t.test_type] ?? 'text-zinc-400',
                      )}>
                        {TEST_TYPE_LABELS[t.test_type] ?? t.test_type}
                      </p>
                      <p className="text-xs text-zinc-400 truncate">{t.name}</p>
                    </div>
                    <button
                      onClick={() => onAddOneSuggested(t)}
                      className="text-xs text-zinc-600 hover:text-accent shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <Plus size={12} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Tests tab ─────────────────────────────────────────────────────────────────

function TestsTab({
  suiteId, tests, selectedTestId, showNewTest, newTest, isSubmitting,
  onShowNewTest, onCancelNewTest, onNewTestChange, onSubmitNewTest,
  onSelectTest, onRun, onClear, onExport, isRunning,
}: {
  suiteId: number
  tests: ApiTest[]
  selectedTestId: number | null
  showNewTest: boolean
  newTest: { test_type: string; name: string; method: string; url: string; headers: string; config: string }
  isSubmitting: boolean
  onShowNewTest: () => void
  onCancelNewTest: () => void
  onNewTestChange: (k: string, v: string) => void
  onSubmitNewTest: () => void
  onSelectTest: (id: number) => void
  onRun: (id: number) => void
  onClear: (id: number) => void
  onExport: (id: number) => void
  isRunning: boolean
}) {
  return (
    <div className="space-y-3 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-xs text-zinc-400 uppercase tracking-wide">
          {tests.length} Test{tests.length !== 1 ? 's' : ''}
        </h2>
        <button
          onClick={onShowNewTest}
          className="flex items-center gap-1 px-2 py-1 text-xs bg-bg-surface border border-bg-border rounded hover:border-accent hover:text-accent text-zinc-400 transition-colors"
        >
          <Plus size={11} /> New Test
        </button>
      </div>

      {/* New test form */}
      {showNewTest && (
        <div className="bg-bg-surface border border-bg-border rounded-lg p-3 space-y-2">
          <p className="text-xs text-zinc-400 font-medium">New Test</p>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-xs text-zinc-600 block mb-1">Type</label>
              <select
                value={newTest.test_type}
                onChange={e => onNewTestChange('test_type', e.target.value)}
                className="w-full px-2 py-1 text-xs bg-bg-elevated border border-bg-border rounded text-zinc-200 focus:outline-none focus:border-accent"
              >
                <option value="auth_strip">Auth Strip</option>
                <option value="idor_sweep">IDOR Sweep</option>
                <option value="token_replay">Token Replay</option>
                <option value="cross_user_auth">Cross-User Auth</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-zinc-600 block mb-1">Method</label>
              <select
                value={newTest.method}
                onChange={e => onNewTestChange('method', e.target.value)}
                className="w-full px-2 py-1 text-xs bg-bg-elevated border border-bg-border rounded text-zinc-200 focus:outline-none focus:border-accent"
              >
                {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => (
                  <option key={m}>{m}</option>
                ))}
              </select>
            </div>
          </div>
          <input
            value={newTest.name}
            onChange={e => onNewTestChange('name', e.target.value)}
            placeholder="Test name…"
            className="w-full px-2 py-1 text-xs bg-bg-elevated border border-bg-border rounded text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-accent"
          />
          <input
            value={newTest.url}
            onChange={e => onNewTestChange('url', e.target.value)}
            placeholder="https://api.example.com/endpoint?id=123"
            className="w-full px-2 py-1.5 text-xs bg-bg-elevated border border-bg-border rounded text-zinc-300 font-mono placeholder:text-zinc-600 focus:outline-none focus:border-accent"
          />
          <div>
            <label className="text-xs text-zinc-600 block mb-1">Headers (JSON)</label>
            <textarea
              value={newTest.headers}
              onChange={e => onNewTestChange('headers', e.target.value)}
              rows={3}
              className="w-full px-2 py-1 text-xs bg-bg-elevated border border-bg-border rounded text-zinc-300 font-mono focus:outline-none focus:border-accent resize-none"
            />
          </div>
          <div>
            <label className="text-xs text-zinc-600 block mb-1">Config (JSON)</label>
            <textarea
              value={newTest.config}
              onChange={e => onNewTestChange('config', e.target.value)}
              rows={3}
              className="w-full px-2 py-1 text-xs bg-bg-elevated border border-bg-border rounded text-zinc-300 font-mono focus:outline-none focus:border-accent resize-none"
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={onSubmitNewTest}
              disabled={isSubmitting || !newTest.name || !newTest.url}
              className="px-3 py-1 text-xs bg-accent text-white rounded hover:opacity-90 disabled:opacity-50"
            >
              {isSubmitting ? 'Creating…' : 'Create Test'}
            </button>
            <button onClick={onCancelNewTest} className="px-3 py-1 text-xs text-zinc-400 hover:text-zinc-200">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Test list */}
      {tests.length === 0 ? (
        <div className="text-center py-12 text-zinc-600 text-sm">
          <Terminal size={24} className="mx-auto mb-3 opacity-30" />
          <p>No tests yet.</p>
          <p className="text-xs mt-1">Build from proxy flows to auto-detect test cases, or create one manually.</p>
        </div>
      ) : (
        <div className="space-y-1">
          {tests.map((test) => (
            <TestRow
              key={test.id}
              test={test}
              isSelected={test.id === selectedTestId}
              onClick={() => onSelectTest(test.id)}
              onRun={() => onRun(test.id)}
              onClear={() => onClear(test.id)}
              onExport={() => onExport(test.id)}
              isRunning={isRunning && test.status === 'running'}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function TestRow({
  test, isSelected, onClick, onRun, onClear, onExport, isRunning,
}: {
  test: ApiTest
  isSelected: boolean
  onClick: () => void
  onRun: () => void
  onClear: () => void
  onExport: () => void
  isRunning: boolean
}) {
  return (
    <div
      className={clsx(
        'flex items-center gap-3 px-3 py-2 rounded border cursor-pointer group transition-colors',
        isSelected
          ? 'bg-bg-elevated border-accent/40'
          : 'bg-bg-surface border-bg-border hover:bg-bg-elevated',
        test.vulnerable_count > 0 && 'border-l-2 border-l-red-500',
      )}
      onClick={onClick}
    >
      {/* Status stripe */}
      <div className="flex items-center gap-1.5 shrink-0">
        {statusIcon(test.status)}
      </div>

      {/* Type badge */}
      <span className={clsx(
        'text-xs font-mono px-1.5 py-0.5 rounded border shrink-0',
        TEST_TYPE_COLORS[test.test_type] ?? 'text-zinc-400 border-zinc-700',
      )}>
        {TEST_TYPE_LABELS[test.test_type] ?? test.test_type}
      </span>

      {/* Name */}
      <span className="text-xs text-zinc-300 flex-1 truncate">{test.name}</span>

      {/* Run count */}
      {test.run_count > 0 && (
        <span className="text-xs text-zinc-600 shrink-0">{test.run_count}×</span>
      )}

      {/* Vulnerable count */}
      {test.vulnerable_count > 0 && (
        <div className="flex items-center gap-1 text-red-400 shrink-0">
          <AlertTriangle size={11} />
          <span className="text-xs font-medium">{test.vulnerable_count}</span>
        </div>
      )}

      {/* Actions */}
      <div
        className="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
        onClick={e => e.stopPropagation()}
      >
        <button
          onClick={onRun}
          disabled={isRunning || test.status === 'running'}
          title="Run test"
          className="p-1 rounded hover:bg-bg-base text-zinc-500 hover:text-green-400 disabled:opacity-40 transition-colors"
        >
          {test.status === 'running'
            ? <Loader2 size={12} className="animate-spin" />
            : <Play size={12} />}
        </button>
        {test.result_count > 0 && (
          <button
            onClick={onClear}
            title="Clear results"
            className="p-1 rounded hover:bg-bg-base text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            <Trash2 size={12} />
          </button>
        )}
        {test.vulnerable_count > 0 && (
          <button
            onClick={onExport}
            title="Export as finding"
            className="p-1 rounded hover:bg-bg-base text-zinc-500 hover:text-accent transition-colors"
          >
            <Upload size={12} />
          </button>
        )}
      </div>
    </div>
  )
}

// ── Results tab ───────────────────────────────────────────────────────────────

function ResultsTab({
  test, results, wsLogs, wsWaiting, expandedResultId, logsEndRef,
  onRerun, onExpandResult,
}: {
  test: ApiTest | null
  results: ApiTestResult[]
  wsLogs: WsTestEvent[]
  wsWaiting: boolean
  expandedResultId: number | null
  logsEndRef: RefObject<HTMLDivElement>
  onRerun: () => void
  onExpandResult: (id: number) => void
}) {
  if (!test) {
    return (
      <div className="flex items-center justify-center h-48 text-zinc-600 text-sm">
        Select a test from the Tests tab to view results.
      </div>
    )
  }

  return (
    <div className="space-y-4 max-w-5xl">
      {/* Test header */}
      <div className="flex items-center gap-3">
        <span className={clsx(
          'text-xs font-mono px-1.5 py-0.5 rounded border',
          TEST_TYPE_COLORS[test.test_type] ?? 'text-zinc-400 border-zinc-700',
        )}>
          {TEST_TYPE_LABELS[test.test_type] ?? test.test_type}
        </span>
        <h2 className="text-sm text-zinc-200 font-medium">{test.name}</h2>
        <div className={clsx('flex items-center gap-1 text-xs', STATUS_STYLES[test.status] ?? 'text-zinc-400')}>
          {statusIcon(test.status)}
          <span className="capitalize">{test.status}</span>
        </div>
        <button
          onClick={onRerun}
          disabled={test.status === 'running'}
          className="ml-auto flex items-center gap-1 px-2 py-1 text-xs border border-bg-border rounded hover:border-green-500/50 hover:text-green-400 text-zinc-500 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={11} className={test.status === 'running' ? 'animate-spin' : ''} />
          Re-run
        </button>
      </div>

      {/* Description */}
      {test.description && (
        <p className="text-xs text-zinc-500 leading-relaxed">{test.description}</p>
      )}

      {/* Waiting banner */}
      {wsWaiting && (
        <div className="flex items-start gap-2 px-3 py-2.5 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
          <AlertTriangle size={14} className="text-yellow-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-xs text-yellow-300 font-medium">Action required</p>
            <p className="text-xs text-yellow-400/80 mt-0.5">
              Log out of the app now. The test will automatically continue and replay the captured token to check for server-side invalidation.
            </p>
          </div>
        </div>
      )}

      {/* Live log */}
      {wsLogs.length > 0 && (
        <div className="bg-bg-surface border border-bg-border rounded-lg overflow-hidden">
          <div className="px-3 py-1.5 border-b border-bg-border flex items-center gap-2">
            <Terminal size={11} className="text-zinc-600" />
            <span className="text-xs text-zinc-500">Live output</span>
            {test.status === 'running' && <Loader2 size={10} className="animate-spin text-blue-400 ml-auto" />}
          </div>
          <div className="max-h-40 overflow-y-auto px-3 py-2 space-y-0.5 font-mono">
            {wsLogs.filter(l => l.type !== 'ping').map((log, i) => (
              <div key={i} className={clsx('text-xs leading-relaxed', {
                'text-zinc-400': log.type === 'progress',
                'text-red-400': log.type === 'error',
                'text-yellow-400': log.type === 'waiting',
                'text-green-400 font-medium': log.type === 'result' && log.vulnerable,
                'text-blue-400': log.type === 'result' && !log.vulnerable,
                'text-zinc-600': log.type === 'done',
              })}>
                {log.type === 'result' && (
                  <span className="mr-2">
                    [{log.label}] HTTP {log.status ?? '—'}
                    {log.vulnerable && ' ⚠ VULNERABLE'}
                  </span>
                )}
                {(log.type !== 'result') && (log.message ?? '')}
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>
      )}

      {/* Results list */}
      {results.length === 0 && test.status !== 'running' ? (
        <div className="text-center py-8 text-zinc-600 text-xs">
          No results yet. Click Re-run to execute this test.
        </div>
      ) : (
        <div className="space-y-1">
          {results.map((r) => (
            <ResultRow
              key={r.id}
              result={r}
              isExpanded={expandedResultId === r.id}
              onToggle={() => onExpandResult(r.id)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function ResultRow({
  result, isExpanded, onToggle,
}: {
  result: ApiTestResult
  isExpanded: boolean
  onToggle: () => void
}) {
  return (
    <div className={clsx(
      'border rounded-lg overflow-hidden',
      result.is_vulnerable ? 'border-red-500/40' : 'border-bg-border',
    )}>
      {/* Row header */}
      <div
        className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-bg-elevated transition-colors bg-bg-surface"
        onClick={onToggle}
      >
        {isExpanded
          ? <ChevronDown size={12} className="text-zinc-500 shrink-0" />
          : <ChevronRight size={12} className="text-zinc-500 shrink-0" />}

        {/* Label */}
        <span className="text-xs font-mono text-zinc-400 w-48 truncate shrink-0">{result.label ?? '—'}</span>

        {/* Method */}
        <span className="text-xs font-mono text-zinc-500 shrink-0">{result.request_method}</span>

        {/* Status */}
        <span className={clsx('text-xs font-mono font-medium shrink-0', httpStatusColor(result.response_status))}>
          {result.response_status ?? '—'}
        </span>

        {/* Duration */}
        {result.duration_ms != null && (
          <span className="text-xs text-zinc-600 shrink-0">{result.duration_ms}ms</span>
        )}

        {/* Vulnerable */}
        {result.is_vulnerable && (
          <div className="flex items-center gap-1 text-red-400 ml-auto shrink-0">
            <AlertTriangle size={11} />
            <span className="text-xs font-medium">Vulnerable</span>
            {result.severity && (
              <Badge variant="severity" value={result.severity} className="ml-1" />
            )}
          </div>
        )}

        {/* Finding snippet */}
        {result.finding && !result.is_vulnerable && (
          <span className="text-xs text-zinc-600 ml-auto truncate max-w-48 shrink-0">{result.finding}</span>
        )}
      </div>

      {/* Expanded detail */}
      {isExpanded && (
        <div className="border-t border-bg-border">
          {/* Finding */}
          {result.finding && (
            <div className={clsx(
              'px-3 py-2 text-xs border-b border-bg-border',
              result.is_vulnerable ? 'text-red-300 bg-red-500/5' : 'text-zinc-400',
            )}>
              {result.finding}
            </div>
          )}

          {/* Diff summary */}
          {result.diff_summary && (
            <div className="px-3 py-1.5 text-xs text-zinc-600 border-b border-bg-border bg-bg-base">
              ↕ {result.diff_summary}
            </div>
          )}

          {/* Request / Response split */}
          <div className="grid grid-cols-2 divide-x divide-bg-border">
            {/* Request */}
            <div className="p-3 space-y-2">
              <p className="text-xs text-zinc-600 uppercase tracking-wide">Request</p>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-medium text-zinc-400">{result.request_method}</span>
                <span className="text-xs font-mono text-zinc-500 break-all">{result.request_url}</span>
              </div>
              {Object.keys(result.request_headers).length > 0 && (
                <div className="space-y-0.5 max-h-32 overflow-y-auto">
                  {Object.entries(result.request_headers).map(([k, v]) => (
                    <div key={k} className="flex gap-2 text-xs">
                      <span className="text-zinc-600 shrink-0 w-36 truncate">{k}</span>
                      <span className="text-zinc-500 truncate font-mono">{String(v).slice(0, 60)}</span>
                    </div>
                  ))}
                </div>
              )}
              {result.request_body && (
                <pre className="text-xs font-mono text-zinc-500 bg-bg-base p-2 rounded max-h-24 overflow-auto whitespace-pre-wrap break-all">
                  {result.request_body.slice(0, 500)}
                </pre>
              )}
            </div>

            {/* Response */}
            <div className="p-3 space-y-2">
              <p className="text-xs text-zinc-600 uppercase tracking-wide">Response</p>
              <div className="flex items-center gap-2">
                <span className={clsx('text-xs font-mono font-semibold', httpStatusColor(result.response_status))}>
                  HTTP {result.response_status ?? '—'}
                </span>
                {result.duration_ms != null && (
                  <span className="text-xs text-zinc-600">{result.duration_ms}ms</span>
                )}
              </div>
              {Object.keys(result.response_headers).length > 0 && (
                <div className="space-y-0.5 max-h-24 overflow-y-auto">
                  {Object.entries(result.response_headers).slice(0, 10).map(([k, v]) => (
                    <div key={k} className="flex gap-2 text-xs">
                      <span className="text-zinc-600 shrink-0 w-36 truncate">{k}</span>
                      <span className="text-zinc-500 truncate font-mono">{String(v).slice(0, 60)}</span>
                    </div>
                  ))}
                </div>
              )}
              {result.response_body && (
                <pre className={clsx(
                  'text-xs font-mono p-2 rounded max-h-48 overflow-auto whitespace-pre-wrap break-all',
                  result.is_vulnerable ? 'text-red-300 bg-red-500/5' : 'text-zinc-400 bg-bg-base',
                )}>
                  {(() => {
                    try {
                      return JSON.stringify(JSON.parse(result.response_body), null, 2).slice(0, 2000)
                    } catch {
                      return result.response_body.slice(0, 2000)
                    }
                  })()}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Fuzzer tab ────────────────────────────────────────────────────────────────

const ALL_ATTACKS = ['idor', 'verb_tampering', 'auth_bypass', 'rate_limit'] as const
type AttackType = typeof ALL_ATTACKS[number]

const ATTACK_LABELS: Record<AttackType, string> = {
  idor: 'IDOR',
  verb_tampering: 'Verb Tampering',
  auth_bypass: 'Auth Bypass Headers',
  rate_limit: 'Rate Limit Detection',
}

const JOB_STATUS_COLORS: Record<string, string> = {
  pending: 'text-zinc-400',
  running: 'text-blue-400',
  complete: 'text-green-400',
  error: 'text-red-400',
}

function FuzzResultRow({ r }: { r: FuzzResult }) {
  const [open, setOpen] = useState(false)
  return (
    <div className={clsx('border-b border-bg-border last:border-0', r.is_interesting && 'bg-yellow-900/10')}>
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-3 px-4 py-2 hover:bg-bg-elevated text-left"
      >
        {open ? <ChevronDown size={12} className="text-zinc-500 shrink-0" /> : <ChevronRight size={12} className="text-zinc-500 shrink-0" />}
        {r.is_interesting && <AlertTriangle size={12} className="text-yellow-400 shrink-0" />}
        <span className="text-xs font-mono text-zinc-400 w-16 shrink-0">{r.method}</span>
        <span className="text-xs font-mono text-zinc-300 flex-1 truncate">{r.url}</span>
        <span className="text-xs px-1.5 py-0.5 bg-bg-elevated rounded text-zinc-500 shrink-0">{r.attack_type}</span>
        <span className={clsx('text-xs w-10 text-right shrink-0 font-mono',
          r.response_status && r.response_status >= 500 ? 'text-red-400' :
          r.response_status && r.response_status >= 400 ? 'text-orange-400' : 'text-zinc-400'
        )}>
          {r.response_status ?? '—'}
        </span>
      </button>
      {open && (
        <div className="px-8 pb-3 text-xs text-zinc-400 space-y-1">
          {r.notes && <p className="text-yellow-300">{r.notes}</p>}
          {r.response_body && (
            <pre className="bg-bg-elevated rounded p-2 text-zinc-400 overflow-auto max-h-24 whitespace-pre-wrap break-all text-xs">
              {r.response_body}
            </pre>
          )}
          <p className="text-zinc-600">{r.duration_ms?.toFixed(0)}ms</p>
        </div>
      )}
    </div>
  )
}

function FuzzJobRow({ job }: { job: FuzzJob }) {
  const [open, setOpen] = useState(false)
  const qc = useQueryClient()

  const { data: detail } = useQuery<FuzzJobDetail>({
    queryKey: ['fuzz-job', job.id],
    queryFn: () => fuzzingApi.getJob(job.id),
    enabled: open,
  })

  const del = useMutation({
    mutationFn: () => fuzzingApi.deleteJob(job.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fuzz-jobs'] }),
  })

  const wsUrl = job.status === 'running' ? `/ws/fuzzing/${job.id}` : null
  const { lastMessage } = useWebSocket(wsUrl)
  useEffect(() => {
    if (lastMessage) qc.invalidateQueries({ queryKey: ['fuzz-job', job.id] })
  }, [lastMessage, qc, job.id])

  const interesting = detail?.results.filter(r => r.is_interesting).length ?? 0

  return (
    <div className="border border-bg-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-3 px-3 py-2.5 bg-bg-surface">
        <button onClick={() => setOpen(v => !v)} className="text-zinc-500 hover:text-zinc-200 shrink-0">
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </button>
        <span className={clsx('text-xs font-medium capitalize shrink-0', JOB_STATUS_COLORS[job.status] ?? 'text-zinc-400')}>
          {job.status === 'running' && <Loader2 size={10} className="inline animate-spin mr-1" />}
          {job.status}
        </span>
        <span className="text-xs text-zinc-500 shrink-0">{job.endpoint_count} endpoints</span>
        <span className="text-xs text-zinc-600 truncate flex-1">{new Date(job.created_at).toLocaleString()}</span>
        {interesting > 0 && (
          <span className="text-xs px-1.5 py-0.5 bg-yellow-900/40 text-yellow-400 rounded shrink-0">
            {interesting} interesting
          </span>
        )}
        <button
          onClick={() => del.mutate()}
          disabled={del.isPending}
          className="text-zinc-600 hover:text-red-400 shrink-0 transition-colors"
        >
          <Trash2 size={12} />
        </button>
      </div>
      {open && detail && (
        <div className="bg-bg-elevated divide-y divide-bg-border">
          {detail.results.length === 0 ? (
            <p className="px-4 py-3 text-xs text-zinc-500">No results yet…</p>
          ) : (
            detail.results.map(r => <FuzzResultRow key={r.id} r={r} />)
          )}
        </div>
      )}
    </div>
  )
}

function FuzzerTab({
  defaultSessionId,
  defaultAnalysisId,
}: {
  defaultSessionId: number | null
  defaultAnalysisId: number | null
}) {
  const qc = useQueryClient()
  const [sessionId, setSessionId] = useState(defaultSessionId ? String(defaultSessionId) : '')
  const [analysisId, setAnalysisId] = useState(defaultAnalysisId ? String(defaultAnalysisId) : '')
  const [baseUrl, setBaseUrl] = useState('')
  const [filter, setFilter] = useState('')
  const [attacks, setAttacks] = useState<Set<AttackType>>(new Set(ALL_ATTACKS))

  // Sync defaults when suite selection changes
  useEffect(() => {
    setSessionId(defaultSessionId ? String(defaultSessionId) : '')
  }, [defaultSessionId])
  useEffect(() => {
    setAnalysisId(defaultAnalysisId ? String(defaultAnalysisId) : '')
  }, [defaultAnalysisId])

  const { data: jobs = [] } = useQuery<FuzzJob[]>({
    queryKey: ['fuzz-jobs'],
    queryFn: () => fuzzingApi.listJobs(),
    refetchInterval: (query) =>
      (query.state.data as FuzzJob[] | undefined)?.some(j => j.status === 'running') ? 3000 : false,
  })

  const create = useMutation({
    mutationFn: () => fuzzingApi.createJob({
      session_id: sessionId ? Number(sessionId) : undefined,
      analysis_id: analysisId ? Number(analysisId) : undefined,
      attacks: Array.from(attacks),
      endpoint_filter: filter || undefined,
      base_url: baseUrl || undefined,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fuzz-jobs'] }),
  })

  function toggleAttack(a: AttackType) {
    setAttacks(prev => {
      const next = new Set(prev)
      next.has(a) ? next.delete(a) : next.add(a)
      return next
    })
  }

  return (
    <div className="space-y-4 max-w-4xl">
      <div className="flex items-center gap-2">
        <Crosshair size={14} className="text-accent" />
        <h2 className="text-sm font-medium text-zinc-200">API Fuzzer</h2>
        <span className="text-xs text-zinc-600">— verb tampering, IDOR, auth bypass, rate limiting</span>
      </div>

      {/* Job creator */}
      <div className="bg-bg-surface rounded-lg border border-bg-border p-4 space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Session ID</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-accent"
              placeholder="Session ID (proxy flows)"
              value={sessionId}
              onChange={e => setSessionId(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Analysis ID</label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-accent"
              placeholder="Analysis ID (static endpoints)"
              value={analysisId}
              onChange={e => setAnalysisId(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Base URL <span className="text-zinc-600">(for static)</span></label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-accent font-mono"
              placeholder="https://api.example.com"
              value={baseUrl}
              onChange={e => setBaseUrl(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">URL Filter <span className="text-zinc-600">(regex)</span></label>
            <input
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-accent font-mono"
              placeholder="/api/v1/.*"
              value={filter}
              onChange={e => setFilter(e.target.value)}
            />
          </div>
        </div>

        {/* Attack types */}
        <div>
          <label className="text-xs text-zinc-500 mb-2 block">Attack Types</label>
          <div className="flex gap-4 flex-wrap">
            {ALL_ATTACKS.map(a => (
              <label key={a} className="flex items-center gap-1.5 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={attacks.has(a)}
                  onChange={() => toggleAttack(a)}
                  className="accent-accent"
                />
                <span className="text-xs text-zinc-400 group-hover:text-zinc-200 transition-colors">{ATTACK_LABELS[a]}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => create.mutate()}
            disabled={create.isPending || (!sessionId && !analysisId)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:opacity-90 disabled:opacity-50 rounded text-xs text-white transition-opacity"
          >
            <Play size={11} />
            {create.isPending ? 'Starting…' : 'Start Fuzz Job'}
          </button>
          {create.isError && (
            <p className="text-xs text-red-400">{(create.error as Error).message}</p>
          )}
        </div>
      </div>

      {/* Jobs list */}
      <div className="space-y-2">
        {jobs.length === 0 ? (
          <p className="text-xs text-zinc-600 py-4 text-center">No fuzz jobs yet. Enter a session or analysis ID above to start.</p>
        ) : (
          jobs.map(j => <FuzzJobRow key={j.id} job={j} />)
        )}
      </div>
    </div>
  )
}

// ── Empty state ───────────────────────────────────────────────────────────────

function EmptyState({ onCreateSuite }: { onCreateSuite: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center h-full text-center px-8">
      <Shield size={32} className="text-zinc-700 mb-4" />
      <h2 className="text-sm text-zinc-400 font-medium mb-1">No suite selected</h2>
      <p className="text-xs text-zinc-600 mb-4 max-w-xs leading-relaxed">
        Create a test suite to start detecting IDOR, auth bypass, token replay, and cross-user authorization vulnerabilities.
      </p>
      <button
        onClick={onCreateSuite}
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-accent text-white rounded hover:opacity-90"
      >
        <Plus size={12} /> Create Suite
      </button>
    </div>
  )
}

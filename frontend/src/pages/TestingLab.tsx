import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  FlaskConical, Plus, Trash2, ChevronDown, ChevronRight, Loader2,
  AlertCircle, CheckCircle2, XCircle, BarChart2, Terminal, Save
} from 'lucide-react'
import { clsx } from 'clsx'
import { testingApi } from '@/api/testing'
import { analysisApi } from '@/api/analysis'
import { owaspApi } from '@/api/owasp'
import type { TestApp, TestRun, ReproductionStep } from '@/types/testing'

type Tab = 'apps' | 'runs' | 'accuracy'

export default function TestingLab() {
  const [tab, setTab] = useState<Tab>('apps')

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Tab bar */}
      <div className="flex items-center gap-1 px-4 py-2 border-b border-bg-border bg-bg-surface shrink-0">
        <FlaskConical size={16} className="text-accent mr-2" />
        <h2 className="text-sm font-semibold text-zinc-200 mr-4">Testing Lab</h2>
        {(['apps', 'runs', 'accuracy'] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={clsx(
              'px-3 py-1.5 text-xs rounded transition-colors capitalize',
              tab === t ? 'bg-accent/20 text-accent' : 'text-zinc-500 hover:text-zinc-200 hover:bg-bg-elevated'
            )}
          >
            {t === 'accuracy' ? 'Accuracy Dashboard' : t === 'apps' ? 'Test Apps' : 'Test Runs'}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-hidden">
        {tab === 'apps' && <AppsTab />}
        {tab === 'runs' && <RunsTab />}
        {tab === 'accuracy' && <AccuracyTab />}
      </div>
    </div>
  )
}

/* ──────────────── Apps Tab ──────────────── */

function AppsTab() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    display_name: '', package_name: '', apk_path: '', category: '', description: '', is_vulnerable_app: false
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedApp, setSelectedApp] = useState<number | null>(null)

  const { data: apps = [], isLoading } = useQuery({
    queryKey: ['test-apps'],
    queryFn: () => testingApi.listApps(),
  })

  const { data: appDetail } = useQuery({
    queryKey: ['test-app', selectedApp],
    queryFn: () => testingApi.getApp(selectedApp!),
    enabled: !!selectedApp,
  })

  const handleCreate = async () => {
    if (!form.display_name || !form.package_name) {
      setError('Display name and package name are required')
      return
    }
    setSaving(true)
    setError(null)
    try {
      await testingApi.createApp({
        display_name: form.display_name,
        package_name: form.package_name,
        apk_path: form.apk_path || undefined,
        category: form.category || undefined,
        description: form.description || undefined,
        is_vulnerable_app: form.is_vulnerable_app,
      })
      qc.invalidateQueries({ queryKey: ['test-apps'] })
      setShowForm(false)
      setForm({ display_name: '', package_name: '', apk_path: '', category: '', description: '', is_vulnerable_app: false })
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? e?.message ?? 'Failed to create app')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id: number) => {
    await testingApi.deleteApp(id)
    qc.invalidateQueries({ queryKey: ['test-apps'] })
    if (selectedApp === id) setSelectedApp(null)
  }

  return (
    <div className="flex h-full overflow-hidden">
      {/* Left list */}
      <div className="w-72 shrink-0 border-r border-bg-border flex flex-col bg-bg-surface">
        <div className="p-3 border-b border-bg-border flex items-center justify-between">
          <span className="text-xs text-zinc-400">{apps.length} apps</span>
          <button
            onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-1 text-xs text-accent hover:text-accent/80 px-2 py-1 rounded hover:bg-bg-elevated"
          >
            <Plus size={12} /> New App
          </button>
        </div>

        {showForm && (
          <div className="p-3 border-b border-bg-border space-y-2">
            <input className={inputCls} placeholder="Display name *" value={form.display_name}
              onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))} />
            <input className={inputCls} placeholder="Package name *" value={form.package_name}
              onChange={(e) => setForm((f) => ({ ...f, package_name: e.target.value }))} />
            <input className={inputCls} placeholder="APK path (optional)" value={form.apk_path}
              onChange={(e) => setForm((f) => ({ ...f, apk_path: e.target.value }))} />
            <input className={inputCls} placeholder="Category (e.g. finance, health)" value={form.category}
              onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))} />
            <textarea className={`${inputCls} h-16 resize-none`} placeholder="Description" value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />
            <label className="flex items-center gap-2 text-xs text-zinc-400 cursor-pointer">
              <input type="checkbox" className="accent-accent" checked={form.is_vulnerable_app}
                onChange={(e) => setForm((f) => ({ ...f, is_vulnerable_app: e.target.checked }))} />
              Vulnerable benchmark app
            </label>
            {error && <p className="text-xs text-red-400">{error}</p>}
            <div className="flex gap-2">
              <button onClick={handleCreate} disabled={saving}
                className="flex-1 py-1.5 text-xs bg-accent/20 text-accent rounded hover:bg-accent/30 disabled:opacity-40">
                {saving ? <Loader2 size={12} className="animate-spin mx-auto" /> : 'Save'}
              </button>
              <button onClick={() => setShowForm(false)} className="px-3 py-1.5 text-xs text-zinc-500 hover:text-zinc-200 rounded hover:bg-bg-elevated">
                Cancel
              </button>
            </div>
          </div>
        )}

        <div className="flex-1 overflow-auto">
          {isLoading && <div className="flex justify-center pt-8"><Loader2 className="animate-spin text-accent" /></div>}
          {!isLoading && apps.length === 0 && <p className="text-xs text-zinc-600 p-4 text-center">No apps registered</p>}
          {apps.map((app) => (
            <div
              key={app.id}
              onClick={() => setSelectedApp(app.id)}
              className={clsx(
                'px-3 py-2.5 border-b border-bg-border cursor-pointer hover:bg-bg-elevated transition-colors',
                selectedApp === app.id && 'bg-bg-elevated border-l-2 border-l-accent'
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-zinc-200 truncate">{app.display_name}</p>
                  <p className="text-[10px] text-zinc-500 font-mono truncate">{app.package_name}</p>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  {app.is_vulnerable_app && (
                    <span className="text-[10px] px-1 rounded bg-orange-500/10 text-orange-400 border border-orange-500/30">vuln</span>
                  )}
                  {app.category && (
                    <span className="text-[10px] px-1 rounded bg-zinc-700/50 text-zinc-400">{app.category}</span>
                  )}
                  <button onClick={(e) => { e.stopPropagation(); handleDelete(app.id) }}
                    className="p-0.5 text-zinc-600 hover:text-red-400 transition-colors">
                    <Trash2 size={11} />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Right — app detail + runs */}
      <div className="flex-1 overflow-auto p-4">
        {!selectedApp ? (
          <div className="flex flex-col items-center justify-center h-48 text-zinc-600 gap-2">
            <FlaskConical size={24} />
            <p className="text-sm">Select an app to view its test runs</p>
          </div>
        ) : !appDetail ? (
          <div className="flex justify-center pt-8"><Loader2 className="animate-spin text-accent" /></div>
        ) : (
          <AppDetail app={appDetail} runs={appDetail.runs ?? []} />
        )}
      </div>
    </div>
  )
}

function AppDetail({ app, runs }: { app: TestApp; runs: TestRun[] }) {
  return (
    <div className="space-y-4 max-w-3xl">
      <div className="bg-bg-surface rounded border border-bg-border p-4">
        <div className="flex items-start justify-between">
          <div>
            <h3 className="text-sm font-semibold text-zinc-200">{app.display_name}</h3>
            <p className="text-xs font-mono text-zinc-500 mt-0.5">{app.package_name}</p>
            {app.description && <p className="text-xs text-zinc-400 mt-2 leading-relaxed">{app.description}</p>}
          </div>
          <div className="flex flex-col items-end gap-1 shrink-0 ml-4">
            {app.is_vulnerable_app && (
              <span className="text-xs px-2 py-0.5 rounded border bg-orange-500/10 text-orange-400 border-orange-500/30">
                Vulnerable App
              </span>
            )}
            {app.category && (
              <span className="text-xs px-2 py-0.5 rounded bg-zinc-700/50 text-zinc-400">{app.category}</span>
            )}
          </div>
        </div>
        {app.apk_path && (
          <p className="text-[10px] font-mono text-zinc-600 mt-3 truncate">{app.apk_path}</p>
        )}
      </div>

      <div>
        <h4 className="text-xs font-semibold text-zinc-400 uppercase mb-2">Test Runs ({runs.length})</h4>
        {runs.length === 0 ? (
          <p className="text-xs text-zinc-600">No runs yet. Create a run from the Test Runs tab.</p>
        ) : (
          <div className="space-y-2">
            {runs.map((r) => <RunSummaryCard key={r.id} run={r} />)}
          </div>
        )}
      </div>
    </div>
  )
}

/* ──────────────── Runs Tab ──────────────── */

function RunsTab() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [selectedRun, setSelectedRun] = useState<number | null>(null)
  const [runTab, setRunTab] = useState<'details' | 'reproduction' | 'accuracy'>('details')
  const [form, setForm] = useState({
    test_app_id: '',
    analysis_id: '',
    owasp_scan_id: '',
    frida_script_name: '',
    frida_script_source: '',
    notes: '',
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [accuracyEdit, setAccuracyEdit] = useState({ tp: '', fp: '', fn: '', notes: '' })
  const [savingAccuracy, setSavingAccuracy] = useState(false)

  const { data: apps = [] } = useQuery({ queryKey: ['test-apps'], queryFn: () => testingApi.listApps() })
  const { data: analyses = [] } = useQuery({ queryKey: ['analyses-list'], queryFn: () => analysisApi.list() })
  const { data: owaspScans = [] } = useQuery({ queryKey: ['owasp-scans'], queryFn: () => owaspApi.list() })

  // Fetch all runs by loading per-app data — or list directly if endpoint exists
  // We'll aggregate from all apps
  const { data: allRuns = [], refetch: refetchRuns } = useQuery({
    queryKey: ['all-test-runs', apps.map((a) => a.id)],
    queryFn: async () => {
      const results = await Promise.all(apps.map((a) => testingApi.getApp(a.id)))
      return results.flatMap((r) => r.runs ?? [])
    },
    enabled: apps.length > 0,
  })

  const { data: runDetail, refetch: refetchRun } = useQuery({
    queryKey: ['test-run', selectedRun],
    queryFn: () => testingApi.getRun(selectedRun!),
    enabled: !!selectedRun,
  })

  const handleCreateRun = async () => {
    if (!form.test_app_id) { setError('Select a test app'); return }
    setSaving(true)
    setError(null)
    try {
      const run = await testingApi.createRun({
        test_app_id: Number(form.test_app_id),
        analysis_id: form.analysis_id ? Number(form.analysis_id) : undefined,
        owasp_scan_id: form.owasp_scan_id ? Number(form.owasp_scan_id) : undefined,
        frida_script_name: form.frida_script_name || undefined,
        frida_script_source: form.frida_script_source || undefined,
        notes: form.notes || undefined,
      })
      await refetchRuns()
      setSelectedRun(run.id)
      setShowForm(false)
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? e?.message ?? 'Failed to create run')
    } finally {
      setSaving(false)
    }
  }

  const handleDeleteRun = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation()
    await testingApi.deleteRun(id)
    refetchRuns()
    if (selectedRun === id) setSelectedRun(null)
  }

  const handleSaveAccuracy = async () => {
    if (!selectedRun) return
    setSavingAccuracy(true)
    try {
      await testingApi.updateAccuracy(
        selectedRun,
        Number(accuracyEdit.tp) || 0,
        Number(accuracyEdit.fp) || 0,
        Number(accuracyEdit.fn) || 0,
        accuracyEdit.notes || undefined
      )
      await refetchRun()
      qc.invalidateQueries({ queryKey: ['testing-accuracy'] })
    } finally {
      setSavingAccuracy(false)
    }
  }

  return (
    <div className="flex h-full overflow-hidden">
      {/* Left list */}
      <div className="w-72 shrink-0 border-r border-bg-border flex flex-col bg-bg-surface">
        <div className="p-3 border-b border-bg-border flex items-center justify-between">
          <span className="text-xs text-zinc-400">{allRuns.length} runs</span>
          <button
            onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-1 text-xs text-accent hover:text-accent/80 px-2 py-1 rounded hover:bg-bg-elevated"
          >
            <Plus size={12} /> New Run
          </button>
        </div>

        {showForm && (
          <div className="p-3 border-b border-bg-border space-y-2 max-h-96 overflow-auto">
            <label className="block text-xs text-zinc-500 mb-0.5">Test App *</label>
            <select className={inputCls} value={form.test_app_id}
              onChange={(e) => setForm((f) => ({ ...f, test_app_id: e.target.value }))}>
              <option value="">— select —</option>
              {apps.map((a) => <option key={a.id} value={a.id}>{a.display_name}</option>)}
            </select>
            <label className="block text-xs text-zinc-500 mb-0.5">Static Analysis</label>
            <select className={inputCls} value={form.analysis_id}
              onChange={(e) => setForm((f) => ({ ...f, analysis_id: e.target.value }))}>
              <option value="">— none —</option>
              {(analyses as any[]).map((a: any) => <option key={a.id} value={a.id}>{a.package_name ?? `#${a.id}`}</option>)}
            </select>
            <label className="block text-xs text-zinc-500 mb-0.5">OWASP Scan</label>
            <select className={inputCls} value={form.owasp_scan_id}
              onChange={(e) => setForm((f) => ({ ...f, owasp_scan_id: e.target.value }))}>
              <option value="">— none —</option>
              {owaspScans.map((s) => <option key={s.id} value={s.id}>{s.package_name ?? `Scan #${s.id}`}</option>)}
            </select>
            <input className={inputCls} placeholder="Frida script name (optional)" value={form.frida_script_name}
              onChange={(e) => setForm((f) => ({ ...f, frida_script_name: e.target.value }))} />
            <textarea className={`${inputCls} h-16 resize-none font-mono`} placeholder="Frida script source (optional)"
              value={form.frida_script_source}
              onChange={(e) => setForm((f) => ({ ...f, frida_script_source: e.target.value }))} />
            <textarea className={`${inputCls} h-12 resize-none`} placeholder="Notes" value={form.notes}
              onChange={(e) => setForm((f) => ({ ...f, notes: e.target.value }))} />
            {error && <p className="text-xs text-red-400">{error}</p>}
            <div className="flex gap-2">
              <button onClick={handleCreateRun} disabled={saving}
                className="flex-1 py-1.5 text-xs bg-accent/20 text-accent rounded hover:bg-accent/30 disabled:opacity-40">
                {saving ? <Loader2 size={12} className="animate-spin mx-auto" /> : 'Create Run'}
              </button>
              <button onClick={() => setShowForm(false)} className="px-3 py-1.5 text-xs text-zinc-500 hover:text-zinc-200 rounded hover:bg-bg-elevated">
                Cancel
              </button>
            </div>
          </div>
        )}

        <div className="flex-1 overflow-auto">
          {allRuns.length === 0 && <p className="text-xs text-zinc-600 p-4 text-center">No runs yet</p>}
          {allRuns.map((run) => {
            const app = apps.find((a) => a.id === run.test_app_id)
            return (
              <div
                key={run.id}
                onClick={() => { setSelectedRun(run.id); setRunTab('details') }}
                className={clsx(
                  'px-3 py-2.5 border-b border-bg-border cursor-pointer hover:bg-bg-elevated transition-colors',
                  selectedRun === run.id && 'bg-bg-elevated border-l-2 border-l-accent'
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium text-zinc-200 truncate">{app?.display_name ?? `App #${run.test_app_id}`}</p>
                    <p className="text-[10px] text-zinc-500 mt-0.5">
                      {run.finding_count} findings · {new Date(run.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {run.precision != null && (
                      <span className="text-[10px] font-mono text-accent">P:{(run.precision * 100).toFixed(0)}%</span>
                    )}
                    <button onClick={(e) => handleDeleteRun(run.id, e)}
                      className="p-0.5 text-zinc-600 hover:text-red-400 transition-colors">
                      <Trash2 size={11} />
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Right — run detail */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {!selectedRun ? (
          <div className="flex flex-col items-center justify-center h-full text-zinc-600 gap-2">
            <Terminal size={24} />
            <p className="text-sm">Select a run or create a new one</p>
          </div>
        ) : !runDetail ? (
          <div className="flex justify-center pt-16"><Loader2 className="animate-spin text-accent" /></div>
        ) : (
          <>
            <div className="flex items-center gap-1 px-4 py-2 border-b border-bg-border bg-bg-surface shrink-0">
              {(['details', 'reproduction', 'accuracy'] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setRunTab(t)}
                  className={clsx(
                    'px-3 py-1.5 text-xs rounded capitalize',
                    runTab === t ? 'bg-accent/20 text-accent' : 'text-zinc-500 hover:text-zinc-200 hover:bg-bg-elevated'
                  )}
                >
                  {t}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-auto p-4">
              {runTab === 'details' && <RunDetailsPane run={runDetail} apps={apps} />}
              {runTab === 'reproduction' && <ReproductionPane steps={runDetail.reproduction_steps ?? []} />}
              {runTab === 'accuracy' && (
                <AccuracyEditPane
                  run={runDetail}
                  edit={accuracyEdit}
                  setEdit={setAccuracyEdit}
                  onSave={handleSaveAccuracy}
                  saving={savingAccuracy}
                />
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function RunDetailsPane({ run, apps }: { run: TestRun; apps: TestApp[] }) {
  const app = apps.find((a) => a.id === run.test_app_id)
  return (
    <div className="space-y-4 max-w-2xl">
      <div className="bg-bg-surface rounded border border-bg-border p-4 space-y-2">
        <div className="flex items-center justify-between">
          <p className="text-sm font-semibold text-zinc-200">{app?.display_name ?? `App #${run.test_app_id}`}</p>
          <p className="text-xs text-zinc-500">{new Date(run.created_at).toLocaleString()}</p>
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <Kv label="Analysis ID" value={run.analysis_id != null ? `#${run.analysis_id}` : '—'} />
          <Kv label="OWASP Scan ID" value={run.owasp_scan_id != null ? `#${run.owasp_scan_id}` : '—'} />
          <Kv label="Frida Script" value={run.frida_script_name ?? '—'} />
          <Kv label="Finding Count" value={String(run.finding_count)} />
        </div>
        {run.notes && <p className="text-xs text-zinc-400 pt-2 leading-relaxed border-t border-bg-border">{run.notes}</p>}
      </div>

      {run.frida_script_source && (
        <div>
          <p className="text-xs font-semibold text-zinc-400 uppercase mb-2">Frida Script Source</p>
          <pre className="text-xs font-mono text-zinc-300 bg-bg-base rounded border border-bg-border p-3 max-h-64 overflow-auto whitespace-pre-wrap break-all">
            {run.frida_script_source}
          </pre>
        </div>
      )}
    </div>
  )
}

function ReproductionPane({ steps }: { steps: ReproductionStep[] }) {
  const [expanded, setExpanded] = useState<number | null>(null)

  if (steps.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 text-zinc-600 gap-2">
        <Terminal size={24} />
        <p className="text-sm">No reproduction steps — add findings to the run to generate them</p>
      </div>
    )
  }

  return (
    <div className="space-y-2 max-w-3xl">
      {steps.map((step) => (
        <div key={step.step} className="bg-bg-surface rounded border border-bg-border overflow-hidden">
          <div
            className="flex items-start gap-3 px-3 py-2.5 cursor-pointer hover:bg-bg-elevated"
            onClick={() => setExpanded(expanded === step.step ? null : step.step)}
          >
            <span className="text-xs font-mono text-zinc-600 shrink-0 mt-0.5">#{step.step}</span>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-zinc-200">{step.title}</p>
              {step.cwe && <p className="text-[10px] text-zinc-500 mt-0.5">{step.cwe} · {step.category}</p>}
            </div>
            {expanded === step.step ? <ChevronDown size={12} className="text-zinc-500 shrink-0" /> : <ChevronRight size={12} className="text-zinc-500 shrink-0" />}
          </div>
          {expanded === step.step && (
            <div className="border-t border-bg-border bg-bg-base px-3 py-3 space-y-3">
              {step.description && (
                <p className="text-xs text-zinc-300 leading-relaxed">{step.description}</p>
              )}
              {step.commands && step.commands.length > 0 && (
                <div>
                  <p className="text-[10px] text-zinc-500 uppercase font-medium mb-1">Commands</p>
                  <div className="space-y-1">
                    {step.commands.map((cmd, i) => (
                      <pre key={i} className="text-xs font-mono text-green-300 bg-bg-elevated rounded px-2 py-1.5 whitespace-pre-wrap break-all">
                        {cmd}
                      </pre>
                    ))}
                  </div>
                </div>
              )}
              {step.expected_output && (
                <div>
                  <p className="text-[10px] text-zinc-500 uppercase font-medium mb-1">Expected Output</p>
                  <p className="text-xs text-zinc-400">{step.expected_output}</p>
                </div>
              )}
              {step.evidence && (
                <div>
                  <p className="text-[10px] text-zinc-500 uppercase font-medium mb-1">Evidence</p>
                  <p className="text-xs text-zinc-500 font-mono">{step.evidence}</p>
                </div>
              )}
              {step.attack_path && (
                <div>
                  <p className="text-[10px] text-zinc-500 uppercase font-medium mb-1">Attack Path</p>
                  <p className="text-xs text-zinc-400 leading-relaxed">{step.attack_path}</p>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

function AccuracyEditPane({
  run, edit, setEdit, onSave, saving
}: {
  run: TestRun
  edit: { tp: string; fp: string; fn: string; notes: string }
  setEdit: React.Dispatch<React.SetStateAction<{ tp: string; fp: string; fn: string; notes: string }>>
  onSave: () => void
  saving: boolean
}) {
  return (
    <div className="space-y-4 max-w-sm">
      <div className="bg-bg-surface rounded border border-bg-border p-4 space-y-3">
        <p className="text-xs font-semibold text-zinc-300">Update Accuracy Metrics</p>
        <div className="grid grid-cols-3 gap-2">
          {(['tp', 'fp', 'fn'] as const).map((k) => (
            <div key={k}>
              <label className="block text-[10px] text-zinc-500 mb-1">
                {k === 'tp' ? 'True Positives' : k === 'fp' ? 'False Positives' : 'False Negatives'}
              </label>
              <input
                type="number"
                min="0"
                className={inputCls}
                placeholder="0"
                value={edit[k]}
                onChange={(e) => setEdit((p) => ({ ...p, [k]: e.target.value }))}
              />
            </div>
          ))}
        </div>
        <div>
          <label className="block text-[10px] text-zinc-500 mb-1">Notes</label>
          <textarea
            className={`${inputCls} h-16 resize-none`}
            placeholder="Evaluation notes..."
            value={edit.notes}
            onChange={(e) => setEdit((p) => ({ ...p, notes: e.target.value }))}
          />
        </div>
        <button
          onClick={onSave}
          disabled={saving}
          className="w-full flex items-center justify-center gap-2 py-2 text-xs bg-accent/20 text-accent rounded hover:bg-accent/30 disabled:opacity-40"
        >
          {saving ? <Loader2 size={12} className="animate-spin" /> : <Save size={12} />}
          Save Accuracy
        </button>
      </div>

      {/* Current values */}
      <div className="bg-bg-surface rounded border border-bg-border p-4 space-y-2">
        <p className="text-xs font-semibold text-zinc-400">Current Values</p>
        <div className="grid grid-cols-3 gap-3 text-center">
          <MetricBox label="True Pos" value={run.true_positives} color="text-green-400" />
          <MetricBox label="False Pos" value={run.false_positives} color="text-red-400" />
          <MetricBox label="False Neg" value={run.false_negatives} color="text-orange-400" />
        </div>
        {run.precision != null && run.recall != null && (
          <div className="flex justify-around pt-2 border-t border-bg-border">
            <div className="text-center">
              <p className="text-xs text-zinc-500">Precision</p>
              <p className="text-sm font-mono font-bold text-zinc-200">{(run.precision * 100).toFixed(1)}%</p>
            </div>
            <div className="text-center">
              <p className="text-xs text-zinc-500">Recall</p>
              <p className="text-sm font-mono font-bold text-zinc-200">{(run.recall * 100).toFixed(1)}%</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

/* ──────────────── Accuracy Dashboard Tab ──────────────── */

function AccuracyTab() {
  const { data, isLoading } = useQuery({
    queryKey: ['testing-accuracy'],
    queryFn: () => testingApi.accuracy(),
  })

  if (isLoading) return <div className="flex justify-center pt-16"><Loader2 className="animate-spin text-accent" /></div>
  if (!data) return null

  const f1 = data.f1 != null ? `${(data.f1 * 100).toFixed(1)}%` : '—'
  const prec = data.precision != null ? `${(data.precision * 100).toFixed(1)}%` : '—'
  const rec = data.recall != null ? `${(data.recall * 100).toFixed(1)}%` : '—'

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div className="flex items-center gap-2">
        <BarChart2 size={16} className="text-accent" />
        <h3 className="text-sm font-semibold text-zinc-200">Aggregate Accuracy</h3>
        <span className="text-xs text-zinc-500">across {data.total_runs} run{data.total_runs !== 1 ? 's' : ''}</span>
      </div>

      {data.total_runs === 0 ? (
        <div className="flex flex-col items-center justify-center h-48 text-zinc-600 gap-2">
          <BarChart2 size={32} />
          <p className="text-sm">No accuracy data yet — score some runs first</p>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-4">
            <BigMetricCard label="Precision" value={prec} icon={<CheckCircle2 size={20} className="text-green-400" />} />
            <BigMetricCard label="Recall" value={rec} icon={<AlertCircle size={20} className="text-yellow-400" />} />
            <BigMetricCard label="F1 Score" value={f1} icon={<BarChart2 size={20} className="text-accent" />} />
          </div>

          <div className="bg-bg-surface rounded border border-bg-border p-4 grid grid-cols-3 gap-4">
            <MetricBox label="True Positives" value={data.total_tp} color="text-green-400" />
            <MetricBox label="False Positives" value={data.total_fp} color="text-red-400" />
            <MetricBox label="False Negatives" value={data.total_fn} color="text-orange-400" />
          </div>

          <div className="bg-bg-surface rounded border border-bg-border p-4 space-y-3">
            <p className="text-xs text-zinc-500 font-medium">Interpretation</p>
            <div className="space-y-1.5">
              <InterpRow label="Precision" value={data.precision}
                good="High precision means few false alarms — vulnerabilities flagged are likely real."
                bad="Low precision means many false positives — noisy results requiring manual triage." />
              <InterpRow label="Recall" value={data.recall}
                good="High recall means few missed vulnerabilities — good coverage."
                bad="Low recall means the tool is missing real vulnerabilities." />
            </div>
          </div>
        </>
      )}
    </div>
  )
}

/* ──────────────── Shared helpers ──────────────── */

const inputCls = 'w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent'

function RunSummaryCard({ run }: { run: TestRun }) {
  return (
    <div className="bg-bg-elevated rounded border border-bg-border px-3 py-2 flex items-center justify-between gap-3">
      <div>
        <p className="text-xs text-zinc-300">{run.finding_count} findings</p>
        <p className="text-[10px] text-zinc-600">{new Date(run.created_at).toLocaleString()}</p>
      </div>
      <div className="flex items-center gap-3 text-xs font-mono">
        {run.precision != null && <span className="text-green-400">P {(run.precision * 100).toFixed(0)}%</span>}
        {run.recall != null && <span className="text-yellow-400">R {(run.recall * 100).toFixed(0)}%</span>}
      </div>
    </div>
  )
}

function Kv({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[10px] text-zinc-500 uppercase">{label}</p>
      <p className="text-zinc-300 font-mono">{value}</p>
    </div>
  )
}

function MetricBox({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="text-center">
      <p className="text-xs text-zinc-500">{label}</p>
      <p className={clsx('text-xl font-mono font-bold', color)}>{value}</p>
    </div>
  )
}

function BigMetricCard({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) {
  return (
    <div className="bg-bg-surface rounded border border-bg-border p-4 flex flex-col items-center gap-2">
      {icon}
      <p className="text-2xl font-mono font-bold text-zinc-100">{value}</p>
      <p className="text-xs text-zinc-500">{label}</p>
    </div>
  )
}

function InterpRow({ label, value, good, bad }: { label: string; value: number | null; good: string; bad: string }) {
  if (value == null) return null
  const pct = value * 100
  const isGood = pct >= 70
  return (
    <div className="flex items-start gap-2">
      {isGood ? <CheckCircle2 size={12} className="text-green-400 mt-0.5 shrink-0" /> : <XCircle size={12} className="text-red-400 mt-0.5 shrink-0" />}
      <div>
        <span className="text-xs text-zinc-400 font-medium">{label} ({pct.toFixed(1)}%): </span>
        <span className="text-xs text-zinc-500">{isGood ? good : bad}</span>
      </div>
    </div>
  )
}

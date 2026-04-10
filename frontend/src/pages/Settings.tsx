import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { CheckCircle, XCircle, Loader2 } from 'lucide-react'
import { api } from '@/api/client'

interface ToolStatus {
  name: string
  found: boolean
  path: string | null
  version: string | null
  required: boolean
  install_hint: string
}

export default function SettingsPage() {
  const [saved, setSaved] = useState(false)

  const { data: settings, refetch: refetchSettings } = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get('/settings').then((r) => r.data),
  })

  const { data: tools } = useQuery({
    queryKey: ['tools'],
    queryFn: () => api.get<Record<string, ToolStatus>>('/settings/tools').then((r) => r.data),
    refetchInterval: 10_000,
  })

  const { mutate: save } = useMutation({
    mutationFn: (body: Record<string, string>) => api.patch('/settings', body).then((r) => r.data),
    onSuccess: () => { setSaved(true); setTimeout(() => setSaved(false), 2000); refetchSettings() },
  })

  const [form, setForm] = useState<Record<string, string>>({})

  if (!settings) return <div className="p-6"><Loader2 className="animate-spin text-accent" /></div>

  const current = { ...settings, ...form }

  return (
    <div className="p-6 max-w-2xl space-y-8">
      <h1 className="text-lg font-semibold text-zinc-200">Settings</h1>

      {/* Tool status */}
      <section>
        <h2 className="text-sm text-zinc-400 uppercase tracking-wide mb-3">Tool Status</h2>
        <div className="space-y-2">
          {tools && Object.values(tools).map((t: ToolStatus) => (
            <div key={t.name} className="flex items-start gap-3 bg-bg-surface rounded-lg border border-bg-border px-4 py-3">
              {t.found
                ? <CheckCircle size={14} className="text-green-400 mt-0.5 shrink-0" />
                : <XCircle size={14} className="text-red-400 mt-0.5 shrink-0" />}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-zinc-200">{t.name}</span>
                  {t.version && <span className="text-xs text-zinc-500 font-mono">{t.version}</span>}
                  {t.required && !t.found && <span className="text-xs text-red-400">required</span>}
                </div>
                {!t.found && <p className="text-xs text-zinc-500 mt-0.5">{t.install_hint}</p>}
                {t.path && t.found && <p className="text-xs text-zinc-600 font-mono truncate">{t.path}</p>}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Tool paths */}
      <section>
        <h2 className="text-sm text-zinc-400 uppercase tracking-wide mb-3">Tool Paths</h2>
        <div className="space-y-3">
          {[
            ['java_path', 'Java path', 'java'],
            ['apktool_jar', 'apktool.jar path', 'tools/apktool.jar'],
            ['jadx_path', 'jadx path', 'tools/jadx/bin/jadx'],
            ['adb_path', 'adb path', 'tools/platform-tools/adb'],
          ].map(([key, label, placeholder]) => (
            <div key={key}>
              <label className="text-xs text-zinc-400 mb-1 block">{label}</label>
              <input
                className="w-full bg-bg-surface border border-bg-border rounded px-3 py-1.5 text-sm font-mono text-zinc-200 focus:outline-none focus:border-accent"
                value={current[key] ?? ''}
                placeholder={placeholder}
                onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
              />
            </div>
          ))}
        </div>
      </section>

      {/* Proxy settings */}
      <section>
        <h2 className="text-sm text-zinc-400 uppercase tracking-wide mb-3">Proxy</h2>
        <div className="grid grid-cols-2 gap-3">
          {[
            ['proxy_host', 'Listen host', '0.0.0.0'],
            ['proxy_port', 'Listen port', '8080'],
          ].map(([key, label, placeholder]) => (
            <div key={key}>
              <label className="text-xs text-zinc-400 mb-1 block">{label}</label>
              <input
                className="w-full bg-bg-surface border border-bg-border rounded px-3 py-1.5 text-sm font-mono text-zinc-200 focus:outline-none focus:border-accent"
                value={current[key] ?? ''}
                placeholder={placeholder}
                onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
              />
            </div>
          ))}
        </div>
      </section>

      <div className="flex items-center gap-3">
        <button
          onClick={() => save(form)}
          className="px-4 py-2 bg-accent hover:bg-accent-hover text-white text-sm rounded transition-colors"
        >
          Save Changes
        </button>
        {saved && <span className="text-xs text-green-400">Saved</span>}
      </div>
    </div>
  )
}

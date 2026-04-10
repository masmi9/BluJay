import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Virtuoso } from 'react-virtuoso'
import { Play, Square, Trash2, Filter } from 'lucide-react'
import { clsx } from 'clsx'
import { adbApi, sessionApi } from '@/api/adb'
import { useDeviceStore } from '@/store/deviceStore'
import { useLogcat } from '@/hooks/useLogcat'
import type { LogcatLine } from '@/types/adb'
import ScreenshotGallery from '@/components/dynamic/ScreenshotGallery'

const DYNAMIC_TABS = ['Logcat', 'Screenshots'] as const
type DynamicTab = typeof DYNAMIC_TABS[number]

const LEVEL_COLORS: Record<string, string> = {
  V: 'text-zinc-500',
  D: 'text-zinc-400',
  I: 'text-blue-400',
  W: 'text-yellow-400',
  E: 'text-red-400',
  F: 'text-red-500',
}

export default function DynamicAnalysis() {
  const { sessionId: paramSessionId } = useParams<{ sessionId: string }>()
  const { devices, selectedSerial, selectDevice, activeSession, setActiveSession } = useDeviceStore()
  const [activeTab, setActiveTab] = useState<DynamicTab>('Logcat')
  const [levelFilter, setLevelFilter] = useState<string>('')
  const [tagFilter, setTagFilter] = useState('')

  const sessionId = paramSessionId ? Number(paramSessionId) : activeSession?.id ?? null
  const { lines, clear } = useLogcat(sessionId)

  useQuery({
    queryKey: ['devices'],
    queryFn: async () => {
      const devs = await adbApi.listDevices()
      return devs
    },
    refetchInterval: 5000,
  })

  const { data: session } = useQuery({
    queryKey: ['session', sessionId],
    queryFn: () => sessionApi.get(sessionId!),
    enabled: !!sessionId,
    refetchInterval: 3000,
  })

  const filtered = lines.filter((l) => {
    if (levelFilter && l.level !== levelFilter) return false
    if (tagFilter && !l.tag.toLowerCase().includes(tagFilter.toLowerCase())) return false
    return true
  })

  return (
    <div className="flex flex-col h-full p-4 gap-4">
      {/* Controls row */}
      <div className="flex items-center gap-3 flex-wrap">
        <select
          className="bg-bg-surface border border-bg-border rounded px-2 py-1 text-xs text-zinc-200"
          value={selectedSerial ?? ''}
          onChange={(e) => selectDevice(e.target.value || null)}
        >
          <option value="">Select device...</option>
          {devices.filter((d) => d.state === 'device').map((d) => (
            <option key={d.serial} value={d.serial}>{d.model || d.serial}</option>
          ))}
        </select>

        {session && (
          <span className="text-xs text-zinc-400 font-mono">
            pkg: <span className="text-zinc-200">{session.package_name}</span>
          </span>
        )}

        <div className="flex-1" />

        {/* Tab switcher */}
        <div className="flex gap-1 bg-bg-elevated rounded-lg p-1">
          {DYNAMIC_TABS.map((t) => (
            <button
              key={t}
              onClick={() => setActiveTab(t)}
              className={clsx(
                'px-3 py-1 rounded text-xs transition-colors',
                activeTab === t ? 'bg-accent text-white' : 'text-zinc-400 hover:text-zinc-200'
              )}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Log filters — only shown on Logcat tab */}
        {activeTab === 'Logcat' && (
          <div className="flex items-center gap-2">
            <Filter size={12} className="text-zinc-500" />
            <select
              className="bg-bg-surface border border-bg-border rounded px-2 py-1 text-xs text-zinc-200"
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value)}
            >
              <option value="">All levels</option>
              {['V', 'D', 'I', 'W', 'E', 'F'].map((l) => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
            <input
              className="bg-bg-surface border border-bg-border rounded px-2 py-1 text-xs text-zinc-200 w-32"
              placeholder="Filter by tag..."
              value={tagFilter}
              onChange={(e) => setTagFilter(e.target.value)}
            />
            <button onClick={clear} className="p-1 text-zinc-500 hover:text-zinc-200">
              <Trash2 size={14} />
            </button>
          </div>
        )}
      </div>

      {/* Tab content */}
      {activeTab === 'Logcat' && (
        <div className="flex-1 bg-bg-surface rounded-lg border border-bg-border overflow-hidden">
          {filtered.length === 0 ? (
            <div className="flex items-center justify-center h-full text-zinc-600 text-sm">
              {sessionId ? 'Waiting for log output...' : 'No active session'}
            </div>
          ) : (
            <Virtuoso
              style={{ height: '100%' }}
              data={filtered}
              followOutput="smooth"
              itemContent={(_, line: LogcatLine) => (
                <div className="flex gap-2 px-3 py-0.5 hover:bg-bg-elevated font-mono text-xs leading-5">
                  <span className="text-zinc-600 w-28 shrink-0">{line.ts}</span>
                  <span className={clsx('w-4 shrink-0 font-bold', LEVEL_COLORS[line.level])}>{line.level}</span>
                  <span className="text-zinc-500 w-24 truncate shrink-0">{line.tag}</span>
                  <span className="text-zinc-300 flex-1 break-all">{line.message}</span>
                </div>
              )}
            />
          )}
        </div>
      )}

      {activeTab === 'Screenshots' && sessionId && selectedSerial && (
        <div className="flex-1 bg-bg-surface rounded-lg border border-bg-border overflow-auto">
          <ScreenshotGallery sessionId={sessionId} serial={selectedSerial} />
        </div>
      )}

      {activeTab === 'Screenshots' && (!sessionId || !selectedSerial) && (
        <div className="flex-1 flex items-center justify-center text-zinc-500 text-sm">
          Select a device and start a session to capture screenshots.
        </div>
      )}
    </div>
  )
}

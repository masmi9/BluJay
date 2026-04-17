import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import * as Dialog from '@radix-ui/react-dialog'
import { Camera, Trash2, X, Download } from 'lucide-react'
import { screenshotApi } from '@/api/screenshot'
import type { Screenshot } from '@/types/screenshot'

interface Props {
  sessionId: number
  serial: string
  platform?: string   // 'android' | 'ios', defaults to 'android'
}

export default function ScreenshotGallery({ sessionId, serial, platform = 'android' }: Props) {
  const qc = useQueryClient()
  const [label, setLabel] = useState('')
  const [selected, setSelected] = useState<Screenshot | null>(null)

  const { data: screenshots = [] } = useQuery({
    queryKey: ['screenshots', sessionId],
    queryFn: () => screenshotApi.list(sessionId),
    refetchInterval: false,
  })

  const capture = useMutation({
    mutationFn: () => screenshotApi.capture({ serial, session_id: sessionId, label, platform }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['screenshots', sessionId] })
      setLabel('')
    },
  })

  const remove = useMutation({
    mutationFn: (id: number) => screenshotApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['screenshots', sessionId] }),
  })

  return (
    <div className="flex flex-col gap-3 p-4">
      {/* Capture bar */}
      <div className="flex gap-2">
        <input
          className="flex-1 bg-bg-elevated border border-bg-border rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-accent"
          placeholder="Label (optional)"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && capture.mutate()}
        />
        <button
          onClick={() => capture.mutate()}
          disabled={capture.isPending}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent/80 disabled:opacity-50 rounded text-sm text-white transition-colors"
        >
          <Camera size={14} />
          {capture.isPending ? 'Capturing…' : 'Capture Screenshot'}
        </button>
      </div>

      {capture.isError && (
        <p className="text-red-400 text-xs">{(capture.error as Error).message}</p>
      )}

      {/* Gallery grid */}
      {screenshots.length === 0 ? (
        <p className="text-zinc-500 text-sm">No screenshots yet.</p>
      ) : (
        <div className="grid grid-cols-4 gap-3">
          {screenshots.map((ss) => (
            <div key={ss.id} className="group relative rounded-lg overflow-hidden border border-bg-border bg-bg-elevated">
              <button
                className="w-full"
                onClick={() => setSelected(ss)}
              >
                <img
                  src={`data:image/jpeg;base64,${ss.thumbnail_b64}`}
                  alt={ss.label || 'screenshot'}
                  className="w-full object-cover"
                />
              </button>
              <div className="px-2 py-1 text-xs text-zinc-400 truncate">
                {ss.label || new Date(ss.captured_at).toLocaleTimeString()}
              </div>
              <button
                onClick={() => remove.mutate(ss.id)}
                className="absolute top-1 right-1 hidden group-hover:flex items-center justify-center w-6 h-6 bg-black/60 rounded text-red-400 hover:text-red-300"
              >
                <Trash2 size={12} />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Full-size dialog */}
      <Dialog.Root open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/70 z-40" />
          <Dialog.Content className="fixed inset-0 z-50 flex items-center justify-center p-6">
            <div className="relative bg-bg-surface rounded-xl border border-bg-border max-w-4xl max-h-full flex flex-col overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 border-b border-bg-border">
                <Dialog.Title className="text-sm font-medium text-zinc-200">
                  {selected?.label || 'Screenshot'} — {selected && new Date(selected.captured_at).toLocaleString()}
                </Dialog.Title>
                <div className="flex items-center gap-2">
                  {selected && (
                    <a
                      href={screenshotApi.imageUrl(selected.id)}
                      download
                      className="flex items-center gap-1 text-xs text-zinc-400 hover:text-zinc-200"
                    >
                      <Download size={13} /> PNG
                    </a>
                  )}
                  <Dialog.Close className="text-zinc-500 hover:text-zinc-200">
                    <X size={16} />
                  </Dialog.Close>
                </div>
              </div>
              {selected && (
                <img
                  src={screenshotApi.imageUrl(selected.id)}
                  alt={selected.label}
                  className="max-h-[80vh] object-contain"
                />
              )}
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  )
}

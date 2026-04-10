import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Code2, RefreshCw, AlertTriangle, Info } from 'lucide-react'
import { clsx } from 'clsx'
import { webviewApi } from '@/api/webview'
import type { WebViewFile, WebViewFinding } from '@/types/webview'
import { Badge } from '@/components/common/Badge'

const SEV_VARIANT: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
}

const SOURCE_LABELS: Record<string, string> = {
  asset: 'Asset',
  loadUrl_inline: 'loadUrl inline',
  loadData_inline: 'loadData inline',
  js_bridge: 'JS Bridge',
}

export default function WebViewPage() {
  const { id } = useParams<{ id: string }>()
  const analysisId = Number(id)
  const qc = useQueryClient()
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null)
  const [content, setContent] = useState<string>('')
  const [loadingContent, setLoadingContent] = useState(false)

  const { data: result, isLoading } = useQuery({
    queryKey: ['webview', analysisId],
    queryFn: () => webviewApi.getFiles(analysisId),
  })

  const scan = useMutation({
    mutationFn: () => webviewApi.scan(analysisId),
    onSuccess: (data) => qc.setQueryData(['webview', analysisId], data),
  })

  async function selectFile(file: WebViewFile) {
    setSelectedIndex(file.index)
    setLoadingContent(true)
    try {
      const c = await webviewApi.getContent(analysisId, file.index)
      setContent(c)
    } finally {
      setLoadingContent(false)
    }
  }

  const files = result?.files ?? []
  const selectedFile = selectedIndex !== null ? files[selectedIndex] : null

  return (
    <div className="flex h-full overflow-hidden">
      {/* Left: file tree */}
      <div className="w-72 shrink-0 flex flex-col border-r border-bg-border bg-bg-surface overflow-y-auto">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-bg-border">
          <Code2 size={16} className="text-accent" />
          <span className="text-sm font-medium text-zinc-200">WebView JS</span>
          <span className="ml-auto text-xs text-zinc-500">{files.length} files</span>
          <button
            onClick={() => scan.mutate()}
            disabled={scan.isPending}
            className="text-zinc-500 hover:text-zinc-200 disabled:opacity-50"
            title="Re-scan"
          >
            <RefreshCw size={13} className={scan.isPending ? 'animate-spin' : ''} />
          </button>
        </div>

        {isLoading && <p className="p-4 text-xs text-zinc-500">Loading…</p>}

        {files.map((f) => (
          <button
            key={f.index}
            onClick={() => selectFile(f)}
            className={clsx(
              'text-left px-4 py-2.5 border-b border-bg-border hover:bg-bg-elevated transition-colors',
              selectedIndex === f.index && 'bg-bg-elevated border-l-2 border-l-accent'
            )}
          >
            <div className="flex items-center gap-2">
              <span className="text-xs px-1.5 py-0.5 bg-bg-elevated rounded text-zinc-500">
                {SOURCE_LABELS[f.source] ?? f.source}
              </span>
              {f.findings.length > 0 && (
                <AlertTriangle size={11} className="text-yellow-500 shrink-0" />
              )}
            </div>
            <p className="text-xs text-zinc-300 font-mono mt-1 truncate" title={f.path}>{f.path}</p>
            <p className="text-xs text-zinc-600 mt-0.5">{f.size_bytes} bytes · {f.findings.length} findings</p>
          </button>
        ))}

        {!isLoading && files.length === 0 && (
          <div className="p-4 text-xs text-zinc-500">
            No JS files found. Click <RefreshCw size={10} className="inline" /> to scan.
          </div>
        )}
      </div>

      {/* Right: editor + findings */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Code pane */}
        <div className="flex-1 overflow-auto bg-bg-elevated font-mono text-xs p-4 leading-5">
          {!selectedFile && (
            <p className="text-zinc-500">Select a file to view its contents.</p>
          )}
          {selectedFile && loadingContent && (
            <p className="text-zinc-500">Loading…</p>
          )}
          {selectedFile && !loadingContent && (
            <pre className="text-zinc-300 whitespace-pre-wrap break-all">{content}</pre>
          )}
        </div>

        {/* Findings panel */}
        {selectedFile && selectedFile.findings.length > 0 && (
          <div className="border-t border-bg-border bg-bg-surface max-h-56 overflow-y-auto">
            <div className="px-4 py-2 text-xs font-medium text-zinc-400 border-b border-bg-border">
              Findings ({selectedFile.findings.length})
            </div>
            {selectedFile.findings.map((f, i) => (
              <div key={i} className="flex items-start gap-3 px-4 py-2 border-b border-bg-border hover:bg-bg-elevated">
                <Badge variant={SEV_VARIANT[f.severity] ?? 'info'}>{f.severity}</Badge>
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-zinc-200">{f.title}</p>
                  <p className="text-xs text-zinc-500 font-mono truncate">{f.evidence}</p>
                </div>
                <span className="text-xs text-zinc-600 shrink-0">line {f.line}</span>
              </div>
            ))}
          </div>
        )}

        {/* Bridge methods */}
        {selectedFile && selectedFile.bridge_methods.length > 0 && (
          <div className="border-t border-bg-border bg-bg-surface max-h-40 overflow-y-auto">
            <div className="px-4 py-2 text-xs font-medium text-zinc-400 border-b border-bg-border flex items-center gap-1">
              <Info size={11} /> Exposed Bridge Methods ({selectedFile.bridge_methods.length})
            </div>
            {selectedFile.bridge_methods.map((m, i) => (
              <div key={i} className="px-4 py-1.5 font-mono text-xs text-zinc-300 border-b border-bg-border">
                {m}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

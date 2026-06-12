import { useState, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  FolderSearch, ChevronRight, ChevronDown, File, Folder,
  Search, Loader2, X, AlertCircle,
} from 'lucide-react'
import { clsx } from 'clsx'
import Editor from '@monaco-editor/react'
import { analysisApi } from '@/api/analysis'
import type { SourceEntry } from '@/types/analysis'

const BASE = '/api/v1/analyses'

// Map extension → Monaco language
function langFor(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase() ?? ''
  const MAP: Record<string, string> = {
    java: 'java', kt: 'kotlin', smali: 'ini', xml: 'xml',
    json: 'json', js: 'javascript', ts: 'typescript',
    py: 'python', md: 'markdown', gradle: 'groovy',
    swift: 'swift', m: 'objective-c', plist: 'xml',
  }
  return MAP[ext] ?? 'plaintext'
}

interface SearchMatch { file: string; line: number; match: string }

// ── Tree node component ───────────────────────────────────────────────────────

interface TreeNodeProps {
  entry: SourceEntry
  analysisId: number
  depth: number
  onSelectFile: (path: string) => void
  selectedFile: string | null
}

function TreeNode({ entry, analysisId, depth, onSelectFile, selectedFile }: TreeNodeProps) {
  const [open, setOpen] = useState(false)

  const { data: children, isFetching } = useQuery<SourceEntry[]>({
    queryKey: ['explorer-dir', analysisId, entry.path],
    queryFn: async () => {
      const r = await fetch(`${BASE}/${analysisId}/source?path=${encodeURIComponent(entry.path)}`)
      if (!r.ok) throw new Error('Failed to load')
      return r.json()
    },
    enabled: entry.is_dir && open,
    staleTime: Infinity,
  })

  const toggle = useCallback(() => {
    if (entry.is_dir) setOpen((o) => !o)
    else onSelectFile(entry.path)
  }, [entry, onSelectFile])

  const name = entry.path.split('/').pop() ?? entry.path
  const isSelected = !entry.is_dir && selectedFile === entry.path

  return (
    <div>
      <button
        onClick={toggle}
        className={clsx(
          'flex items-center gap-1.5 w-full text-left py-0.5 px-1 rounded text-xs transition-colors',
          isSelected ? 'bg-accent/20 text-accent' : 'text-zinc-400 hover:bg-bg-elevated hover:text-zinc-200'
        )}
        style={{ paddingLeft: `${depth * 12 + 4}px` }}
      >
        {entry.is_dir ? (
          <>
            {open ? <ChevronDown size={10} className="text-zinc-500 shrink-0" /> : <ChevronRight size={10} className="text-zinc-500 shrink-0" />}
            <Folder size={11} className={open ? 'text-yellow-400 shrink-0' : 'text-zinc-500 shrink-0'} />
          </>
        ) : (
          <>
            <span className="w-[10px] shrink-0" />
            <File size={11} className="text-zinc-600 shrink-0" />
          </>
        )}
        <span className="truncate">{name}</span>
        {entry.is_dir && isFetching && <Loader2 size={9} className="animate-spin text-zinc-600 ml-auto shrink-0" />}
      </button>

      {entry.is_dir && open && children && (
        <div>
          {children.map((child) => (
            <TreeNode
              key={child.path}
              entry={child}
              analysisId={analysisId}
              depth={depth + 1}
              onSelectFile={onSelectFile}
              selectedFile={selectedFile}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ExplorerPage() {
  const [analysisId, setAnalysisId] = useState<number | null>(null)
  const [selectedFile, setSelectedFile] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<SearchMatch[] | null>(null)
  const [searching, setSearching] = useState(false)
  const [searchError, setSearchError] = useState<string | null>(null)
  const [view, setView] = useState<'explorer' | 'search'>('explorer')

  const { data: analyses = [] } = useQuery({ queryKey: ['analyses'], queryFn: analysisApi.list })

  const { data: rootEntries, isLoading: rootLoading, error: rootError } = useQuery<SourceEntry[]>({
    queryKey: ['explorer-root', analysisId],
    queryFn: async () => {
      const r = await fetch(`${BASE}/${analysisId}/source?path=`)
      if (!r.ok) {
        const body = await r.json().catch(() => ({ detail: r.statusText }))
        throw new Error(body.detail ?? r.statusText)
      }
      return r.json()
    },
    enabled: !!analysisId,
    staleTime: 60_000,
  })

  const { data: fileContent, isLoading: fileLoading } = useQuery<{ path: string; content: string }>({
    queryKey: ['explorer-file', analysisId, selectedFile],
    queryFn: async () => {
      const r = await fetch(`${BASE}/${analysisId}/source/file?path=${encodeURIComponent(selectedFile!)}`)
      if (!r.ok) throw new Error(await r.text())
      return r.json()
    },
    enabled: !!analysisId && !!selectedFile,
    staleTime: 30_000,
  })

  const runSearch = useCallback(async () => {
    if (!analysisId || !searchQuery.trim()) return
    setSearching(true)
    setSearchError(null)
    setView('search')
    try {
      const r = await fetch(`${BASE}/${analysisId}/source/search?q=${encodeURIComponent(searchQuery.trim())}`)
      if (!r.ok) {
        const body = await r.json().catch(() => ({ detail: r.statusText }))
        throw new Error(body.detail ?? r.statusText)
      }
      const data = await r.json()
      setSearchResults(data.results)
    } catch (e: any) {
      setSearchError(e.message)
      setSearchResults(null)
    } finally {
      setSearching(false)
    }
  }, [analysisId, searchQuery])

  const clickSearchResult = (match: SearchMatch) => {
    setSelectedFile(match.file)
    setView('explorer')
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Top bar */}
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-bg-border bg-bg-surface shrink-0">
        <FolderSearch size={15} className="text-accent shrink-0" />
        <span className="text-sm font-semibold text-zinc-200">Decompiler Explorer</span>

        <select
          value={analysisId ?? ''}
          onChange={(e) => { setAnalysisId(e.target.value ? Number(e.target.value) : null); setSelectedFile(null); setSearchResults(null) }}
          className="bg-bg-elevated border border-bg-border rounded px-2 py-1 text-xs text-zinc-200 focus:outline-none focus:border-accent w-64"
        >
          <option value="">Select analysis…</option>
          {analyses.filter((a: any) => a.status === 'complete').map((a: any) => (
            <option key={a.id} value={a.id}>{a.apk_filename}</option>
          ))}
        </select>

        {/* String search */}
        <div className="flex items-center gap-1 flex-1 max-w-md bg-bg-elevated border border-bg-border rounded px-2 py-1">
          <Search size={11} className="text-zinc-500 shrink-0" />
          <input
            type="text"
            placeholder="Search strings across all files…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && runSearch()}
            disabled={!analysisId}
            className="flex-1 bg-transparent text-xs text-zinc-200 placeholder-zinc-600 outline-none"
          />
          {searchQuery && (
            <button onClick={() => { setSearchQuery(''); setSearchResults(null); setView('explorer') }} className="text-zinc-600 hover:text-zinc-400">
              <X size={10} />
            </button>
          )}
        </div>
        <button
          onClick={runSearch}
          disabled={!analysisId || !searchQuery.trim() || searching}
          className="flex items-center gap-1 px-3 py-1 rounded bg-accent text-white text-xs hover:bg-accent/80 disabled:opacity-40 transition-colors"
        >
          {searching ? <Loader2 size={11} className="animate-spin" /> : <Search size={11} />}
          Search
        </button>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* File tree panel */}
        <div className="w-64 shrink-0 border-r border-bg-border bg-bg-surface overflow-y-auto">
          {!analysisId && (
            <div className="flex items-center justify-center h-full text-zinc-600 text-xs p-4 text-center">
              Select an analysis to browse the decompiled source
            </div>
          )}
          {analysisId && rootLoading && (
            <div className="flex items-center justify-center h-24">
              <Loader2 size={16} className="animate-spin text-accent" />
            </div>
          )}
          {analysisId && rootError && (
            <div className="p-4 text-xs text-red-400 flex items-start gap-2">
              <AlertCircle size={12} className="shrink-0 mt-0.5" />
              {(rootError as Error).message}
            </div>
          )}
          {rootEntries && (
            <div className="p-1 space-y-0.5">
              {rootEntries.map((entry) => (
                <TreeNode
                  key={entry.path}
                  entry={entry}
                  analysisId={analysisId!}
                  depth={0}
                  onSelectFile={(path) => { setSelectedFile(path); setView('explorer') }}
                  selectedFile={selectedFile}
                />
              ))}
            </div>
          )}
        </div>

        {/* Right panel: file viewer or search results */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {view === 'search' && (
            <div className="flex flex-col h-full">
              <div className="px-4 py-2 border-b border-bg-border bg-bg-surface text-xs text-zinc-400 shrink-0">
                {searching ? 'Searching…' : searchResults !== null ? `${searchResults.length} matches for "${searchQuery}"` : ''}
                {searchError && <span className="text-red-400">{searchError}</span>}
              </div>
              <div className="flex-1 overflow-auto">
                {searchResults?.map((m, i) => (
                  <button
                    key={i}
                    onClick={() => clickSearchResult(m)}
                    className="flex items-start gap-3 w-full text-left px-4 py-2 border-b border-bg-border hover:bg-bg-elevated transition-colors"
                  >
                    <div className="shrink-0 text-right">
                      <p className="text-[10px] text-zinc-600 font-mono">{m.line}</p>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-[10px] text-accent truncate font-mono">{m.file}</p>
                      <p className="text-xs text-zinc-300 font-mono truncate mt-0.5">{m.match}</p>
                    </div>
                  </button>
                ))}
                {searchResults?.length === 0 && (
                  <p className="text-center text-zinc-600 text-xs py-8">No matches found</p>
                )}
              </div>
            </div>
          )}

          {view === 'explorer' && (
            <>
              {!selectedFile && (
                <div className="flex items-center justify-center h-full text-zinc-600 text-sm">
                  Select a file from the tree to view its contents
                </div>
              )}
              {selectedFile && (
                <div className="flex flex-col h-full">
                  <div className="flex items-center gap-2 px-3 py-1.5 border-b border-bg-border bg-bg-surface shrink-0">
                    <File size={11} className="text-zinc-500" />
                    <span className="text-xs text-zinc-400 font-mono truncate">{selectedFile}</span>
                    {fileLoading && <Loader2 size={11} className="animate-spin text-accent ml-auto" />}
                  </div>
                  <div className="flex-1 overflow-hidden">
                    {fileContent && (
                      <Editor
                        height="100%"
                        language={langFor(selectedFile)}
                        value={fileContent.content}
                        theme="vs-dark"
                        options={{
                          readOnly: true,
                          fontSize: 12,
                          fontFamily: 'monospace',
                          minimap: { enabled: true },
                          lineNumbers: 'on',
                          scrollBeyondLastLine: false,
                          wordWrap: 'off',
                          folding: true,
                        }}
                      />
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

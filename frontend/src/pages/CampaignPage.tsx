import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Layers, Plus, Play, Trash2, Upload, CheckCircle, XCircle, Clock, Loader2, ExternalLink } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { campaignApi, type CampaignOut, type CampaignSummary } from '@/api/campaign'

const STATUS_ICON: Record<string, React.ReactNode> = {
  pending: <Clock size={13} className="text-zinc-500" />,
  running: <Loader2 size={13} className="text-blue-400 animate-spin" />,
  complete: <CheckCircle size={13} className="text-green-400" />,
  failed: <XCircle size={13} className="text-red-400" />,
}

const STATUS_COLOR: Record<string, string> = {
  pending: 'text-zinc-400',
  running: 'text-blue-400',
  complete: 'text-green-400',
  failed: 'text-red-400',
}

function ProgressBar({ total, complete, failed }: { total: number; complete: number; failed: number }) {
  if (total === 0) return <div className="h-1 bg-bg-border rounded" />
  const cp = (complete / total) * 100
  const fp = (failed / total) * 100
  return (
    <div className="h-1.5 bg-bg-border rounded overflow-hidden flex">
      <div className="bg-green-500 transition-all" style={{ width: `${cp}%` }} />
      <div className="bg-red-500 transition-all" style={{ width: `${fp}%` }} />
    </div>
  )
}

function CampaignCard({ summary, onOpen, onDelete }: {
  summary: CampaignSummary
  onOpen: () => void
  onDelete: () => void
}) {
  return (
    <div
      onClick={onOpen}
      className="bg-bg-surface border border-bg-border rounded-lg p-4 hover:border-accent/40 cursor-pointer transition-colors"
    >
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          {STATUS_ICON[summary.status] ?? STATUS_ICON.pending}
          <span className="text-sm font-semibold text-zinc-200">{summary.name}</span>
          <span className="text-xs text-zinc-600 border border-bg-border rounded px-1">{summary.platform}</span>
        </div>
        <button
          onClick={(e) => { e.stopPropagation(); onDelete() }}
          className="text-zinc-600 hover:text-red-400 transition-colors"
        >
          <Trash2 size={13} />
        </button>
      </div>
      <ProgressBar total={summary.total} complete={summary.complete} failed={summary.failed} />
      <div className="flex items-center gap-3 mt-2 text-xs text-zinc-500">
        <span className={STATUS_COLOR[summary.status]}>{summary.status}</span>
        <span>{summary.complete}/{summary.total} complete</span>
        {summary.failed > 0 && <span className="text-red-400">{summary.failed} failed</span>}
      </div>
    </div>
  )
}

function CampaignDetail({ campaign, onRun, isRunning }: {
  campaign: CampaignOut
  onRun: () => void
  isRunning: boolean
}) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)

  const uploadMutation = useMutation({
    mutationFn: (file: File) => campaignApi.addTarget(campaign.id, file),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['campaign', campaign.id] }),
  })

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-base font-semibold text-zinc-100 flex items-center gap-2">
            <Layers size={16} className="text-accent" />
            {campaign.name}
          </h2>
          {campaign.description && (
            <p className="text-xs text-zinc-500 mt-0.5">{campaign.description}</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => fileRef.current?.click()}
            disabled={campaign.status === 'running'}
            className="flex items-center gap-1.5 text-xs bg-bg-elevated hover:bg-bg-border disabled:opacity-40 border border-bg-border text-zinc-300 px-3 py-1.5 rounded transition-colors"
          >
            <Upload size={12} />
            Add APK/IPA
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".apk,.ipa"
            multiple
            className="hidden"
            onChange={(e) => {
              Array.from(e.target.files ?? []).forEach((f) => uploadMutation.mutate(f))
              e.target.value = ''
            }}
          />
          <button
            onClick={onRun}
            disabled={campaign.status === 'running' || campaign.targets.length === 0 || isRunning}
            className="flex items-center gap-1.5 text-xs bg-accent hover:bg-accent/80 disabled:opacity-40 text-white px-3 py-1.5 rounded transition-colors"
          >
            {isRunning || campaign.status === 'running'
              ? <Loader2 size={12} className="animate-spin" />
              : <Play size={12} />
            }
            Run Campaign
          </button>
        </div>
      </div>

      {/* Targets table */}
      {campaign.targets.length === 0 ? (
        <div
          onClick={() => fileRef.current?.click()}
          className="border-2 border-dashed border-bg-border rounded-lg p-12 text-center cursor-pointer hover:border-accent/40 transition-colors"
        >
          <Upload size={24} className="text-zinc-600 mx-auto mb-2" />
          <p className="text-sm text-zinc-500">Drop APK/IPA files here or click to upload</p>
        </div>
      ) : (
        <div className="border border-bg-border rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-bg-border bg-bg-surface">
                <th className="text-left px-3 py-2 text-zinc-500 font-medium">File</th>
                <th className="text-left px-3 py-2 text-zinc-500 font-medium w-24">Status</th>
                <th className="text-left px-3 py-2 text-zinc-500 font-medium w-24">Analysis</th>
                <th className="px-3 py-2 w-10" />
              </tr>
            </thead>
            <tbody>
              {campaign.targets.map((t) => (
                <tr key={t.id} className="border-b border-bg-border last:border-0 hover:bg-bg-elevated/30">
                  <td className="px-3 py-2 font-mono text-zinc-300">{t.apk_filename}</td>
                  <td className="px-3 py-2">
                    <span className={`flex items-center gap-1 ${STATUS_COLOR[t.status]}`}>
                      {STATUS_ICON[t.status]}
                      {t.status}
                    </span>
                    {t.error && (
                      <span className="text-red-400 block truncate max-w-xs" title={t.error}>
                        {t.error}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {t.analysis_id ? (
                      <button
                        onClick={() => navigate(`/analysis/${t.analysis_id}`)}
                        className="flex items-center gap-1 text-accent hover:text-accent/80 transition-colors"
                      >
                        #{t.analysis_id}
                        <ExternalLink size={10} />
                      </button>
                    ) : (
                      <span className="text-zinc-600">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2" />
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default function CampaignPage() {
  const qc = useQueryClient()
  const [activeCampaignId, setActiveCampaignId] = useState<number | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newPlatform, setNewPlatform] = useState('android')

  const { data: summaries = [], isLoading } = useQuery<CampaignSummary[]>({
    queryKey: ['campaigns'],
    queryFn: () => campaignApi.list(),
    refetchInterval: 3000,
  })

  const { data: activeCampaign } = useQuery<CampaignOut>({
    queryKey: ['campaign', activeCampaignId],
    queryFn: () => campaignApi.get(activeCampaignId!),
    enabled: activeCampaignId != null,
    refetchInterval: 2000,
  })

  const createMutation = useMutation({
    mutationFn: () => campaignApi.create(newName, newDesc || undefined, newPlatform),
    onSuccess: (c) => {
      setActiveCampaignId(c.id)
      setShowCreate(false)
      setNewName('')
      setNewDesc('')
      qc.invalidateQueries({ queryKey: ['campaigns'] })
    },
  })

  const runMutation = useMutation({
    mutationFn: (id: number) => campaignApi.run(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['campaigns'] })
      qc.invalidateQueries({ queryKey: ['campaign', activeCampaignId] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => campaignApi.delete(id),
    onSuccess: (_, id) => {
      if (activeCampaignId === id) setActiveCampaignId(null)
      qc.invalidateQueries({ queryKey: ['campaigns'] })
    },
  })

  return (
    <div className="flex h-full">
      {/* Left panel */}
      <div className="w-72 shrink-0 border-r border-bg-border flex flex-col">
        <div className="p-3 border-b border-bg-border flex items-center justify-between">
          <span className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
            <Layers size={14} />
            Campaigns
          </span>
          <button
            onClick={() => setShowCreate((s) => !s)}
            className="w-6 h-6 flex items-center justify-center rounded bg-accent hover:bg-accent/80 text-white transition-colors"
          >
            <Plus size={13} />
          </button>
        </div>

        {showCreate && (
          <div className="p-3 border-b border-bg-border space-y-2">
            <input
              type="text"
              placeholder="Campaign name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
            />
            <input
              type="text"
              placeholder="Description (optional)"
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-accent"
            />
            <select
              value={newPlatform}
              onChange={(e) => setNewPlatform(e.target.value)}
              className="w-full bg-bg-elevated border border-bg-border rounded px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-accent"
            >
              <option value="android">Android</option>
              <option value="ios">iOS</option>
              <option value="mixed">Mixed</option>
            </select>
            <div className="flex gap-2">
              <button
                onClick={() => createMutation.mutate()}
                disabled={!newName || createMutation.isPending}
                className="flex-1 bg-accent hover:bg-accent/80 disabled:opacity-40 text-white text-xs py-1.5 rounded transition-colors"
              >
                {createMutation.isPending ? 'Creating…' : 'Create'}
              </button>
              <button
                onClick={() => setShowCreate(false)}
                className="flex-1 bg-bg-elevated hover:bg-bg-border text-zinc-400 text-xs py-1.5 rounded transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
          {isLoading && <p className="text-xs text-zinc-500 p-2">Loading…</p>}
          {summaries.map((s) => (
            <CampaignCard
              key={s.id}
              summary={s}
              onOpen={() => setActiveCampaignId(s.id)}
              onDelete={() => deleteMutation.mutate(s.id)}
            />
          ))}
          {!isLoading && summaries.length === 0 && (
            <p className="text-xs text-zinc-600 p-2">No campaigns yet</p>
          )}
        </div>
      </div>

      {/* Main panel */}
      {activeCampaign ? (
        <CampaignDetail
          campaign={activeCampaign}
          onRun={() => runMutation.mutate(activeCampaign.id)}
          isRunning={runMutation.isPending}
        />
      ) : (
        <div className="flex-1 flex flex-col items-center justify-center text-zinc-600">
          <Layers size={40} className="mb-3 opacity-30" />
          <p className="text-sm">Select or create a campaign</p>
          <p className="text-xs mt-1 opacity-70">Run batch analysis across multiple APKs/IPAs</p>
        </div>
      )}
    </div>
  )
}

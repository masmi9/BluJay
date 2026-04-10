import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { BarChart2, Info } from 'lucide-react'
import { riskApi } from '@/api/risk'
import { RiskScoreCard } from '@/components/analysis/RiskScoreCard'
import { RiskGraph } from '@/components/analysis/RiskGraph'
import type { GraphNode } from '@/types/risk'

const NODE_TYPE_DESCRIPTIONS: Record<string, string> = {
  analysis:   'Root analysis node',
  finding:    'Static security finding',
  library:    'Detected third-party library',
  cve:        'Known CVE / vulnerability',
  host:       'Backend network host',
  component:  'Android component (Activity/Service/etc.)',
  permission:  'Android permission',
}

export default function RiskPage() {
  const { id } = useParams<{ id: string }>()
  const analysisId = Number(id)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)

  const { data: score, isLoading: scoreLoading } = useQuery({
    queryKey: ['risk-score', analysisId],
    queryFn: () => riskApi.getScore(analysisId),
  })

  const { data: graph, isLoading: graphLoading } = useQuery({
    queryKey: ['risk-graph', analysisId],
    queryFn: () => riskApi.getGraph(analysisId),
  })

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 px-6 py-4 border-b border-bg-border shrink-0">
        <BarChart2 size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-zinc-100">Risk Score & Graph</h1>
        {score && (
          <span className="ml-2 text-sm text-zinc-400">
            Analysis #{analysisId}
          </span>
        )}
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left: score card + legend */}
        <div className="w-72 shrink-0 flex flex-col gap-4 p-4 border-r border-bg-border overflow-y-auto">
          {scoreLoading && <p className="text-zinc-500 text-sm">Computing score…</p>}
          {score && <RiskScoreCard analysisId={analysisId} score={score} />}

          {/* Node type legend */}
          <div className="bg-bg-surface rounded-lg border border-bg-border p-4">
            <p className="text-xs font-medium text-zinc-400 mb-3">Graph Legend</p>
            {[
              { type: 'analysis',   color: '#6366f1', label: 'Analysis' },
              { type: 'finding',    color: '#ef4444', label: 'Finding (severity-colored)' },
              { type: 'library',    color: '#3b82f6', label: 'Library' },
              { type: 'cve',        color: '#991b1b', label: 'CVE' },
              { type: 'host',       color: '#0d9488', label: 'Network Host' },
              { type: 'permission', color: '#7c3aed', label: 'Permission' },
            ].map(({ type, color, label }) => (
              <div key={type} className="flex items-center gap-2 mb-1.5">
                <div className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: color }} />
                <span className="text-xs text-zinc-400">{label}</span>
              </div>
            ))}
          </div>

          {/* Selected node details */}
          {selectedNode && (
            <div className="bg-bg-surface rounded-lg border border-bg-border p-4">
              <p className="text-xs font-medium text-zinc-400 mb-2 flex items-center gap-1">
                <Info size={11} /> Selected Node
              </p>
              <p className="text-sm text-zinc-200 font-medium break-all">{selectedNode.label}</p>
              <p className="text-xs text-zinc-500 mt-1 capitalize">{selectedNode.type}</p>
              {selectedNode.severity && (
                <p className="text-xs text-zinc-400 mt-1">Severity: <span className="capitalize text-zinc-200">{selectedNode.severity}</span></p>
              )}
              <p className="text-xs text-zinc-600 mt-2">{NODE_TYPE_DESCRIPTIONS[selectedNode.type]}</p>
            </div>
          )}
        </div>

        {/* Right: D3 graph */}
        <div className="flex-1 bg-bg-elevated relative overflow-hidden">
          {graphLoading && (
            <div className="absolute inset-0 flex items-center justify-center text-zinc-500 text-sm">
              Building graph…
            </div>
          )}
          {graph && graph.nodes.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center text-zinc-500 text-sm">
              No graph data yet. Complete static analysis and run a CVE scan first.
            </div>
          )}
          {graph && graph.nodes.length > 0 && (
            <RiskGraph data={graph} onNodeClick={setSelectedNode} />
          )}
          <div className="absolute bottom-3 right-3 text-xs text-zinc-600">
            Scroll to zoom · Drag to pan · Click node for details
          </div>
        </div>
      </div>
    </div>
  )
}

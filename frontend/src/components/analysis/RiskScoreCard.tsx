import { useNavigate } from 'react-router-dom'
import { RadialBarChart, RadialBar, ResponsiveContainer, Cell } from 'recharts'
import { clsx } from 'clsx'
import type { RiskScore } from '@/types/risk'

const GRADE_COLORS: Record<string, string> = {
  A: '#22c55e',
  B: '#84cc16',
  C: '#eab308',
  D: '#f97316',
  F: '#ef4444',
}

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
}

interface Props {
  analysisId: number
  score: RiskScore
  compact?: boolean
}

export function RiskScoreCard({ analysisId, score, compact = false }: Props) {
  const navigate = useNavigate()
  const color = GRADE_COLORS[score.grade] ?? '#6b7280'
  const gaugeData = [{ value: score.score }, { value: 100 - score.score }]

  const totalFindings = Object.values(score.finding_count_by_severity).reduce((a, b) => a + b, 0)

  if (compact) {
    return (
      <button
        onClick={() => navigate(`/risk/${analysisId}`)}
        className="flex items-center gap-3 px-3 py-2 bg-bg-elevated rounded-lg border border-bg-border hover:border-accent transition-colors"
      >
        <div className="relative w-10 h-10">
          <svg viewBox="0 0 36 36" className="w-10 h-10 -rotate-90">
            <circle cx="18" cy="18" r="15" fill="none" stroke="#27272a" strokeWidth="3" />
            <circle
              cx="18" cy="18" r="15" fill="none"
              stroke={color} strokeWidth="3"
              strokeDasharray={`${(score.score / 100) * 94} 94`}
              strokeLinecap="round"
            />
          </svg>
          <span className="absolute inset-0 flex items-center justify-center text-xs font-bold" style={{ color }}>
            {score.grade}
          </span>
        </div>
        <div className="text-left">
          <p className="text-xs text-zinc-400">Risk Score</p>
          <p className="text-sm font-semibold text-zinc-200">{score.score}/100</p>
        </div>
      </button>
    )
  }

  return (
    <div className="bg-bg-surface rounded-xl border border-bg-border p-6 flex flex-col gap-4">
      <div className="flex items-center gap-4">
        {/* Gauge */}
        <div className="relative w-24 h-24 shrink-0">
          <svg viewBox="0 0 36 36" className="w-24 h-24 -rotate-90">
            <circle cx="18" cy="18" r="15" fill="none" stroke="#27272a" strokeWidth="3" />
            <circle
              cx="18" cy="18" r="15" fill="none"
              stroke={color} strokeWidth="3"
              strokeDasharray={`${(score.score / 100) * 94} 94`}
              strokeLinecap="round"
              className="transition-all duration-700"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold" style={{ color }}>{score.grade}</span>
            <span className="text-xs text-zinc-500">{score.score}/100</span>
          </div>
        </div>

        {/* Severity breakdown */}
        <div className="flex-1 flex flex-col gap-1.5">
          {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
            const count = score.finding_count_by_severity[sev] ?? 0
            const pct = totalFindings > 0 ? (count / totalFindings) * 100 : 0
            return (
              <div key={sev} className="flex items-center gap-2">
                <span className="text-xs w-14 text-zinc-500 capitalize">{sev}</span>
                <div className="flex-1 h-1.5 bg-bg-elevated rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${pct}%`, backgroundColor: SEV_COLORS[sev] }}
                  />
                </div>
                <span className="text-xs text-zinc-400 w-6 text-right">{count}</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* CVE counts */}
      {Object.keys(score.breakdown.cves ?? {}).length > 0 && (
        <div className="flex gap-2 flex-wrap">
          {Object.entries(score.breakdown.cves).map(([sev, cnt]) => (
            <span
              key={sev}
              className="px-2 py-0.5 rounded text-xs"
              style={{ backgroundColor: SEV_COLORS[sev] + '33', color: SEV_COLORS[sev] }}
            >
              {cnt} CVE {sev}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

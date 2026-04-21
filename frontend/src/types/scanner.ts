export type SeverityLevel = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type ScanType = 'passive' | 'active'

export interface ScanFinding {
  id: number
  session_id: number | null
  flow_id: string | null
  scan_job_id: number | null
  scan_type: ScanType
  check_name: string
  severity: SeverityLevel
  url: string
  host: string
  title: string
  detail: string
  evidence: string | null
  remediation: string | null
  timestamp: string
}

export interface ActiveScanJob {
  id: number
  session_id: number | null
  flow_ids: string[]
  checks: string[]
  status: 'pending' | 'running' | 'done' | 'error'
  started_at: string | null
  finished_at: string | null
  finding_count: number
  requests_sent: number
  error: string | null
  created_at: string
}

export interface FindingsResponse {
  total: number
  items: ScanFinding[]
}

export const ACTIVE_CHECKS = [
  'xss-reflected',
  'sqli-error',
  'open-redirect',
  'path-traversal',
  'ssrf-basic',
] as const

export const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

export const SEVERITY_COLOR: Record<SeverityLevel, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
  high:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low:      'text-blue-400 bg-blue-500/10 border-blue-500/20',
  info:     'text-zinc-400 bg-zinc-500/10 border-zinc-500/20',
}

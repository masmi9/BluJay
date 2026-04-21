export interface OwaspScanSummary {
  id: number
  created_at: string
  analysis_id: number | null
  platform: string
  apk_path: string | null
  package_name: string | null
  mode: 'deep' | 'quick'
  status: 'pending' | 'running' | 'complete' | 'failed'
  progress: number
  finding_count: number
  by_severity: Record<string, number>
  duration_s: number | null
  error: string | null
}

export interface OwaspFinding {
  id?: number
  title?: string
  name?: string
  severity?: string
  risk_level?: string
  category?: string
  type?: string
  description?: string
  evidence?: string
  cwe_id?: string
  cwe_name?: string
  cvss_score?: number
  reproduction_commands?: string[]
  remediation?: string
  business_impact?: string
  masvs_control?: string
}

export interface DetectedLibrary {
  id: number
  analysis_id: number
  name: string
  version: string | null
  ecosystem: string
  source: string
}

export interface CveMatch {
  id: number
  analysis_id: number
  library_id: number
  osv_id: string
  cve_id: string | null
  severity: 'critical' | 'high' | 'medium' | 'low' | null
  cvss_score: number | null
  summary: string | null
  fixed_version: string | null
  published: string | null
  fetched_at: string
}

export interface CveScanResponse {
  libraries: DetectedLibrary[]
  cve_matches: CveMatch[]
  total_critical: number
  total_high: number
}
